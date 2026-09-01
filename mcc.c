// SPDX-License-Identifier: GPL-2.0
/*
 * MCC TCP Congestion Control - quic‑go MCCSender 完全体移植
 * 适配主线 Linux 5.15 - 6.6
 *
 *
 * 【Pacing‑Driven Architecture】
 * START/GUARD(r=true): snd_cwnd = 0x7fffffff，cwnd不做限制，发包由sk_pacing_rate主导，
 *                      完美模拟原版 CanSend() 的 r || 短路返回 true。
 *
 * 【内存模型突破】
 * struct mcc 大小远超 ICSK_CA_PRIV_SIZE (64 bytes)。
 * 采用内核高级技巧：将 icsk_ca_priv 的前 8 字节作为指针，
 * 指向动态分配的 struct mcc。Ring Buffer 内嵌于 struct mcc 中。
 *
 * 【移植偏差与内核适配】
 * 1. Go原版状态切换+pacing_rate赋值在 CanSend() 发包前执行；Linux没有发包前cc钩子，
 *    放在pkts_acked ACK回调。
 * 2. Go HasPacingBudget 逻辑无直接内核对应接口，本移植未实现。
 * 3. sample->pkts_acked为段计数，acked_bytes = pkts_acked * mss_cache，SACK/partial‑ACK存在估算偏差。
 * 4. ackCount：仅重建mcc_init清零；与原版保持一致。
 * 5. RTO处理：Linux TCP 的 RTO 超时必须通过 tp->retrans_out > 0 过滤掉虚假 RTO (Spurious RTO) 的 Undo 恢复，避免无妄惩罚。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <net/tcp.h>
#include <linux/ktime.h>

#define MCC_MIN_BDP             128
#define MCC_BG_RTT_DEFAULT_US   (5 * USEC_PER_SEC)
#define MCC_PROBE_RTT_DUR_US    (200 * USEC_PER_MSEC)
#define MCC_RTT_UPDATE_INT_US   (5 * USEC_PER_SEC)
#define MCC_ACK_RING_SIZE       10000

enum mcc_state {
	MCC_START = 0,
	MCC_STOP,
	MCC_GUARD,
	MCC_PROBE_RTT,
};

struct mcc_ack_entry {
	u32 acked_bytes;
	u64 time_ns;
};

struct mcc {
	struct mcc_ack_entry *ring;
	u64 pacing_rate;
	u64 probe_rtt_save_rate;
	u64 window_delivered;
	u64 last_new_bg_rtt_time;
	u64 last_probe_rtt_start;
	u32 smoothed_rtt_us;
	u32 backGround_rtt_us;
	u32 max_datagram_size;
	u32 ack_count;
	u16 bdp_limit_factor;
	u16 state;
	u16 old_state;
	bool ring_allocated;
	u32 head;
	u32 tail;
};

static int low_rtt_mode = 0;
module_param(low_rtt_mode, int, 0444);
MODULE_PARM_DESC(low_rtt_mode, "Enable low RTT mode (bdp_limit_factor=2)");

/*
 * 【核心内存突破】
 * 将 icsk_ca_priv 的前 8 字节视为 struct mcc 的指针。
 */
static inline struct mcc *mcc_ca(const struct sock *sk)
{
	return *(struct mcc **)inet_csk_ca(sk);
}

static inline void mcc_set_ca(struct sock *sk, struct mcc *ca)
{
	*(struct mcc **)inet_csk_ca(sk) = ca;
}

static inline u64 mcc_min_maxbandwidth(const struct mcc *ca)
{
	return (u64)MCC_MIN_BDP * ca->max_datagram_size * USEC_PER_SEC
	       / ca->backGround_rtt_us;
}

/* ─── Ring Buffer ─── */

static void mcc_release_ring(struct mcc *ca)
{
	if (ca->ring_allocated && ca->ring) {
		kfree(ca->ring);
		ca->ring = NULL;
		ca->ring_allocated = false;
	}
}

static int mcc_alloc_ring(struct mcc *ca)
{
	ca->ring = kcalloc(MCC_ACK_RING_SIZE, sizeof(struct mcc_ack_entry), GFP_ATOMIC);
	if (!ca->ring)
		return -ENOMEM;
	ca->head = 0;
	ca->tail = 0;
	ca->window_delivered = 0;
	ca->ring_allocated = true;
	return 0;
}

static void mcc_ack_ring_push(struct mcc *ca, u32 acked_bytes, u64 now_ns)
{
	u32 next_tail;

	if (!ca->ring_allocated || acked_bytes == 0)
		return;

	next_tail = (ca->tail + 1) % MCC_ACK_RING_SIZE;
	if (next_tail == ca->head) {
		ca->window_delivered -= ca->ring[ca->head].acked_bytes;
		ca->head = (ca->head + 1) % MCC_ACK_RING_SIZE;
	}

	ca->ring[ca->tail].acked_bytes = acked_bytes;
	ca->ring[ca->tail].time_ns = now_ns;
	ca->tail = next_tail;
	ca->window_delivered += acked_bytes;
}

static u64 mcc_update_bw_filter(struct mcc *ca, u64 now_ns)
{
	u64 srtt_ns;
	u32 h;

	if (ca->smoothed_rtt_us == 0 || !ca->ring_allocated)
		return mcc_min_maxbandwidth(ca);

	srtt_ns = (u64)ca->smoothed_rtt_us * NSEC_PER_USEC;
	h = ca->head;
	while (h != ca->tail) {
		if (now_ns - ca->ring[h].time_ns > srtt_ns) {
			ca->window_delivered -= ca->ring[h].acked_bytes;
			h = (h + 1) % MCC_ACK_RING_SIZE;
		} else {
			break;
		}
	}
	ca->head = h;

	return ca->window_delivered * USEC_PER_SEC / ca->smoothed_rtt_us;
}

/* ─── State Machine Helpers ─── */

static void mcc_may_exit_probe_rtt(struct mcc *ca, u64 now_ns)
{
	if (ca->state == MCC_PROBE_RTT &&
	    (now_ns - ca->last_probe_rtt_start) >= (u64)MCC_PROBE_RTT_DUR_US * NSEC_PER_USEC) {
		ca->state = MCC_GUARD;
		if (ca->old_state == MCC_START)
			ca->state = MCC_START;
	}
}

/* ─── 标准回调实现 ─── */

static void mcc_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u64 now_ns = ktime_get_ns();
	struct mcc *ca = mcc_ca(sk);

	if (ca) {
		mcc_release_ring(ca);
		kfree(ca);
	}

	ca = kzalloc(sizeof(struct mcc), GFP_ATOMIC);
	if (!ca)
		return;
	mcc_set_ca(sk, ca);

	ca->max_datagram_size = tp->mss_cache ? tp->mss_cache : 1460;
	ca->backGround_rtt_us = MCC_BG_RTT_DEFAULT_US;
	ca->last_new_bg_rtt_time = now_ns;
	ca->last_probe_rtt_start = now_ns;
	ca->bdp_limit_factor = (low_rtt_mode == 1) ? 2 : 3;
	ca->state = MCC_START;
	ca->pacing_rate = mcc_min_maxbandwidth(ca);

	if (mcc_alloc_ring(ca) != 0)
		ca->ring_allocated = false;

	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
	sk->sk_pacing_rate = ca->pacing_rate * ca->bdp_limit_factor;
}

static void mcc_release(struct sock *sk)
{
	struct mcc *ca = mcc_ca(sk);
	if (ca) {
		mcc_release_ring(ca);
		kfree(ca);
		mcc_set_ca(sk, NULL);
	}
}

static u32 mcc_ssthresh(struct sock *sk)
{
	return TCP_INFINITE_SSTHRESH;
}

static void mcc_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
}

static u32 mcc_undo_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	return max_t(u32, tp->prior_cwnd, MCC_MIN_BDP);
}

static void mcc_set_state(struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/*
	 * 【防御虚假 RTO + 真实 RTO 全量重置】
	 * Linux 内核在进入 TCP_CA_Loss 时，既可能是真实丢包重传，
	 * 也可能是虚假 RTO (Spurious RTO) 的 Undo 恢复。
	 *
	 * 只有当 tp->retrans_out > 0 时，才说明发生了真实的丢包重传。
	 * 此时必须无条件调用 mcc_init() 进行全量重置，因为网络路径假设已崩塌。
	 *
	 * 如果 tp->retrans_out == 0，说明是虚假 RTO 的撤销操作，
	 * 必须直接忽略，绝不能对 MCC 算法做任何惩罚或重置。
	 */
	if (new_state == TCP_CA_Loss && tp->retrans_out > 0) {
		mcc_init(sk);
	}
}

static void mcc_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
}

static void mcc_pkts_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct mcc *ca = mcc_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u64 now_ns = ktime_get_ns();
	u32 rtt_us = sample->rtt_us;
	u32 acked_bytes;
	u64 cwnd_bytes;
	u32 cwnd_segs;
	s64 rtt_diff;
	s64 threshold;

	if (!ca)
		return;

	/* ═══ Part 1: 状态机检查 (r || 的核心判断) ═══ */
	mcc_may_exit_probe_rtt(ca, now_ns);

	if (ca->state != MCC_PROBE_RTT) {
		rtt_diff = (s64)ca->smoothed_rtt_us - (s64)ca->backGround_rtt_us;
		threshold = (s64)(ca->bdp_limit_factor - 1) * (s64)ca->backGround_rtt_us;

		if (rtt_diff > threshold) {
			/* r == false: RTT 超标，可能抢占了过多带宽 */
			if (ca->state != MCC_STOP) {
				u64 bw;

				ca->state = MCC_STOP;
				bw = mcc_update_bw_filter(ca, now_ns);
				ca->pacing_rate = max_t(u64, bw, mcc_min_maxbandwidth(ca));

				if ((now_ns - ca->last_probe_rtt_start) <
				    (u64)ca->smoothed_rtt_us * NSEC_PER_USEC &&
				    ca->probe_rtt_save_rate != 0)
					ca->pacing_rate = max_t(u64, ca->probe_rtt_save_rate,
								ca->pacing_rate);
			}
		} else {
			/* r == true: RTT 安全 */
			if (ca->state == MCC_STOP)
				ca->state = MCC_GUARD;
		}
	}

	/* ═══ Part 2: RTT 更新 + Ring Push ═══ */
	if (rtt_us != 0) {
		if (ca->smoothed_rtt_us == 0)
			ca->smoothed_rtt_us = rtt_us;
		else
			ca->smoothed_rtt_us = (3 * ca->smoothed_rtt_us + rtt_us) / 4;

		if (rtt_us < ca->backGround_rtt_us) {
			ca->backGround_rtt_us = rtt_us;
			ca->last_new_bg_rtt_time = now_ns;
		}
	}

	acked_bytes = max_t(u32, sample->pkts_acked, 1) * tp->mss_cache;
	mcc_ack_ring_push(ca, acked_bytes, now_ns);

	/* 检查进入 PROBE_RTT */
	if ((now_ns - ca->last_probe_rtt_start) >= (u64)MCC_RTT_UPDATE_INT_US * NSEC_PER_USEC &&
	    (now_ns - ca->last_new_bg_rtt_time) >= (u64)MCC_RTT_UPDATE_INT_US * NSEC_PER_USEC) {
		u64 bw;

		ca->last_probe_rtt_start = now_ns;
		ca->backGround_rtt_us = MCC_BG_RTT_DEFAULT_US;
		ca->old_state = ca->state;
		ca->state = MCC_PROBE_RTT;

		bw = mcc_update_bw_filter(ca, now_ns);
		ca->probe_rtt_save_rate = max_t(u64, bw, mcc_min_maxbandwidth(ca));
	}

	/* 状态驱动的 pacing_rate 增长 */
	switch (ca->state) {
	case MCC_START:
		ca->pacing_rate += (u64)ca->max_datagram_size * USEC_PER_SEC
				   / ca->backGround_rtt_us;
		break;
	case MCC_GUARD:
		ca->ack_count++;
		if (ca->ack_count % 4 == 0)
			ca->pacing_rate += ca->max_datagram_size;
		break;
	case MCC_STOP:
	case MCC_PROBE_RTT:
		break;
	}

	/* ═══ Part 3: cwnd + pacing 写回 (Pacing-Driven Architecture) ═══ */

	/*
	 * 【核心重构】
	 * 当 r == true (非 STOP/PROBE_RTT 状态) 时，将 cwnd 设为无限大。
	 * 此时内核发送引擎被彻底放行，发包节拍完全交由底层的 sk_pacing_rate 接管。
	 * 这完美复刻了原版 Go 代码中 CanSend() 的短路放行逻辑！
	 */
	if (ca->state == MCC_START || ca->state == MCC_GUARD) {
		tp->snd_cwnd = 0x7fffffff;
	} else {
		/*
		 * 当 r == false (MCC_STOP) 或 MCC_PROBE_RTT 时，
		 * 必须对 cwnd 进行物理限制，作为 Pacing 之外的第二道安全防线。
		 */
		cwnd_bytes = ca->pacing_rate * ca->backGround_rtt_us / USEC_PER_SEC;
		cwnd_segs = max_t(u32, cwnd_bytes / ca->max_datagram_size, MCC_MIN_BDP);

		if (ca->state == MCC_PROBE_RTT) {
			/* PROBE_RTT: 0.5 * factor */
			cwnd_segs = (u32)((u64)cwnd_segs * ca->bdp_limit_factor / 2);
		} else {
			/* other: 1.0 * (factor - 0.5) */
			cwnd_segs = (u32)((u64)cwnd_segs * (ca->bdp_limit_factor * 2 - 1) / 2);
		}

		cwnd_segs = max_t(u32, cwnd_segs, MCC_MIN_BDP);
		tp->snd_cwnd = min_t(u32, cwnd_segs, tp->snd_cwnd_clamp);
	}

	/* Pacing Rate 写回内核 (始终乘以 bdp_limit_factor 对齐 OnPacketSent) */
	sk->sk_pacing_rate = ca->pacing_rate * ca->bdp_limit_factor;
}

static void mcc_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	struct mcc *ca = mcc_ca(sk);
	u64 now_ns = ktime_get_ns();
	if (ca)
		mcc_may_exit_probe_rtt(ca, now_ns);
}

static struct tcp_congestion_ops mcc_cong_ops = {
	.init		= mcc_init,
	.release	= mcc_release,
	.ssthresh	= mcc_ssthresh,
	.cong_avoid	= mcc_cong_avoid,
	.undo_cwnd	= mcc_undo_cwnd,
	.set_state	= mcc_set_state,
	.cwnd_event	= mcc_cwnd_event,
	.pkts_acked	= mcc_pkts_acked,
	.cong_control	= mcc_cong_control,
	.owner		= THIS_MODULE,
	.name		= "mcc",
};

static int __init mcc_register(void)
{
	return tcp_register_congestion_control(&mcc_cong_ops);
}

static void __exit mcc_unregister(void)
{
	tcp_unregister_congestion_control(&mcc_cong_ops);
}

module_init(mcc_register);
module_exit(mcc_unregister);

MODULE_AUTHOR("qiulaidongfeng");
MODULE_DESCRIPTION("MCC congestion control for linux kernel");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0-rc1");