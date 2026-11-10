// mcc.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <linux/limits.h>

#define BATCH_PKTS         1000U
#define THRESHOLD_EXTRA    100U
#define ALPHA_DEC          700U
#define MIN_CWND           128U
#define INIT_CWND          128U

#define RTT_WIN_MS         5000U   /* MinRTT观测窗口：5s */
#define LOSS_BG_WIN_MS     5000U   /* 背景丢包滑动窗口：5s */
#define SAMPLE_PERIOD_MS   500U    /* 背景丢包采样周期：500ms */
#define MAX_BG_SAMPLES     (LOSS_BG_WIN_MS / SAMPLE_PERIOD_MS) /* 10 */
#define CWND_DECAY_WIN_MS  5000U
#define MAX_DECAY_CNT      3U

struct mcc_loss_state {
    /* 背景丢包：基线样本环形buffer */
    u32 bg_sample_buf[MAX_BG_SAMPLES];
    bool bg_sample_valid[MAX_BG_SAMPLES];
    int bg_sample_idx;
    u32 bg_cached_min;

    /* 背景采样计数器（500ms周期） */
    u32 bg_sent;
    u32 bg_acked;
    u32 bg_lost;
    u64 last_bg_sample_ts;

    /* 实际丢包判断计数器：每累计1000 acked包触发一次降窗判断 */
    u32 run_sent;
    u32 run_acked;
    u32 run_lost;

    u64 ack_accum;

    u64 cycle_start_ts;
    u64 probe_end_ts;
    bool in_probe_minrtt;
    u32 probe_saved_cwnd;

    u64 rtt_window_start;
    u32 rtt_min_5s_us;

    u32 ssthresh_val;
    u32 recover_mark;   /* NewReno风格：记录本次降窗时的 snd_nxt */

    u64 decay_win_start;
    u32 decay_cnt;
};

static u32 scan_bg_min(struct mcc_loss_state *st)
{
    int i;
    u32 min_val = U32_MAX;
    for (i = 0; i < MAX_BG_SAMPLES; i++) {
        if (!st->bg_sample_valid[i])
            continue;
        if (st->bg_sample_buf[i] < min_val)
            min_val = st->bg_sample_buf[i];
    }
    return min_val;
}

static void push_bg_loss_sample(struct mcc_loss_state *st, u32 loss_scaled)
{
    st->bg_sample_buf[st->bg_sample_idx] = loss_scaled;
    st->bg_sample_valid[st->bg_sample_idx] = true;
    st->bg_sample_idx = (st->bg_sample_idx + 1) % MAX_BG_SAMPLES;
    st->bg_cached_min = scan_bg_min(st);
}

static void mcc_loss_init(struct sock *sk)
{
    void **ca_ptr = (void **)inet_csk_ca(sk);
    struct mcc_loss_state *st;
    struct tcp_sock *tp = tcp_sk(sk);
    int i;

    st = kmalloc(sizeof(*st), GFP_ATOMIC);
    if (!st) {
        *ca_ptr = NULL;
        return;
    }
    memset(st, 0, sizeof(*st));

    for (i = 0; i < MAX_BG_SAMPLES; i++) {
        st->bg_sample_valid[i] = false;
    }
    st->bg_cached_min = U32_MAX;
    st->last_bg_sample_ts = tp->tcp_mstamp;
    st->ack_accum = 0;

    st->cycle_start_ts = tp->tcp_mstamp;
    st->probe_end_ts = 0;
    st->in_probe_minrtt = false;
    st->probe_saved_cwnd = 0;

    st->rtt_window_start = tp->tcp_mstamp;
    st->rtt_min_5s_us = U32_MAX;

    st->ssthresh_val = TCP_INFINITE_SSTHRESH;
    st->recover_mark = 0;

    st->decay_win_start = tp->tcp_mstamp;
    st->decay_cnt = 0;

    tp->snd_cwnd = INIT_CWND;
    tp->snd_ssthresh = st->ssthresh_val;

    *ca_ptr = st;
}

static void mcc_loss_release(struct sock *sk)
{
    void **ca_ptr = (void **)inet_csk_ca(sk);
    kfree(*ca_ptr);
    *ca_ptr = NULL;
}

static void mcc_loss_set_state(struct sock *sk, u8 new_state)
{
    (void)sk;
    (void)new_state;
}

static u32 mcc_loss_ssthresh(struct sock *sk)
{
    void **ca_ptr = (void **)inet_csk_ca(sk);
    struct mcc_loss_state *st = *ca_ptr;
    if (!st)
        return MIN_CWND;
    return st->ssthresh_val;
}

static u32 mcc_loss_undo_cwnd(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    return tp->snd_cwnd;
}

static void mcc_loss_cong_control(struct sock *sk, u32 ack, int flag, const struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    void **ca_ptr = (void **)inet_csk_ca(sk);
    struct mcc_loss_state *st = *ca_ptr;
    u64 now = tp->tcp_mstamp;
    u32 cwnd;
    u32 lost_pkts;
    u32 delivered_pkts;
    u32 sent_pkts;
    u32 rtt_curr_us = rs->rtt_us;
    bool rtt_over_250 = false;

    if (!st)
        return;

    cwnd = tp->snd_cwnd;
    delivered_pkts = rs->delivered;
    lost_pkts = rs->losses;
    sent_pkts = delivered_pkts + lost_pkts;

    /* 两路独立累加：背景统计、实际丢包判断统计 */
    st->bg_sent += sent_pkts;
    st->bg_acked += delivered_pkts;
    st->bg_lost += lost_pkts;

    st->run_sent += sent_pkts;
    st->run_acked += delivered_pkts;
    st->run_lost += lost_pkts;

    /* 5s降窗窗口滚动重置 */
    if (now - st->decay_win_start >= CWND_DECAY_WIN_MS * 1000ULL) {
        st->decay_win_start = now;
        st->decay_cnt = 0;
    }

    /* NewReno：ack覆盖recover_mark（snd_nxt）才清除恢复标记 */
    if (st->recover_mark != 0 && after(ack, st->recover_mark)) {
        st->recover_mark = 0;
    }

    /* 维护5s minRTT窗口，无局部副本 */
    if (now - st->rtt_window_start >= RTT_WIN_MS * 1000ULL) {
        st->rtt_min_5s_us = U32_MAX;
        st->rtt_window_start = now;
    }
    if (rtt_curr_us > 0) {
        if (st->rtt_min_5s_us == U32_MAX || rtt_curr_us < st->rtt_min_5s_us) {
            st->rtt_min_5s_us = rtt_curr_us;
        }
    }

    /* pacing rate: 2 * cwnd * mss / minrtt */
    if (st->rtt_min_5s_us != 0 && st->rtt_min_5s_us != U32_MAX) {
        u64 rate;
        rate = div_u64(2ULL * cwnd * tp->mss_cache * 1000000ULL, st->rtt_min_5s_us);
        WRITE_ONCE(sk->sk_pacing_rate, rate);
    }

    /* minRTT探测开始 */
    if ((now - st->cycle_start_ts) >= RTT_WIN_MS * 1000ULL && !st->in_probe_minrtt) {
        st->probe_saved_cwnd = cwnd;
        cwnd = cwnd / 2U;
        st->in_probe_minrtt = true;

        /* 探测时清空两套计数器 */
        st->bg_sent = 0;
        st->bg_acked = 0;
        st->bg_lost = 0;
        st->run_sent = 0;
        st->run_acked = 0;
        st->run_lost = 0;
        st->last_bg_sample_ts = now;

        if (st->rtt_min_5s_us != U32_MAX) {
            st->probe_end_ts = now + st->rtt_min_5s_us;
        } else {
            st->probe_end_ts = now + 200000ULL;
        }
        st->cycle_start_ts = now;
        goto write_out;
    }

    /* 探测结束恢复 */
    if (st->in_probe_minrtt && now >= st->probe_end_ts) {
        st->in_probe_minrtt = false;
        st->probe_end_ts = 0;
        cwnd = st->probe_saved_cwnd;
    }

    /* ====== 背景丢包基线：500ms周期结算，周期内bg_acked>1000才写入样本 ====== */
    if (now - st->last_bg_sample_ts >= SAMPLE_PERIOD_MS * 1000ULL)
    {
        if (st->bg_acked > BATCH_PKTS)
        {
            u32 loss_scaled = st->bg_lost * 10000U / st->bg_sent;
            push_bg_loss_sample(st, loss_scaled);
        }
        st->last_bg_sample_ts = now;
        st->bg_sent = 0;
        st->bg_acked = 0;
        st->bg_lost = 0;
    }

    /* ====== 实际丢包判断：累计run_acked >=1000包触发一次，和bg_cached_min基线对比降窗 ====== */
    if (st->run_acked >= BATCH_PKTS)
    {
        if (!st->in_probe_minrtt && st->bg_cached_min != U32_MAX
            && st->recover_mark == 0 && st->decay_cnt < MAX_DECAY_CNT)
        {
            u32 curr_loss_scaled = st->run_lost * 10000U / st->run_sent;
            if (curr_loss_scaled > (st->bg_cached_min + THRESHOLD_EXTRA))
            {
                st->ssthresh_val = (cwnd * ALPHA_DEC) / 1000U;
                if (st->ssthresh_val < MIN_CWND)
                    st->ssthresh_val = MIN_CWND;
                cwnd = st->ssthresh_val;
                if (st->ssthresh_val > 1)
                    st->ssthresh_val--;
                /* NewReno: 记录本次降窗时已经发出的最高序号 snd_nxt */
                st->recover_mark = tp->snd_nxt;
                st->decay_cnt++;
            }
        }
        /* 本轮实际丢包判断完成，清零，开启下一轮1000包统计 */
        st->run_sent = 0;
        st->run_acked = 0;
        st->run_lost = 0;
    }

    /* 探测阶段禁止任何增窗 */
    if (st->in_probe_minrtt)
        goto write_out;

    /* RTT规则：慢启动RTT>150%minrtt立刻退出慢启动；RTT>250%禁止增窗 */
    if (rtt_curr_us > 0 && st->rtt_min_5s_us != U32_MAX)
    {
        if (cwnd <= st->ssthresh_val && (rtt_curr_us * 100U > st->rtt_min_5s_us * 150U))
        {
            if (cwnd > 1)
                st->ssthresh_val = cwnd - 1;
            else
                st->ssthresh_val = cwnd;
        }
        if (rtt_curr_us * 100U > st->rtt_min_5s_us * 250U)
        {
            rtt_over_250 = true;
        }
    }

    /* 增窗：慢启动指数；拥塞避免 4 / rtt_sec 每ACK累加 */
    if (!rtt_over_250 && delivered_pkts > 0)
    {
        if (cwnd <= st->ssthresh_val)
        {
            cwnd += delivered_pkts;
        }
        else
        {
            u64 step_acks = (4ULL * 1000000ULL) / st->rtt_min_5s_us;
            st->ack_accum += delivered_pkts;
            while (step_acks > 0 && st->ack_accum >= step_acks)
            {
                cwnd += 1;
                st->ack_accum -= step_acks;
            }
        }
    }

write_out:
    tp->snd_cwnd = cwnd;
    tp->snd_ssthresh = st->ssthresh_val;
}

static struct tcp_congestion_ops tcp_mcc_loss_ops = {
    .init        = mcc_loss_init,
    .release     = mcc_loss_release,
    .ssthresh    = mcc_loss_ssthresh,
    .undo_cwnd   = mcc_loss_undo_cwnd,
    .set_state   = mcc_loss_set_state,
    .cong_control= mcc_loss_cong_control,
    .name        = "mcc_loss",
    .owner       = THIS_MODULE,
};

static int __init mcc_loss_register(void)
{
    return tcp_register_congestion_control(&tcp_mcc_loss_ops);
}

static void __exit mcc_loss_unregister(void)
{
    tcp_unregister_congestion_control(&tcp_mcc_loss_ops);
}

module_init(mcc_loss_register);
module_exit(mcc_loss_unregister);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Custom");
MODULE_DESCRIPTION("MCC-loss: "
"背景丢包：500ms周期，周期内acked>1000才进5s环形基线样本；"
"实际丢包降窗判断：累计acked满1000包触发一次，和背景基线对比；"
"recover_mark采用NewReno风格，记录snd_nxt，ack覆盖snd_nxt才解除恢复；"
"ssthresh=cwnd-1立即退出慢启动；RTT 150%/250%阈值；拥塞避免：4/rtt_sec；"
"探测开始直接goto write_out，并同步last_bg_sample_ts");
