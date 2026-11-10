# MCC for linux

原版实现在https://github.com/qiulaidongfeng/quic-go/blob/master/internal/congestion/mcc.go

目前这是对MCC V2的linux拥塞控制内核模块实现，是bate1版本，功能基本正确，但每条流需要多至少156.25 KiB内存，有待优化。

在mcc_loss目录，是一个基于背景丢包和实际丢包来测量本流对拥塞的贡献程度实现。