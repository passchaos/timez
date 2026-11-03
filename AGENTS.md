# AGENTS.md

## 项目定位

`timez` 是 Project-Z 的时间同步库，负责 NTP/SNTP/NTS、PTP/IEEE 1588/802.1AS、clock discipline、holdover、leap seconds 和硬件时间戳。

当前状态：仅完成目录与 Git 脚手架，尚未实现代码。不要声称任何功能已经完成。

## 目标能力

- clock：统一 TimeSource，暴露 monotonic、UTC、TAI、offset、frequency、uncertainty、quality、discontinuity。
- NTP：NTPv4/SNTP client/server、server selection、polling、leap seconds。
- NTS：RFC 8915，TLS 1.3 密钥建立 + AEAD。
- PTP：IEEE 1588 ordinary/boundary/transparent clock、BMCA、correctionField。
- profiles：802.1AS/gPTP、AES67/ST 2059-2、G.8275.1、C37.238。
- HAL：Linux `SO_TIMESTAMPING`、`PTP_SYS_OFFSET`、`/dev/ptp*`、raw Ethernet；后续 macOS/Windows adapter。
- diag：offset/drift/jitter、holdover、metrics。

## 边界与非目标

- 不实现媒体时间基；`meridian/src/time.zig` 继续拥有媒体 rational time base。
- 不实现 RTP/RTCP 的 NTP 时间戳映射；`horizon` 已有 `rtp_to_ntp_estimator`。
- 不实现日志时间格式化；`kron` 负责日志，可消费 `timez` 的 UTC/时间源。
- 不拥有完整 tzdata/DST 数据库；本地时区转换由 `kron` 或 OS tzdata 负责。
- 不实现 VPN/代理/P2P/投屏；分别属于 `vpnz`/`proxyz`/`p2pz`/`castz`。
- 不实现 NTPv4 autokey；已过时且不安全。
- 不把 PTP 放进 `netz`；PTP 需要 raw Ethernet/硬件时间戳/PHC。

## 依赖方向

```text
timez -> zio/std.Io   (clock、UDP、事件循环)
      -> vail         (NTS 的 TLS 1.3)
      -> alea         (nonce/随机)
      -> netz         (可选，UDP/TLS 传输辅助)
```

不得反向依赖。`horizon`/`strmz`/`castz` 消费 `timez`；`timez` 不依赖它们。

## 规划模块

```text
src/
  clock/      time source, monotonic/utc/tai, offset, quality, discontinuity
  ntp/        ntpv4/sntp client/server, nts, leap seconds, server selection
  ptp/        ieee1588, 802.1as, bmca, ordinary/boundary/transparent clock
  profiles/   aes67/st2059-2, g.8275.1, c37.238
  hal/        linux timestamping, /dev/ptp*, raw ethernet
  diag/       offset/drift/jitter, holdover, metrics
  root.zig
```

## 与相邻库的关系

- `horizon` 继续负责 RTP/RTCP 内部的 NTP 时间戳映射和媒体同步；`timez` 只提供系统时间源。
- `meridian` 继续负责媒体时间基；`timez` 不进入媒体核心。
- `strmz` 用 `timez` 做 live edge、segment 可用时间、LL-HLS/LL-DASH 调度。
- `castz` 用 `timez` 做多设备同步和超时。
- `kron` 可选消费 `timez` 的 UTC/时间源给日志打时间戳；本地时区/DST 转换仍由 `kron` 或 OS tzdata 负责，`timez` 不依赖 `kron`。
- `vail` 提供 NTS 所需 TLS 1.3；`netz` 可选提供传输。

## 里程碑

1. `timez.clock`：TimeSource、monotonic/UTC/TAI、offset/quality/discontinuity。
2. `timez.ntp`：SNTP/NTPv4 client，再做 server。
3. NTS：TLS 1.3 + AEAD。
4. `timez.hal`：Linux 时钟/时间戳适配。
5. `timez.ptp`：ordinary clock + default profile。
6. 802.1AS + 媒体/电信 profile。
7. holdover、leap seconds、诊断和测量。

## 验证策略

- 单元测试贴近实现；协议/时钟集成测试放 `test/`。
- 先跑最小单测和模块测试；PTP/HAL 改动再跑硬件相关测试。
- 所有 NTP/PTP wire parser 必须有界、可 fuzz。
- 必须测试时钟跳变、slew、holdover、错误服务器、重放、NTS 失败和权限不足。
- 性能/精度指标至少包含：offset、drift、jitter、holdover、PTP 硬件时间戳误差。

## 安全与合规

- 优先 NTS；不要实现 NTP autokey。
- PTP 默认无加密；不要把 PTP 当作安全边界。
- 时钟同步不能成为权限提升或注入入口；所有输入必须有界验证。

## Zig 约定

- 使用 Zig 0.16.x 语义和标准库 API。
- `zig fmt .`；显式 allocator/ownership；热路径避免不必要分配。
- 协议、clock discipline、HAL 分层，便于独立测试和跨平台适配。

## 当前待办

- 等待用户选择开发优先级。
- 先做 `timez.clock + timez.ntp`；PTP 在专业 AV/TSN 需求明确后再做。
