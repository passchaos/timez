# Architecture

`timez` is layered so protocol logic, clock discipline, and platform access
can be tested independently.

```text
                    consumers
       horizon / strmz / castz / kron
                       |
                    timez
   +-------------------+-------------------+
   |                   |                   |
 clock               ntp                 ptp
   |             /    |    \               |
 system      client server selection   message
 discipline      \    |    /               |
   |              transport               bmca
   |                   |                   |
   +------------ std.Io / zio -------------+
                       |
                     hal.linux
             timestamping / ptp_clock / raw_ethernet
```

## Clock model

`clock.TimeSource` returns one coherent `Snapshot` containing monotonic time,
UTC, TAI, offset, frequency, uncertainty, quality, and an optional
discontinuity. `SystemClock` reads host clocks through `std.Io`.
`DisciplinedClock` consumes reference samples, filters them, estimates
frequency, and applies bounded steps or slews. Holdover grows uncertainty
from a configurable drift bound.

## NTP

The NTP packet parser is allocation-free and bounded. The client validates
mode, version, origin timestamp, source address, zero timestamps, and delay.
The server is stateless except for optional rate limiting and NTS cookie keys.
Selection keeps eight samples per server, picks the lowest-delay sample,
ages dispersion, intersects candidate intervals (Marzullo), and combines
survivors with inverse-variance weights.

## NTS

NTS-KE is abstracted behind `nts.ke.Channel`: application-data send/receive,
close, and the RFC 8446 exporter. `nts.ke.negotiate` implements the client
record exchange and `nts.ke.negotiateServer` validates requests, derives keys,
and mints encrypted cookies for the server response. `nts.vail` implements the
client channel with vail's incremental TLS 1.3 state machine; the integration
suite also drives a vail TLS 1.3 server channel through `negotiateServer`. The NTP packet layer uses:

- Unique Identifier (0x0104), at least 32 random octets.
- NTS Cookie (0x0204), opaque.
- NTS Cookie Placeholder (0x0304).
- NTS Authenticator and Encrypted Extension Fields (0x0404).

Only AEAD_AES_SIV_CMAC_256 (identifier 15) is implemented. The authenticator
associated data is the packet from the header through the last extension
before the authenticator. Server cookies are AES-SIV encrypted and contain
the negotiated AEAD identifier and both direction keys.

## PTP

PTP messages are parsed with strict length checks. The ordinary clock builds
and consumes Sync/Follow_Up/Delay_Req/Delay_Resp/Pdelay_Req/Pdelay_Resp/
Pdelay_Resp_Follow_Up/Announce messages. The BMCA
orders datasets by priority1, clockClass, clockAccuracy,
offsetScaledLogVariance, priority2, clockIdentity, and stepsRemoved.
Transparent clocks add ingress-to-egress residence time to the correction
field. Boundary clocks hold up to eight independent ordinary-clock ports.

## HAL

Linux is the first HAL. `SO_TIMESTAMPING` returns software and raw PHC
timestamps; `/dev/ptp*` exposes caps, `PTP_SYS_OFFSET`, and
`PTP_SYS_OFFSET_PRECISE`; `AF_PACKET` provides Layer-2 PTP transport.
macOS and Windows adapters can be added behind `hal.mod` without changing
clock or protocol code.
