# Validation

## Commands

```sh
zig build test
zig build test-integration
```

`zig build test` runs module unit tests and the integration suite. The
integration suite includes:

- A real UDP loopback NTP request/response exchange.
- NTP client -> clock filter/selection -> discipline composition.
- NTS client/server protection and NTS NAK handling.
- A real `vail` TLS 1.3 NTS-KE exchange using an Ed25519 raw public key,
  including the server negotiation path and encrypted cookie minting.
- Linux `SO_TIMESTAMPING` receive timestamps on loopback.
- PTP announce/sync/follow-up feeding the discipline loop.

## Fuzzing

Both wire parsers have `std.testing.fuzz` entry points, which run as normal
tests in `zig build test`. The NTP fuzz test round-trips any successfully
parsed packet; the PTP fuzz test does the same for headers and bodies.
Parsers reject excessive lengths, invalid versions, malformed extension
fields, and truncated bodies.

Zig 0.16.0's `-ffuzz` test runner currently fails in its own
`test_runner.zig` (`builtin.StackTrace` versus `debug.StackTrace`), so
continuous fuzzing is pending that upstream fix.

## Coverage highlights

- Clock: UTC/TAI round-trip, leap table boundaries, pending positive/negative
  leaps, jump vs slew detection, holdover entry, frequency estimation.
- NTP: packet/extension/MAC parsing, era disambiguation, origin mismatch,
  replay, wrong source, kiss-o'-death, negative delay, NTS tamper and replay.
- NTS: KE record termination, server errors, unknown critical records,
  exporter context, cookie tamper and key rotation, NAK matching.
- PTP: header/body round-trip, announce parsing, BMCA tie-breakers,
  two-step offset, path delay, transparent-clock residence, boundary ports.
- HAL: timestamping control parsing, typed permission errors, raw Ethernet
  frame sizes, live software timestamps.
- Diag: min/max/mean/RMS/jitter, holdover prediction, metrics formatting.

## Hardware limits

PTP hardware timestamping and `/dev/ptp*` tests require a PHC-capable NIC,
kernel support, and `CAP_NET_RAW`/device permissions. The HAL returns typed
`AccessDenied`, `NoSuchInterface`, `Unsupported`, and `NoDevice` errors when
those are unavailable.
