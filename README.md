# timez

`timez` is Project-Z's time synchronization library for Zig 0.16.x. It
provides a unified clock model, NTPv4/SNTP and NTS, IEEE 1588 PTP, media and
telecom PTP profiles, Linux timestamping/PTP hardware adapters, and
diagnostics.

## Status

Implemented and tested:

| Area | Contents |
| --- | --- |
| `timez.clock` | `TimeSource`/`Monotonic`, UTC/TAI, leap seconds, clock quality, jump detection, `SystemClock`, offset filtering, frequency estimation, step/slew discipline, holdover, discontinuity reporting |
| `timez.ntp` | Bounded NTPv4/SNTP packet parser/serializer, timestamp era conversion, client, server, kiss-o'-death handling, RFC 5905 clock filter and Marzullo selection, reachability, adaptive polling, UDP and in-memory transports |
| `timez.ntp.nts` | RFC 8915 NTS-KE record codec, RFC 8446 exporter key derivation, AES-SIV-CMAC-256 authenticator, cookie codec and jar, client/server sessions, and a `vail` TLS 1.3 NTS-KE adapter |
| `timez.hal.linux` | `SO_TIMESTAMPING` configuration and `SCM_TIMESTAMPING` parsing, `/dev/ptp*` caps and sys-offset ioctls, `AF_PACKET` raw Ethernet PTP transport |
| `timez.ptp` | IEEE 1588 types, bounded PTPv2 message parser/serializer, BMCA, ordinary/boundary/transparent clock logic, sync/path-delay estimation |
| `timez.profiles` | IEEE 1588 default, 802.1AS/gPTP, AES67/ST 2059-2, G.8275.1, C37.238 |
| `timez.diag` | Offset/drift/jitter statistics, holdover prediction, and metrics/counters |

Deliberately not implemented:

- NTPv4 autokey (obsolete and unsafe).
- A complete tzdata/DST database; local time conversion belongs to `kron` or
  the OS.
- Media rational time bases (`meridian`) and RTP/RTCP NTP mapping (`horizon`).
- VPN/proxy/P2P/casting stacks.

## Dependency direction

```text
timez -> std.Io / zio   clocks, UDP, event loop
      -> vail           TLS 1.3 for NTS-KE
      -> alea           optional nonce/random helper
      -> netz           optional transport helper
```

`timez` does not depend on `horizon`, `strmz`, `castz`, or `kron`.

## Build and test

```sh
zig build test              # unit tests + test/ integration tests
zig build test-integration  # integration tests only
zig build docs              # generated API docs
```

The NTS TLS integration test runs a local vail TLS 1.3 server with an
Ed25519 raw public key and completes a real NTS-KE exchange.

The NTP and PTP wire parsers include `std.testing.fuzz` entry points and are
bounded for arbitrary input. They run as ordinary tests in `zig build test`.
Zig 0.16.0's `-ffuzz` test runner currently fails in its own
`test_runner.zig` with a `builtin.StackTrace`/`debug.StackTrace` type
mismatch, so continuous fuzzing will become available once that upstream
issue is fixed.

## Quick examples

### Clock snapshot

```zig
var system = timez.clock.SystemClock.init(io);
system.setCorrection(offset, frequency, uncertainty, quality);
const snapshot = try system.nowSnapshot();
```

### NTP query

```zig
var client = timez.ntp.Client.init(source, monotonic, .{});
var peer = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 123);
var transport = try timez.ntp.UdpTransport.init(io, peer, null);
defer transport.deinit();
const measurement = try client.query(transport.transport(), peer, &request_buf, &response_buf);
```

### NTS

```zig
var channel = try timez.ntp.nts.vail.VailChannel.init(.{
    .allocator = allocator,
    .io = io,
    .address = ntske_address,
    .server_name = "time.example.com",
    .verifier = verifier,
});
defer channel.deinit();

var negotiation = try timez.ntp.nts.ke.negotiate(channel.channel(), .{});
defer negotiation.deinit();

var session = timez.ntp.nts.ClientSession.init(io, negotiation.keys, negotiation.cookies);
client.nts = &session;
```

### PTP

```zig
var ordinary = timez.ptp.clock.OrdinaryClock.init(.{
    .identity = timez.ptp.types.ClockIdentity.fromU64(1),
    .domain = 0,
});
const event = try ordinary.handleMessage(frame, receive_timestamp);
```

## Verification notes

- All wire parsers are bounded, reject malformed lengths, and never allocate.
- Tests cover clock jumps, slew, holdover, leap conversion, NTP replay/origin
  mismatch, kiss-o'-death, NTS authentication failure, NTS NAK, cookie tamper,
  BMCA ordering, PTP two-step offsets, and Linux software timestamping.
- PTP hardware timestamping is exposed through the HAL but requires a
  PHC-capable NIC and `CAP_NET_RAW`; those hardware paths are not exercised by
  CI-style tests on hosts without those capabilities.
