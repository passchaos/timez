//! SNTP/NTPv4 client protocol logic.
//!
//! The client owns no sockets: it accepts a `Transport`, emits a 48-byte
//! request, validates the response, and returns an offset/delay measurement.
//! This keeps the wire protocol deterministic and testable while `transport.zig`
//! provides the real UDP implementation.

const std = @import("std");
const clock = @import("../clock/mod.zig");
const packet_mod = @import("packet.zig");
const timestamp_mod = @import("timestamp.zig");
const transport_mod = @import("transport.zig");
const nts_mod = @import("nts.zig");

pub const Packet = packet_mod.Packet;
pub const Parsed = packet_mod.Parsed;
pub const Version = packet_mod.Version;
pub const Mode = packet_mod.Mode;
pub const NtpTimestamp = timestamp_mod.NtpTimestamp;
pub const Duration = clock.Duration;
pub const Timestamp = clock.Timestamp;
pub const Quality = clock.Quality;
pub const LeapIndicator = clock.LeapIndicator;
pub const Transport = transport_mod.Transport;
pub const Received = transport_mod.Received;

pub const Config = struct {
    version: Version = .v4,
    /// Timeout for each receive attempt.
    timeout: Duration = Duration.fromSeconds(3),
    /// Number of receive attempts per query (at least one).
    attempts: usize = 2,
    /// Requested poll exponent, log2 seconds.
    poll: i8 = 6,
    /// Client clock precision exponent.
    precision: i8 = -20,
    /// Reject responses whose source address differs from the configured peer.
    verify_source: bool = true,
    /// Randomize the low 16 bits of the transmit timestamp so a replayed
    /// response cannot satisfy the origin check.
    randomize_transmit: bool = true,
    /// Accept a kiss-o'-death response (stratum 0) instead of returning an
    /// error. Callers normally want the error.
    accept_kiss: bool = false,
    /// Reject a measured delay more negative than this.
    max_negative_delay: Duration = Duration.fromMilliseconds(1),
};

pub const QueryError = packet_mod.ParseError || transport_mod.SendError ||
    transport_mod.ReceiveError || clock.Error || error{
    BufferTooSmall,
    InvalidResponseMode,
    InvalidResponseVersion,
    OriginMismatch,
    ZeroTransmitTimestamp,
    ZeroReceiveTimestamp,
    UnexpectedSource,
    KissOfDeath,
    InvalidDelay,
    InvalidStratum,
} || nts_mod.session.Error;

pub const Measurement = struct {
    /// Server clock minus client clock.
    offset: Duration,
    /// Round-trip delay.
    delay: Duration,
    /// Estimated uncertainty of the offset (server dispersion, precision,
    /// and asymmetry allowance).
    dispersion: Duration,
    /// Client transmit time used in the offset formula.
    t1: Timestamp,
    t2: Timestamp,
    t3: Timestamp,
    t4: Timestamp,
    /// Local monotonic receive time.
    monotonic: Duration,
    quality: Quality,
    leap: LeapIndicator,
    stratum: u8,
    reference_id: u32,
    server: std.Io.net.IpAddress,

    pub fn rootDistance(self: Measurement) Duration {
        return .{ .ns = @divTrunc(self.delay.ns, 2) + self.dispersion.ns };
    }

    pub fn sample(self: Measurement) clock.Sample {
        return .{
            .monotonic = self.monotonic,
            .reference = self.t4.add(self.offset),
            .delay = self.delay,
            .dispersion = self.dispersion,
            .uncertainty = .zero,
            .quality = self.quality,
        };
    }
};

pub const Client = struct {
    source: clock.TimeSource,
    monotonic: clock.Monotonic,
    config: Config,
    /// Optional entropy source used to randomize the transmit timestamp.
    /// When null, a non-cryptographic counter/time mix is used; production
    /// callers should supply an `std.Io` (for example `zio.Runtime.io()`).
    io: ?std.Io = null,
    nonce_counter: u32 = 0,
    /// Optional NTS session. When present, requests and responses are
    /// protected with RFC 8915 extension fields.
    nts: ?*nts_mod.ClientSession = null,
    last_measurement: ?Measurement = null,
    last_kiss_code: ?[4]u8 = null,

    pub fn init(
        source: clock.TimeSource,
        monotonic: clock.Monotonic,
        config: Config,
    ) Client {
        return .{
            .source = source,
            .monotonic = monotonic,
            .config = config,
        };
    }

    fn nextNonce(self: *Client, now: Duration) u16 {
        if (self.io) |io| {
            var bytes: [2]u8 = undefined;
            io.random(&bytes);
            return (@as(u16, bytes[0]) << 8) | bytes[1];
        }

        self.nonce_counter +%= 1;
        var state: u32 = self.nonce_counter;
        const ns64: i64 = @truncate(now.ns);
        const time_bits: u32 = @truncate(@as(u64, @bitCast(ns64)));
        state ^= time_bits ^ (time_bits >> 16);
        state *%= 0x9e37_79b9;
        return @truncate(state ^ (state >> 16));
    }

    /// Perform one query using caller-owned buffers. `request_buffer` must be
    /// at least 48 bytes; `response_buffer` should be at least 48 bytes and
    /// large enough for any extensions the server may send.
    pub fn query(
        self: *Client,
        transport: Transport,
        peer: std.Io.net.IpAddress,
        request_buffer: []u8,
        response_buffer: []u8,
    ) QueryError!Measurement {
        if (request_buffer.len < packet_mod.header_len) return error.BufferTooSmall;

        const before = try self.source.now();

        var request: Packet = .{
            .leap = .no_warning,
            .version = self.config.version,
            .mode = .client,
            .stratum = 0,
            .poll = self.config.poll,
            .precision = self.config.precision,
            .transmit_timestamp = NtpTimestamp.fromTimestamp(before.utc),
        };

        if (self.config.randomize_transmit) {
            const nonce = self.nextNonce(before.monotonic);
            request.transmit_timestamp.fraction =
                (request.transmit_timestamp.fraction & 0xffff_0000) | nonce;
        }

        const request_len = if (self.nts) |session|
            try session.protectRequest(&request, request_buffer)
        else
            try request.write(request_buffer);
        try transport.send(request_buffer[0..request_len]);

        const attempts = @max(self.config.attempts, 1);
        var attempt: usize = 0;
        var received: Received = undefined;
        while (attempt < attempts) : (attempt += 1) {
            received = transport.receive(response_buffer, self.config.timeout) catch |err| switch (err) {
                error.Timeout => continue,
                else => return err,
            };
            break;
        } else {
            return error.Timeout;
        }

        const after = try self.source.now();
        const parsed = if (self.nts) |session| session.unprotectResponse(received.bytes) catch |err| {
            if (session.isNtsNak(received.bytes)) {
                self.last_kiss_code = .{ 'N', 'T', 'S', 'N' };
                return error.KissOfDeath;
            }
            return err;
        } else try packet_mod.parse(received.bytes);

        if (parsed.packet.mode != .server) return error.InvalidResponseMode;
        if (parsed.packet.version != self.config.version and parsed.packet.version != .v4) {
            return error.InvalidResponseVersion;
        }
        if (!parsed.packet.origin_timestamp.eql(request.transmit_timestamp)) {
            return error.OriginMismatch;
        }
        if (parsed.packet.transmit_timestamp.isZero()) return error.ZeroTransmitTimestamp;
        if (parsed.packet.receive_timestamp.isZero()) return error.ZeroReceiveTimestamp;
        if (parsed.packet.stratum > 15) return error.InvalidStratum;

        if (self.config.verify_source) {
            if (!received.from.eql(&peer)) return error.UnexpectedSource;
        }

        if (parsed.packet.stratum == 0 and !self.config.accept_kiss) {
            self.last_kiss_code = parsed.packet.kissCode();
            return error.KissOfDeath;
        }

        const pivot = after.utc;
        const t1 = before.utc;
        const t2 = parsed.packet.receive_timestamp.toTimestampNear(pivot);
        const t3 = parsed.packet.transmit_timestamp.toTimestampNear(pivot);
        const t4 = after.utc;

        const offset_sample: clock.OffsetSample = .{ .t1 = t1, .t2 = t2, .t3 = t3, .t4 = t4 };
        const offset = offset_sample.offset();
        const delay = offset_sample.delay();
        if (delay.ns < -self.config.max_negative_delay.ns) return error.InvalidDelay;

        const server_precision = timestamp_mod.precisionInterval(parsed.packet.precision);
        const dispersion = parsed.packet.rootDispersionDuration().add(server_precision);

        var quality = parsed.packet.quality();
        quality.reference_time = t3;

        const measurement: Measurement = .{
            .offset = offset,
            .delay = if (delay.ns < 0) .zero else delay,
            .dispersion = dispersion,
            .t1 = t1,
            .t2 = t2,
            .t3 = t3,
            .t4 = t4,
            .monotonic = after.monotonic,
            .quality = quality,
            .leap = parsed.packet.leap,
            .stratum = parsed.packet.stratum,
            .reference_id = parsed.packet.reference_id,
            .server = peer,
        };
        self.last_measurement = measurement;
        self.last_kiss_code = null;
        return measurement;
    }
};

const TestClock = struct {
    utc: Timestamp,
    mono: Duration,

    pub fn nowSnapshot(self: *TestClock) clock.Error!clock.Snapshot {
        return .{
            .monotonic = self.mono,
            .utc = self.utc,
            .tai = clock.TaiTimestamp.fromNanoseconds(self.utc.ns + 37 * std.time.ns_per_s),
            .synchronized = true,
        };
    }

    pub fn monotonicNow(self: *TestClock) Duration {
        return self.mono;
    }
};

fn buildResponse(
    buffer: []u8,
    origin: NtpTimestamp,
    receive: Timestamp,
    transmit: Timestamp,
    stratum: u8,
) !void {
    const response: Packet = .{
        .leap = .no_warning,
        .version = .v4,
        .mode = .server,
        .stratum = stratum,
        .poll = 6,
        .precision = -20,
        .root_dispersion = timestamp_mod.durationToUfixed16_16(Duration.fromMilliseconds(1)),
        .reference_id = if (stratum == 0) @bitCast([_]u8{ 'R', 'A', 'T', 'E' }) else 0,
        .origin_timestamp = origin,
        .receive_timestamp = NtpTimestamp.fromTimestamp(receive),
        .transmit_timestamp = NtpTimestamp.fromTimestamp(transmit),
    };
    _ = try response.write(buffer);
}

test "client validates response and computes offset" {
    var test_clock = TestClock{
        .utc = Timestamp.fromSeconds(1_000),
        .mono = .zero,
    };
    const source = clock.TimeSource.from(TestClock, &test_clock);
    const monotonic = clock.Monotonic.from(TestClock, &test_clock);

    const peer = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 123);
    var memory = transport_mod.MemoryTransport.init(peer);
    var response_buffer: [64]u8 = undefined;
    try buildResponse(
        &response_buffer,
        NtpTimestamp.fromTimestamp(test_clock.utc),
        Timestamp.fromSeconds(1_001),
        Timestamp.fromSeconds(1_001),
        1,
    );
    memory.response = response_buffer[0..packet_mod.header_len];

    var client = Client.init(source, monotonic, .{
        .attempts = 1,
        .randomize_transmit = false,
    });
    var request_buffer: [64]u8 = undefined;
    var reply_buffer: [64]u8 = undefined;

    const measurement = try client.query(memory.transport(), peer, &request_buffer, &reply_buffer);
    try std.testing.expectEqual(Duration.fromSeconds(1), measurement.offset);
    try std.testing.expectEqual(Duration.zero, measurement.delay);
    try std.testing.expectEqual(@as(u8, 1), measurement.stratum);
    try std.testing.expectEqual(LeapIndicator.no_warning, measurement.leap);
    try std.testing.expectEqual(@as(usize, 1), memory.sent_count);
    try std.testing.expectEqual(@as(usize, 1), memory.receive_count);
}

test "client rejects origin mismatch and replay" {
    var test_clock = TestClock{
        .utc = Timestamp.fromSeconds(1_000),
        .mono = .zero,
    };
    const source = clock.TimeSource.from(TestClock, &test_clock);
    const monotonic = clock.Monotonic.from(TestClock, &test_clock);
    const peer = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 123);

    var memory = transport_mod.MemoryTransport.init(peer);
    var response_buffer: [64]u8 = undefined;
    try buildResponse(
        &response_buffer,
        NtpTimestamp.fromTimestamp(Timestamp.fromSeconds(999)),
        Timestamp.fromSeconds(1_001),
        Timestamp.fromSeconds(1_001),
        1,
    );
    memory.response = response_buffer[0..packet_mod.header_len];

    var client = Client.init(source, monotonic, .{
        .attempts = 1,
        .randomize_transmit = false,
    });
    var request_buffer: [64]u8 = undefined;
    var reply_buffer: [64]u8 = undefined;
    try std.testing.expectError(
        error.OriginMismatch,
        client.query(memory.transport(), peer, &request_buffer, &reply_buffer),
    );
}

test "client rejects kiss of death by default" {
    var test_clock = TestClock{
        .utc = Timestamp.fromSeconds(1_000),
        .mono = .zero,
    };
    const source = clock.TimeSource.from(TestClock, &test_clock);
    const monotonic = clock.Monotonic.from(TestClock, &test_clock);
    const peer = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 123);

    var memory = transport_mod.MemoryTransport.init(peer);
    var response_buffer: [64]u8 = undefined;
    try buildResponse(
        &response_buffer,
        NtpTimestamp.fromTimestamp(test_clock.utc),
        Timestamp.fromSeconds(1_001),
        Timestamp.fromSeconds(1_001),
        0,
    );
    memory.response = response_buffer[0..packet_mod.header_len];

    var client = Client.init(source, monotonic, .{
        .attempts = 1,
        .randomize_transmit = false,
    });
    var request_buffer: [64]u8 = undefined;
    var reply_buffer: [64]u8 = undefined;
    try std.testing.expectError(
        error.KissOfDeath,
        client.query(memory.transport(), peer, &request_buffer, &reply_buffer),
    );
    try std.testing.expectEqual([_]u8{ 'R', 'A', 'T', 'E' }, client.last_kiss_code.?);
}

test "client rejects responses from the wrong source" {
    var test_clock = TestClock{
        .utc = Timestamp.fromSeconds(1_000),
        .mono = .zero,
    };
    const source = clock.TimeSource.from(TestClock, &test_clock);
    const monotonic = clock.Monotonic.from(TestClock, &test_clock);
    const peer = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 123);
    const other = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 456);

    var memory = transport_mod.MemoryTransport.init(other);
    var response_buffer: [64]u8 = undefined;
    try buildResponse(
        &response_buffer,
        NtpTimestamp.fromTimestamp(test_clock.utc),
        Timestamp.fromSeconds(1_001),
        Timestamp.fromSeconds(1_001),
        1,
    );
    memory.response = response_buffer[0..packet_mod.header_len];

    var client = Client.init(source, monotonic, .{
        .attempts = 1,
        .randomize_transmit = false,
    });
    var request_buffer: [64]u8 = undefined;
    var reply_buffer: [64]u8 = undefined;
    try std.testing.expectError(
        error.UnexpectedSource,
        client.query(memory.transport(), peer, &request_buffer, &reply_buffer),
    );
}

test "client rejects impossible negative delay" {
    var test_clock = TestClock{
        .utc = Timestamp.fromSeconds(1_000),
        .mono = .zero,
    };
    const source = clock.TimeSource.from(TestClock, &test_clock);
    const monotonic = clock.Monotonic.from(TestClock, &test_clock);
    const peer = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 123);

    var memory = transport_mod.MemoryTransport.init(peer);
    var response_buffer: [64]u8 = undefined;
    try buildResponse(
        &response_buffer,
        NtpTimestamp.fromTimestamp(test_clock.utc),
        Timestamp.fromSeconds(1_000),
        Timestamp.fromSeconds(1_002),
        1,
    );
    memory.response = response_buffer[0..packet_mod.header_len];

    var client = Client.init(source, monotonic, .{
        .attempts = 1,
        .randomize_transmit = false,
    });
    var request_buffer: [64]u8 = undefined;
    var reply_buffer: [64]u8 = undefined;
    try std.testing.expectError(
        error.InvalidDelay,
        client.query(memory.transport(), peer, &request_buffer, &reply_buffer),
    );
}

test "measurement converts to a discipline sample" {
    const measurement: Measurement = .{
        .offset = Duration.fromMilliseconds(2),
        .delay = Duration.fromMilliseconds(10),
        .dispersion = Duration.fromMilliseconds(1),
        .t1 = Timestamp.fromSeconds(100),
        .t2 = Timestamp.fromSeconds(101),
        .t3 = Timestamp.fromSeconds(101),
        .t4 = Timestamp.fromSeconds(100),
        .monotonic = Duration.fromSeconds(5),
        .quality = .{ .leap = .no_warning, .stratum = 2 },
        .leap = .no_warning,
        .stratum = 2,
        .reference_id = 0,
        .server = undefined,
    };
    const sample = measurement.sample();
    try std.testing.expectEqual(Duration.fromSeconds(5), sample.monotonic);
    try std.testing.expectEqual(Duration.fromMilliseconds(10), sample.delay);
    try std.testing.expectEqual(Duration.fromMilliseconds(1), sample.dispersion);
}
