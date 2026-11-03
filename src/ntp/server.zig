//! Stateless NTPv4/SNTP server response generation.
//!
//! The server accepts a validated request packet and produces a response from
//! a `TimeSource`. It never allocates and rejects unsupported modes and
//! versions. Rate limiting, socket ownership, and NTS key management belong
//! to the caller (or to `nts.zig` for NTS).

const std = @import("std");
const clock = @import("../clock/mod.zig");
const packet_mod = @import("packet.zig");
const timestamp_mod = @import("timestamp.zig");
const nts_mod = @import("nts.zig");

pub const Packet = packet_mod.Packet;
pub const Parsed = packet_mod.Parsed;
pub const Version = packet_mod.Version;
pub const Mode = packet_mod.Mode;
pub const NtpTimestamp = timestamp_mod.NtpTimestamp;
pub const Duration = clock.Duration;
pub const Timestamp = clock.Timestamp;
pub const LeapIndicator = clock.LeapIndicator;

pub const Config = struct {
    /// Stratum advertised when synchronized.
    stratum: u8 = 2,
    poll: i8 = 6,
    precision: i8 = -20,
    root_delay: Duration = .zero,
    root_dispersion: Duration = .zero,
    /// Reference identifier: an IPv4 address or four ASCII characters.
    reference_id: u32 = 0,
    /// Maximum NTP version accepted from clients.
    max_version: Version = .v4,
    /// If the source is unsynchronized, respond with a stratum-zero "INIT"
    /// kiss-o'-death packet instead of claiming to be a valid server.
    respond_when_unsynchronized: bool = true,
    /// Reject unprotected requests with an NTS NAK when NTS is configured.
    require_nts: bool = false,
};

pub const HandleError = packet_mod.ParseError || clock.Error ||
    packet_mod.WriteError || nts_mod.session.Error || error{
    UnsupportedMode,
    UnsupportedVersion,
    NotSynchronized,
};

pub const Server = struct {
    config: Config,
    source: clock.TimeSource,
    /// Optional RFC 8915 server session. When present, authenticated NTS
    /// requests receive protected responses with replacement cookies.
    nts: ?*nts_mod.ServerSession = null,

    pub fn init(source: clock.TimeSource, config: Config) Server {
        return .{ .config = config, .source = source };
    }

    /// Handle one request. `output` must have room for the 48-byte response
    /// plus any extensions the caller wants to append.
    pub fn handle(self: *Server, request_bytes: []const u8, output: []u8) HandleError!usize {
        const request = try packet_mod.parse(request_bytes);

        const response_mode: Mode = switch (request.packet.mode) {
            .client => .server,
            .symmetric_active => .symmetric_passive,
            else => return error.UnsupportedMode,
        };

        if (!request.packet.version.isSupported()) return error.UnsupportedVersion;
        if (@intFromEnum(request.packet.version) > @intFromEnum(self.config.max_version)) {
            return error.UnsupportedVersion;
        }

        const received = try self.source.now();
        const transmitted = try self.source.now();

        if (self.nts) |session| {
            if (request.findExtension(nts_mod.ext_authenticator) != null) {
                var verified = session.verifyRequest(request_bytes) catch
                    return self.handleNak(session, request, request_bytes, received, transmitted, output);
                defer verified.deinit();

                const response = self.buildResponse(request.packet, response_mode, received, transmitted);
                const cookie_count = @min(1 + verified.placeholder_count, nts_mod.cookie.jar_capacity);
                return session.protectResponse(
                    &response,
                    verified.unique_id,
                    &verified.key_material,
                    cookie_count,
                    output,
                );
            }
            if (self.config.require_nts) {
                return self.handleNak(session, request, request_bytes, received, transmitted, output);
            }
        }

        const response = self.buildResponse(request.packet, response_mode, received, transmitted);
        return response.write(output);
    }

    fn buildResponse(
        self: *Server,
        request: Packet,
        response_mode: Mode,
        received: clock.Snapshot,
        transmitted: clock.Snapshot,
    ) Packet {
        var stratum = self.config.stratum;
        var leap = received.quality.leap;
        var reference_id = self.config.reference_id;
        var reference_time = received.quality.reference_time orelse received.utc;

        if (!received.synchronized or received.quality.stratum == 0) {
            stratum = 0;
            leap = .unknown;
            reference_id = asciiReferenceId(.{ 'I', 'N', 'I', 'T' });
            reference_time = received.utc;
        }

        return .{
            .leap = leap,
            .version = request.version,
            .mode = response_mode,
            .stratum = stratum,
            .poll = self.config.poll,
            .precision = self.config.precision,
            .root_delay = timestamp_mod.durationToFixed16_16(self.config.root_delay),
            .root_dispersion = timestamp_mod.durationToUfixed16_16(self.config.root_dispersion),
            .reference_id = reference_id,
            .reference_timestamp = NtpTimestamp.fromTimestamp(reference_time),
            .origin_timestamp = request.transmit_timestamp,
            .receive_timestamp = NtpTimestamp.fromTimestamp(received.utc),
            .transmit_timestamp = NtpTimestamp.fromTimestamp(transmitted.utc),
        };
    }

    fn handleNak(
        self: *Server,
        session: *nts_mod.ServerSession,
        request: Parsed,
        request_bytes: []const u8,
        received: clock.Snapshot,
        transmitted: clock.Snapshot,
        output: []u8,
    ) HandleError!usize {
        const nak: Packet = .{
            .leap = .unknown,
            .version = request.packet.version,
            .mode = .server,
            .stratum = 0,
            .poll = self.config.poll,
            .precision = self.config.precision,
            .reference_id = asciiReferenceId(.{ 'N', 'T', 'S', 'N' }),
            .origin_timestamp = request.packet.transmit_timestamp,
            .receive_timestamp = NtpTimestamp.fromTimestamp(received.utc),
            .transmit_timestamp = NtpTimestamp.fromTimestamp(transmitted.utc),
        };
        var length = try nak.write(output);
        length = try session.appendUniqueId(request_bytes, output, length);
        return length;
    }
};

pub fn asciiReferenceId(text: [4]u8) u32 {
    return @bitCast(text);
}

/// Fixed-window rate limiter suitable for a single server socket.
///
/// This is deliberately not keyed by client address: callers that need
/// per-client limits can maintain a small map keyed by `IpAddress` and reuse
/// the same window algorithm.
pub const RateLimiter = struct {
    window: Duration,
    max_requests: usize,
    window_start: Duration,
    used: usize = 0,
    initialized: bool = false,

    pub fn init(window: Duration, max_requests: usize) RateLimiter {
        return .{ .window = window, .max_requests = max_requests, .window_start = .zero };
    }

    pub fn allow(self: *RateLimiter, now: Duration) bool {
        if (!self.initialized or now.ns - self.window_start.ns >= self.window.ns) {
            self.window_start = now;
            self.used = 0;
            self.initialized = true;
        }
        if (self.used >= self.max_requests) return false;
        self.used += 1;
        return true;
    }
};

const TestClock = struct {
    utc: Timestamp,
    mono: Duration,
    synchronized: bool = true,
    quality: clock.Quality = .{ .leap = .no_warning, .stratum = 1, .precision = -20 },

    pub fn nowSnapshot(self: *TestClock) clock.Error!clock.Snapshot {
        return .{
            .monotonic = self.mono,
            .utc = self.utc,
            .tai = clock.TaiTimestamp.fromNanoseconds(self.utc.ns + 37 * std.time.ns_per_s),
            .quality = self.quality,
            .synchronized = self.synchronized,
        };
    }
};

test "server answers a client request" {
    var test_clock = TestClock{ .utc = Timestamp.fromSeconds(1_700_000_000), .mono = .zero };
    const source = clock.TimeSource.from(TestClock, &test_clock);
    var server = Server.init(source, .{ .stratum = 2, .precision = -20 });

    var request_buffer: [48]u8 = undefined;
    const request: Packet = .{
        .version = .v4,
        .mode = .client,
        .transmit_timestamp = NtpTimestamp.fromTimestamp(test_clock.utc),
    };
    _ = try request.write(&request_buffer);

    var response_buffer: [64]u8 = undefined;
    const len = try server.handle(&request_buffer, &response_buffer);
    try std.testing.expectEqual(@as(usize, 48), len);

    const parsed = try packet_mod.parse(response_buffer[0..len]);
    try std.testing.expectEqual(Mode.server, parsed.packet.mode);
    try std.testing.expectEqual(Version.v4, parsed.packet.version);
    try std.testing.expectEqual(@as(u8, 2), parsed.packet.stratum);
    try std.testing.expectEqual(request.transmit_timestamp.toRaw(), parsed.packet.origin_timestamp.toRaw());
    try std.testing.expectEqual(LeapIndicator.no_warning, parsed.packet.leap);
    try std.testing.expect(!parsed.packet.transmit_timestamp.isZero());
}

test "server refuses to claim synchronization when the source is unsynchronized" {
    var test_clock = TestClock{
        .utc = Timestamp.fromSeconds(1_700_000_000),
        .mono = .zero,
        .synchronized = false,
        .quality = .{ .leap = .unknown, .stratum = 0 },
    };
    const source = clock.TimeSource.from(TestClock, &test_clock);
    var server = Server.init(source, .{ .stratum = 2 });

    var request_buffer: [48]u8 = undefined;
    const request: Packet = .{ .version = .v4, .mode = .client };
    _ = try request.write(&request_buffer);

    var response_buffer: [64]u8 = undefined;
    _ = try server.handle(&request_buffer, &response_buffer);
    const parsed = try packet_mod.parse(response_buffer[0..48]);
    try std.testing.expectEqual(@as(u8, 0), parsed.packet.stratum);
    try std.testing.expectEqual(LeapIndicator.unknown, parsed.packet.leap);
    try std.testing.expectEqual([_]u8{ 'I', 'N', 'I', 'T' }, parsed.packet.kissCode().?);
}

test "server rejects unsupported modes and versions" {
    var test_clock = TestClock{ .utc = Timestamp.fromSeconds(1_700_000_000), .mono = .zero };
    const source = clock.TimeSource.from(TestClock, &test_clock);
    var server = Server.init(source, .{});

    var request_buffer: [48]u8 = undefined;
    var request: Packet = .{ .version = .v4, .mode = .broadcast };
    _ = try request.write(&request_buffer);
    try std.testing.expectError(error.UnsupportedMode, server.handle(&request_buffer, &request_buffer));

    request = .{ .version = .v2, .mode = .client };
    _ = try request.write(&request_buffer);
    try std.testing.expectError(error.UnsupportedVersion, server.handle(&request_buffer, &request_buffer));
}

test "rate limiter bounds request rate" {
    var limiter = RateLimiter.init(Duration.fromSeconds(1), 3);
    try std.testing.expect(limiter.allow(.zero));
    try std.testing.expect(limiter.allow(.zero));
    try std.testing.expect(limiter.allow(.zero));
    try std.testing.expect(!limiter.allow(.zero));
    try std.testing.expect(limiter.allow(Duration.fromSeconds(1)));
}
