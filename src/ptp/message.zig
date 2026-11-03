//! Bounded IEEE 1588 PTP message parser and serializer.
//!
//! The 34-byte header is parsed into typed fields; message bodies are exposed
//! as a slice into the caller's buffer and parsed by protocol-specific
//! helpers. Every length is validated before use, so the parser is suitable
//! for raw Ethernet and untrusted UDP input and for fuzzing.

const std = @import("std");
const types = @import("types.zig");

pub const header_len = 34;
pub const max_message_len = 4096;

pub const ParseError = error{
    TooShort,
    InvalidLength,
    UnsupportedVersion,
    BodyTooShort,
    BufferTooSmall,
    MessageTooLong,
};

pub const Header = struct {
    transport_specific: u4 = 0,
    message_type: types.MessageType = .sync,
    version: types.Version = .v2,
    minor_version: u4 = 0,
    message_length: u16 = header_len,
    domain: u8 = 0,
    minor_sdo_id: u8 = 0,
    flags: types.Flags = .{},
    correction: types.CorrectionField = .{},
    source_port_identity: types.PortIdentity = .{},
    sequence_id: u16 = 0,
    control_field: u8 = 0,
    log_message_interval: i8 = 0,

    pub fn twoStep(self: Header) bool {
        return self.flags.two_step;
    }

    pub fn unicast(self: Header) bool {
        return self.flags.unicast;
    }
};

pub const Parsed = struct {
    header: Header,
    body: []const u8,
    bytes: []const u8,
};

pub fn parse(bytes: []const u8) ParseError!Parsed {
    if (bytes.len < header_len) return error.TooShort;

    const message_length = readU16(bytes, 2);
    if (message_length < header_len) return error.InvalidLength;
    if (message_length > bytes.len) return error.InvalidLength;
    if (message_length > max_message_len) return error.InvalidLength;

    const first = bytes[0];
    const version: types.Version = @enumFromInt(@as(u4, @truncate(bytes[1])));
    if (version != .v2) return error.UnsupportedVersion;

    const header: Header = .{
        .transport_specific = @truncate(first >> 4),
        .message_type = @enumFromInt(@as(u4, @truncate(first))),
        .version = version,
        .minor_version = @truncate(bytes[1] >> 4),
        .message_length = message_length,
        .domain = bytes[4],
        .minor_sdo_id = bytes[5],
        .flags = @bitCast(readU16(bytes, 6)),
        .correction = .{ .raw = readI64(bytes, 8) },
        .source_port_identity = .{
            .clock_identity = .{ .bytes = bytes[20..28].* },
            .port_number = readU16(bytes, 28),
        },
        .sequence_id = readU16(bytes, 30),
        .control_field = bytes[32],
        .log_message_interval = @bitCast(bytes[33]),
    };

    return .{
        .header = header,
        .body = bytes[header_len..message_length],
        .bytes = bytes[0..message_length],
    };
}

/// Serialize a header plus body. The header's `message_length` is ignored and
/// recomputed from `body.len`.
pub fn write(header: Header, body: []const u8, output: []u8) ParseError!usize {
    const total = header_len + body.len;
    if (total > std.math.maxInt(u16)) return error.MessageTooLong;
    if (output.len < total) return error.BufferTooSmall;

    output[0] = (@as(u8, header.transport_specific) << 4) |
        @as(u8, @intFromEnum(header.message_type));
    output[1] = (@as(u8, header.minor_version) << 4) |
        @as(u8, @intFromEnum(header.version));
    putU16(output, 2, @intCast(total));
    output[4] = header.domain;
    output[5] = header.minor_sdo_id;
    putU16(output, 6, @bitCast(header.flags));
    putI64(output, 8, header.correction.raw);
    @memset(output[16..20], 0);
    @memcpy(output[20..28], &header.source_port_identity.clock_identity.bytes);
    putU16(output, 28, header.source_port_identity.port_number);
    putU16(output, 30, header.sequence_id);
    output[32] = header.control_field;
    output[33] = @bitCast(header.log_message_interval);
    @memcpy(output[header_len..total], body);
    return total;
}

pub const SyncBody = struct {
    origin_timestamp: types.Timestamp,
};

pub fn parseSync(body: []const u8) ParseError!SyncBody {
    if (body.len < 10) return error.BodyTooShort;
    return .{ .origin_timestamp = readTimestamp(body, 0) };
}

pub const FollowUpBody = struct {
    precise_origin_timestamp: types.Timestamp,
};

pub fn parseFollowUp(body: []const u8) ParseError!FollowUpBody {
    if (body.len < 10) return error.BodyTooShort;
    return .{ .precise_origin_timestamp = readTimestamp(body, 0) };
}

pub const DelayReqBody = struct {
    origin_timestamp: types.Timestamp,
};

pub fn parseDelayReq(body: []const u8) ParseError!DelayReqBody {
    if (body.len < 10) return error.BodyTooShort;
    return .{ .origin_timestamp = readTimestamp(body, 0) };
}

pub const DelayRespBody = struct {
    receive_timestamp: types.Timestamp,
    requesting_port_identity: types.PortIdentity,
};

pub fn parseDelayResp(body: []const u8) ParseError!DelayRespBody {
    if (body.len < 20) return error.BodyTooShort;
    return .{
        .receive_timestamp = readTimestamp(body, 0),
        .requesting_port_identity = .{
            .clock_identity = .{ .bytes = body[10..18].* },
            .port_number = readU16(body, 18),
        },
    };
}

pub const AnnounceBody = struct {
    origin_timestamp: types.Timestamp,
    current_utc_offset: i16,
    grandmaster_priority1: u8,
    grandmaster_quality: types.ClockQuality,
    grandmaster_priority2: u8,
    grandmaster_identity: types.ClockIdentity,
    steps_removed: u16,
    time_source: types.TimeSource,
};

pub fn parseAnnounce(body: []const u8) ParseError!AnnounceBody {
    if (body.len < 30) return error.BodyTooShort;
    return .{
        .origin_timestamp = readTimestamp(body, 0),
        .current_utc_offset = @bitCast(readU16(body, 10)),
        .grandmaster_priority1 = body[13],
        .grandmaster_quality = .{
            .clock_class = body[14],
            .clock_accuracy = @enumFromInt(body[15]),
            .offset_scaled_log_variance = readU16(body, 16),
        },
        .grandmaster_priority2 = body[18],
        .grandmaster_identity = .{ .bytes = body[19..27].* },
        .steps_removed = readU16(body, 27),
        .time_source = @enumFromInt(body[29]),
    };
}

pub const SignalingBody = struct {
    target_port_identity: types.PortIdentity,
};

pub fn parseSignaling(body: []const u8) ParseError!SignalingBody {
    if (body.len < 10) return error.BodyTooShort;
    return .{ .target_port_identity = .{
        .clock_identity = .{ .bytes = body[0..8].* },
        .port_number = readU16(body, 8),
    } };
}

/// Write a Sync body. The caller supplies the header.
pub fn writeSync(body: []u8, timestamp: types.Timestamp) ParseError!usize {
    if (body.len < 10) return error.BufferTooSmall;
    writeTimestamp(body, 0, timestamp);
    return 10;
}

pub fn writeFollowUp(body: []u8, timestamp: types.Timestamp) ParseError!usize {
    if (body.len < 10) return error.BufferTooSmall;
    writeTimestamp(body, 0, timestamp);
    return 10;
}

pub fn writeDelayReq(body: []u8, timestamp: types.Timestamp) ParseError!usize {
    if (body.len < 10) return error.BufferTooSmall;
    writeTimestamp(body, 0, timestamp);
    return 10;
}

pub fn writeDelayResp(
    body: []u8,
    timestamp: types.Timestamp,
    requesting: types.PortIdentity,
) ParseError!usize {
    if (body.len < 20) return error.BufferTooSmall;
    writeTimestamp(body, 0, timestamp);
    @memcpy(body[10..18], &requesting.clock_identity.bytes);
    putU16(body, 18, requesting.port_number);
    return 20;
}

pub fn writeAnnounce(body: []u8, announce: AnnounceBody) ParseError!usize {
    if (body.len < 30) return error.BufferTooSmall;
    writeTimestamp(body, 0, announce.origin_timestamp);
    putU16(body, 10, @bitCast(announce.current_utc_offset));
    body[12] = 0;
    body[13] = announce.grandmaster_priority1;
    body[14] = announce.grandmaster_quality.clock_class;
    body[15] = @intFromEnum(announce.grandmaster_quality.clock_accuracy);
    putU16(body, 16, announce.grandmaster_quality.offset_scaled_log_variance);
    body[18] = announce.grandmaster_priority2;
    @memcpy(body[19..27], &announce.grandmaster_identity.bytes);
    putU16(body, 27, announce.steps_removed);
    body[29] = @intFromEnum(announce.time_source);
    return 30;
}

pub fn readTimestamp(bytes: []const u8, offset: usize) types.Timestamp {
    var seconds: u48 = 0;
    var i: usize = 0;
    while (i < 6) : (i += 1) {
        seconds = (seconds << 8) | bytes[offset + i];
    }
    return .{
        .seconds = seconds,
        .nanoseconds = readU32(bytes, offset + 6),
    };
}

pub fn setCorrection(bytes: []u8, correction: types.CorrectionField) void {
    putI64(bytes, 8, correction.raw);
}

pub fn writeTimestamp(bytes: []u8, offset: usize, timestamp: types.Timestamp) void {
    var seconds = timestamp.seconds;
    var i: usize = 0;
    while (i < 6) : (i += 1) {
        bytes[offset + 5 - i] = @truncate(seconds);
        seconds >>= 8;
    }
    putU32(bytes, offset + 6, timestamp.nanoseconds);
}

fn readU16(bytes: []const u8, offset: usize) u16 {
    return (@as(u16, bytes[offset]) << 8) | bytes[offset + 1];
}

fn readU32(bytes: []const u8, offset: usize) u32 {
    return (@as(u32, bytes[offset]) << 24) |
        (@as(u32, bytes[offset + 1]) << 16) |
        (@as(u32, bytes[offset + 2]) << 8) |
        bytes[offset + 3];
}

fn readI64(bytes: []const u8, offset: usize) i64 {
    const high = readU32(bytes, offset);
    const low = readU32(bytes, offset + 4);
    return @bitCast((@as(u64, high) << 32) | low);
}

fn putU16(bytes: []u8, offset: usize, value: u16) void {
    bytes[offset] = @truncate(value >> 8);
    bytes[offset + 1] = @truncate(value);
}

fn putU32(bytes: []u8, offset: usize, value: u32) void {
    bytes[offset] = @truncate(value >> 24);
    bytes[offset + 1] = @truncate(value >> 16);
    bytes[offset + 2] = @truncate(value >> 8);
    bytes[offset + 3] = @truncate(value);
}

fn putI64(bytes: []u8, offset: usize, value: i64) void {
    const unsigned: u64 = @bitCast(value);
    putU32(bytes, offset, @truncate(unsigned >> 32));
    putU32(bytes, offset + 4, @truncate(unsigned));
}

test "header round-trip and body parsing" {
    const header: Header = .{
        .transport_specific = 0,
        .message_type = .follow_up,
        .version = .v2,
        .domain = 0,
        .flags = .{ .two_step = true },
        .correction = .{ .raw = 65536 },
        .source_port_identity = .{
            .clock_identity = types.ClockIdentity.fromU64(0x0011223344556677),
            .port_number = 1,
        },
        .sequence_id = 7,
        .control_field = 2,
        .log_message_interval = -3,
    };
    var body: [32]u8 = undefined;
    const body_len = try writeFollowUp(&body, .{ .seconds = 1_700_000_000, .nanoseconds = 42 });

    var packet: [header_len + 32]u8 = undefined;
    const len = try write(header, body[0..body_len], &packet);
    try std.testing.expectEqual(header_len + body_len, len);

    const parsed = try parse(packet[0..len]);
    try std.testing.expectEqual(types.MessageType.follow_up, parsed.header.message_type);
    try std.testing.expect(parsed.header.twoStep());
    try std.testing.expectEqual(@as(i64, 65536), parsed.header.correction.raw);
    try std.testing.expectEqual(@as(u16, 7), parsed.header.sequence_id);
    try std.testing.expectEqual(@as(i8, -3), parsed.header.log_message_interval);
    try std.testing.expectEqual(@as(u8, 0), parsed.header.domain);

    const follow_up = try parseFollowUp(parsed.body);
    try std.testing.expectEqual(@as(u48, 1_700_000_000), follow_up.precise_origin_timestamp.seconds);
    try std.testing.expectEqual(@as(u32, 42), follow_up.precise_origin_timestamp.nanoseconds);
}

test "announce body round-trip" {
    const announce: AnnounceBody = .{
        .origin_timestamp = .{ .seconds = 1_700_000_000, .nanoseconds = 1 },
        .current_utc_offset = 37,
        .grandmaster_priority1 = 10,
        .grandmaster_quality = .{ .clock_class = 6, .clock_accuracy = .within_100ns, .offset_scaled_log_variance = 0x1234 },
        .grandmaster_priority2 = 20,
        .grandmaster_identity = types.ClockIdentity.fromU64(0x0011223344556677),
        .steps_removed = 2,
        .time_source = .gps,
    };
    var body: [32]u8 = undefined;
    const len = try writeAnnounce(&body, announce);
    const parsed = try parseAnnounce(body[0..len]);
    try std.testing.expectEqual(@as(i16, 37), parsed.current_utc_offset);
    try std.testing.expectEqual(@as(u8, 10), parsed.grandmaster_priority1);
    try std.testing.expectEqual(@as(u8, 6), parsed.grandmaster_quality.clock_class);
    try std.testing.expectEqual(@as(u16, 2), parsed.steps_removed);
    try std.testing.expectEqual(types.TimeSource.gps, parsed.time_source);
    try std.testing.expect(types.ClockIdentity.eql(announce.grandmaster_identity, parsed.grandmaster_identity));
}

test "invalid lengths and versions are rejected" {
    try std.testing.expectError(error.TooShort, parse(&[_]u8{0} ** 33));

    var packet: [header_len]u8 = @splat(0);
    putU16(&packet, 2, 100);
    packet[1] = 2;
    try std.testing.expectError(error.InvalidLength, parse(&packet));

    packet[1] = 1;
    putU16(&packet, 2, header_len);
    try std.testing.expectError(error.UnsupportedVersion, parse(&packet));
}

test "delay response body" {
    var body: [32]u8 = undefined;
    const requesting: types.PortIdentity = .{
        .clock_identity = types.ClockIdentity.fromU64(0x0102030405060708),
        .port_number = 3,
    };
    const len = try writeDelayResp(&body, .{ .seconds = 10, .nanoseconds = 20 }, requesting);
    const parsed = try parseDelayResp(body[0..len]);
    try std.testing.expectEqual(@as(u48, 10), parsed.receive_timestamp.seconds);
    try std.testing.expect(types.PortIdentity.eql(requesting, parsed.requesting_port_identity));
}

test "fuzz ptp message parser" {
    try std.testing.fuzz({}, fuzzParse, .{});
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    var buffer: [max_message_len]u8 = undefined;
    const len = smith.slice(&buffer);
    if (parse(buffer[0..len])) |parsed| {
        var output: [max_message_len]u8 = undefined;
        _ = try write(parsed.header, parsed.body, &output);
        const round = try parse(&output);
        try std.testing.expectEqual(parsed.header.message_type, round.header.message_type);
        try std.testing.expectEqual(parsed.header.domain, round.header.domain);
    } else |_| {}
}
