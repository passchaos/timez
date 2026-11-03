//! Bounded NTPv4/SNTP wire packet parser and serializer.
//!
//! Parsing never allocates and accepts caller-owned buffers. Extension fields
//! are returned as slices into the input; malformed lengths, excessive
//! extension counts, and truncated trailers are rejected. The parser is
//! therefore suitable for fuzzing and for exposing to untrusted networks.
//!
//! NTPv4 autokey is intentionally not implemented. Legacy symmetric-key
//! MACs are recognized only as an opaque trailer.

const std = @import("std");
const clock = @import("../clock/mod.zig");
const timestamp = @import("timestamp.zig");

pub const Quality = clock.Quality;
pub const LeapIndicator = clock.LeapIndicator;
pub const Duration = clock.Duration;
pub const Timestamp = clock.Timestamp;
pub const NtpTimestamp = timestamp.NtpTimestamp;

pub const header_len = 48;
pub const max_extensions = 16;
pub const legacy_mac_len = 20;
pub const max_packet_len = 4096;
pub const WriteError = error{BufferTooSmall};

pub const Version = enum(u3) {
    v1 = 1,
    v2 = 2,
    v3 = 3,
    v4 = 4,
    _,

    pub fn fromByte(value: u8) Version {
        return @enumFromInt(value);
    }

    pub fn isSupported(self: Version) bool {
        return self == .v3 or self == .v4;
    }
};

pub const Mode = enum(u3) {
    reserved = 0,
    symmetric_active = 1,
    symmetric_passive = 2,
    client = 3,
    server = 4,
    broadcast = 5,
    control = 6,
    private = 7,
};

pub const Packet = struct {
    leap: LeapIndicator = .unknown,
    version: Version = .v4,
    mode: Mode = .client,
    stratum: u8 = 0,
    poll: i8 = 0,
    precision: i8 = 0,
    /// Signed 16.16 fixed-point seconds.
    root_delay: i32 = 0,
    /// Unsigned 16.16 fixed-point seconds.
    root_dispersion: u32 = 0,
    reference_id: u32 = 0,
    reference_timestamp: NtpTimestamp = .zero,
    origin_timestamp: NtpTimestamp = .zero,
    receive_timestamp: NtpTimestamp = .zero,
    transmit_timestamp: NtpTimestamp = .zero,

    pub fn rootDelayDuration(self: Packet) Duration {
        return timestamp.fixed16_16ToDuration(self.root_delay);
    }

    pub fn rootDispersionDuration(self: Packet) Duration {
        return timestamp.ufixed16_16ToDuration(self.root_dispersion);
    }

    pub fn quality(self: Packet) Quality {
        return .{
            .leap = self.leap,
            .stratum = self.stratum,
            .precision = self.precision,
            .root_delay = self.rootDelayDuration(),
            .root_dispersion = self.rootDispersionDuration(),
            .reference_id = self.reference_id,
        };
    }

    /// A stratum-zero response carrying a four-byte ASCII code is a kiss-o'-death
    /// (RFC 5905 section 7.4).
    pub fn kissCode(self: Packet) ?[4]u8 {
        if (self.stratum != 0) return null;
        return @bitCast(self.reference_id);
    }

    pub fn isKissOfDeath(self: Packet) bool {
        return self.kissCode() != null;
    }

    /// Serialize the 48-byte header into `buffer`.
    pub fn write(self: Packet, buffer: []u8) WriteError!usize {
        if (buffer.len < header_len) return error.BufferTooSmall;

        const flags: u8 = (@as(u8, @intFromEnum(self.leap)) << 6) |
            (@as(u8, @intFromEnum(self.version)) << 3) |
            @as(u8, @intFromEnum(self.mode));
        buffer[0] = flags;
        buffer[1] = self.stratum;
        buffer[2] = @bitCast(self.poll);
        buffer[3] = @bitCast(self.precision);
        putU32(buffer, 4, @bitCast(self.root_delay));
        putU32(buffer, 8, self.root_dispersion);
        putU32(buffer, 12, self.reference_id);
        putU64(buffer, 16, self.reference_timestamp.toRaw());
        putU64(buffer, 24, self.origin_timestamp.toRaw());
        putU64(buffer, 32, self.receive_timestamp.toRaw());
        putU64(buffer, 40, self.transmit_timestamp.toRaw());
        return header_len;
    }
};

pub const ParseError = error{
    TooShort,
    InvalidVersion,
    InvalidMode,
    BadExtension,
    TooManyExtensions,
    ExtensionTooLong,
};

pub const Extension = struct {
    kind: u16,
    value: []const u8,
    /// Byte offset of the extension field header in the original packet.
    offset: usize,
};

pub const Parsed = struct {
    packet: Packet,
    extensions: [max_extensions]Extension = undefined,
    extension_count: usize = 0,
    mac: ?[]const u8 = null,
    /// Complete packet bytes, for authenticating the header and extensions.
    bytes: []const u8 = &.{},

    pub fn findExtension(self: *const Parsed, kind: u16) ?[]const u8 {
        for (self.extensions[0..self.extension_count]) |extension| {
            if (extension.kind == kind) return extension.value;
        }
        return null;
    }
};

/// Parse a packet. The input is not copied.
pub fn parse(bytes: []const u8) ParseError!Parsed {
    if (bytes.len < header_len) return error.TooShort;

    const flags = bytes[0];
    const leap: LeapIndicator = @enumFromInt(@as(u2, @truncate(flags >> 6)));
    const version = Version.fromByte(@as(u3, @truncate(flags >> 3)));
    const mode: Mode = @enumFromInt(@as(u3, @truncate(flags)));
    if (@intFromEnum(version) == 0 or @intFromEnum(version) > 4) return error.InvalidVersion;
    if (mode == .reserved) return error.InvalidMode;

    var parsed = Parsed{
        .packet = .{
            .leap = leap,
            .version = version,
            .mode = mode,
            .stratum = bytes[1],
            .poll = @bitCast(bytes[2]),
            .precision = @bitCast(bytes[3]),
            .root_delay = @bitCast(readU32(bytes, 4)),
            .root_dispersion = readU32(bytes, 8),
            .reference_id = readU32(bytes, 12),
            .reference_timestamp = NtpTimestamp.fromRaw(readU64(bytes, 16)),
            .origin_timestamp = NtpTimestamp.fromRaw(readU64(bytes, 24)),
            .receive_timestamp = NtpTimestamp.fromRaw(readU64(bytes, 32)),
            .transmit_timestamp = NtpTimestamp.fromRaw(readU64(bytes, 40)),
        },
        .bytes = bytes,
    };

    var offset: usize = header_len;
    while (offset < bytes.len) {
        const remaining = bytes.len - offset;

        // A 20-byte trailer that is not a valid extension field is treated as
        // a legacy symmetric-key MAC (key id + digest).
        if (remaining == legacy_mac_len and !isValidExtensionHeader(bytes[offset..])) {
            parsed.mac = bytes[offset..];
            break;
        }

        if (remaining < 4) {
            if (allZero(bytes[offset..])) break;
            return error.BadExtension;
        }

        const kind = readU16(bytes, offset);
        const length = readU16(bytes, offset + 2);

        if (length < 4 or length % 4 != 0) {
            if (remaining == legacy_mac_len) {
                parsed.mac = bytes[offset..];
                break;
            }
            if (allZero(bytes[offset..])) break;
            return error.BadExtension;
        }
        if (length > remaining) return error.ExtensionTooLong;
        if (parsed.extension_count == max_extensions) return error.TooManyExtensions;

        parsed.extensions[parsed.extension_count] = .{
            .kind = kind,
            .value = bytes[offset + 4 .. offset + length],
            .offset = offset,
        };
        parsed.extension_count += 1;
        offset += length;
    }

    return parsed;
}

fn isValidExtensionHeader(bytes: []const u8) bool {
    if (bytes.len < 4) return false;
    const length = readU16(bytes, 2);
    return length >= 4 and length % 4 == 0 and length <= bytes.len;
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}

/// Write one padded extension field at `offset`. Returns the new offset.
/// Values are padded with zero bytes so the extension length stays a multiple
/// of four. The caller owns the returned offset and may append more fields.
pub fn writeExtension(
    buffer: []u8,
    offset: usize,
    kind: u16,
    value: []const u8,
) error{ BufferTooSmall, ExtensionTooLong }!usize {
    const padded_len = (value.len + 3) & ~@as(usize, 3);
    const total_len = 4 + padded_len;
    if (total_len > std.math.maxInt(u16)) return error.ExtensionTooLong;
    if (buffer.len < offset + total_len) return error.BufferTooSmall;

    putU16(buffer, offset, kind);
    putU16(buffer, offset + 2, @intCast(total_len));
    @memcpy(buffer[offset + 4 .. offset + 4 + value.len], value);
    @memset(buffer[offset + 4 + value.len .. offset + total_len], 0);
    return offset + total_len;
}

/// Append a legacy 20-byte MAC trailer. The digest is caller-computed.
pub fn writeLegacyMac(
    buffer: []u8,
    offset: usize,
    key_id: u32,
    digest: *const [16]u8,
) error{BufferTooSmall}!usize {
    if (buffer.len < offset + legacy_mac_len) return error.BufferTooSmall;
    putU32(buffer, offset, key_id);
    @memcpy(buffer[offset + 4 .. offset + legacy_mac_len], digest);
    return offset + legacy_mac_len;
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

fn readU64(bytes: []const u8, offset: usize) u64 {
    return (@as(u64, readU32(bytes, offset)) << 32) | readU32(bytes, offset + 4);
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

fn putU64(bytes: []u8, offset: usize, value: u64) void {
    putU32(bytes, offset, @truncate(value >> 32));
    putU32(bytes, offset + 4, @truncate(value));
}

test "packet round-trip" {
    const packet: Packet = .{
        .leap = .no_warning,
        .version = .v4,
        .mode = .server,
        .stratum = 2,
        .poll = 6,
        .precision = -20,
        .root_delay = 0x0000_1234,
        .root_dispersion = 0x0000_5678,
        .reference_id = 0x41424344,
        .reference_timestamp = .{ .seconds = 1, .fraction = 2 },
        .origin_timestamp = .{ .seconds = 3, .fraction = 4 },
        .receive_timestamp = .{ .seconds = 5, .fraction = 6 },
        .transmit_timestamp = .{ .seconds = 7, .fraction = 8 },
    };
    var buffer: [header_len]u8 = undefined;
    const len = try packet.write(&buffer);
    try std.testing.expectEqual(@as(usize, 48), len);

    const parsed = try parse(&buffer);
    try std.testing.expectEqual(packet.leap, parsed.packet.leap);
    try std.testing.expectEqual(packet.version, parsed.packet.version);
    try std.testing.expectEqual(packet.mode, parsed.packet.mode);
    try std.testing.expectEqual(packet.stratum, parsed.packet.stratum);
    try std.testing.expectEqual(packet.poll, parsed.packet.poll);
    try std.testing.expectEqual(packet.precision, parsed.packet.precision);
    try std.testing.expectEqual(packet.root_delay, parsed.packet.root_delay);
    try std.testing.expectEqual(packet.root_dispersion, parsed.packet.root_dispersion);
    try std.testing.expectEqual(packet.reference_id, parsed.packet.reference_id);
    try std.testing.expectEqual(packet.transmit_timestamp.toRaw(), parsed.packet.transmit_timestamp.toRaw());
    try std.testing.expectEqual(@as(usize, 0), parsed.extension_count);
    try std.testing.expect(parsed.mac == null);
}

test "extensions parse and preserve bounds" {
    var buffer: [header_len + 64]u8 = undefined;
    const base: Packet = .{ .version = .v4, .mode = .client };
    const header = try base.write(&buffer);
    var offset = try writeExtension(&buffer, header, 0x0101, "hello");
    offset = try writeExtension(&buffer, offset, 0x0403, &[_]u8{1} ** 20);

    const parsed = try parse(buffer[0..offset]);
    try std.testing.expectEqual(@as(usize, 2), parsed.extension_count);
    try std.testing.expectEqualSlices(u8, "hello\x00\x00\x00", parsed.findExtension(0x0101).?);
    try std.testing.expectEqual(@as(usize, 20), parsed.findExtension(0x0403).?.len);
}

test "legacy mac trailer is recognized" {
    var buffer: [header_len + legacy_mac_len]u8 = undefined;
    const base: Packet = .{ .version = .v4, .mode = .server };
    const header = try base.write(&buffer);
    const digest = [_]u8{0xaa} ** 16;
    const offset = try writeLegacyMac(&buffer, header, 0xdeadbeef, &digest);
    const parsed = try parse(buffer[0..offset]);
    try std.testing.expectEqual(@as(usize, 0), parsed.extension_count);
    try std.testing.expectEqual(@as(usize, 20), parsed.mac.?.len);
    try std.testing.expectEqual(@as(u32, 0xdeadbeef), readU32(parsed.mac.?, 0));
}

test "malformed extension length is rejected" {
    var buffer: [header_len + 8]u8 = undefined;
    const base: Packet = .{ .version = .v4, .mode = .client };
    _ = try base.write(&buffer);
    putU16(&buffer, header_len, 0x0101);
    putU16(&buffer, header_len + 2, 3); // not a multiple of four
    try std.testing.expectError(error.BadExtension, parse(&buffer));
}

test "extension overflow is rejected" {
    var buffer: [header_len + 8]u8 = undefined;
    const base: Packet = .{ .version = .v4, .mode = .client };
    _ = try base.write(&buffer);
    putU16(&buffer, header_len, 0x0101);
    putU16(&buffer, header_len + 2, 100);
    try std.testing.expectError(error.ExtensionTooLong, parse(&buffer));
}

test "kiss of death code" {
    const packet: Packet = .{
        .stratum = 0,
        .reference_id = @bitCast([_]u8{ 'R', 'A', 'T', 'E' }),
    };
    try std.testing.expect(packet.isKissOfDeath());
    try std.testing.expectEqual([_]u8{ 'R', 'A', 'T', 'E' }, packet.kissCode().?);
}

test "too short and invalid versions" {
    try std.testing.expectError(error.TooShort, parse(&[_]u8{0} ** 47));
    var buffer: [header_len]u8 = undefined;

    // v1/v2 are structurally parseable; protocol policy rejects them.
    const legacy: Packet = .{ .version = .v1, .mode = .client };
    _ = try legacy.write(&buffer);
    const parsed = try parse(&buffer);
    try std.testing.expectEqual(Version.v1, parsed.packet.version);

    const invalid: Packet = .{ .version = @enumFromInt(0), .mode = .client };
    _ = try invalid.write(&buffer);
    try std.testing.expectError(error.InvalidVersion, parse(&buffer));
}

test "fuzz packet parser is bounded" {
    try std.testing.fuzz({}, fuzzParsePacket, .{});
}

fn fuzzParsePacket(_: void, smith: *std.testing.Smith) !void {
    var buffer: [max_packet_len]u8 = undefined;
    const len = smith.slice(&buffer);
    const bytes = buffer[0..len];

    if (parse(bytes)) |parsed| {
        // A successfully parsed packet must serialize back into a valid
        // 48-byte header without reading beyond the input.
        var output: [header_len]u8 = undefined;
        _ = try parsed.packet.write(&output);
        const round = try parse(&output);
        try std.testing.expectEqual(parsed.packet.mode, round.packet.mode);
        try std.testing.expectEqual(parsed.packet.version, round.packet.version);
        try std.testing.expectEqual(parsed.packet.stratum, round.packet.stratum);
    } else |_| {}
}
