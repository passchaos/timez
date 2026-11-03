//! NTS-KE record codec (RFC 8915 section 4.1).
//!
//! Records are type-length-value triples with a critical bit. Parsing is
//! bounded and never allocates; callers can feed a message incrementally and
//! inspect `complete` to know whether the End of Message record arrived.

const std = @import("std");

pub const record_end: u16 = 0;
pub const record_next_protocol: u16 = 1;
pub const record_error: u16 = 2;
pub const record_warning: u16 = 3;
pub const record_aead: u16 = 4;
pub const record_new_cookie: u16 = 5;
pub const record_ntp_server: u16 = 6;
pub const record_ntp_port: u16 = 7;

pub const protocol_ntpv4: u16 = 0;
pub const aead_aes_siv_cmac_256: u16 = 15;

pub const max_records = 64;
pub const max_message_len = 65536;

pub const Record = struct {
    critical: bool,
    kind: u16,
    body: []const u8,
};

pub const Message = struct {
    records: [max_records]Record = undefined,
    count: usize = 0,
    complete: bool = false,

    pub fn find(self: *const Message, kind: u16) ?Record {
        for (self.records[0..self.count]) |record| {
            if (record.kind == kind) return record;
        }
        return null;
    }

    pub fn countKind(self: *const Message, kind: u16) usize {
        var result: usize = 0;
        for (self.records[0..self.count]) |record| {
            if (record.kind == kind) result += 1;
        }
        return result;
    }
};

pub const ParseError = error{
    Truncated,
    TooManyRecords,
    TrailingData,
    InvalidEndRecord,
    InvalidRecord,
};

/// Parse a complete or partial message. A partial message stops before an
/// incomplete record; `complete` is true only after a valid End of Message.
pub fn parse(bytes: []const u8) ParseError!Message {
    var message = Message{};
    var offset: usize = 0;

    while (offset < bytes.len) {
        if (bytes.len - offset < 4) return message;

        const first = bytes[offset];
        const critical = (first & 0x80) != 0;
        const kind = (@as(u16, first & 0x7f) << 8) | bytes[offset + 1];
        const length = readU16(bytes, offset + 2);

        if (bytes.len - offset - 4 < length) return message;
        if (message.count == max_records) return error.TooManyRecords;

        const body = bytes[offset + 4 .. offset + 4 + length];
        message.records[message.count] = .{
            .critical = critical,
            .kind = kind,
            .body = body,
        };
        message.count += 1;
        offset += 4 + length;

        if (kind == record_end) {
            if (!critical or length != 0) return error.InvalidEndRecord;
            if (offset != bytes.len) return error.TrailingData;
            message.complete = true;
            return message;
        }
    }

    return message;
}

/// Parse a fully terminated message and reject a missing End of Message.
pub fn parseComplete(bytes: []const u8) ParseError!Message {
    const message = try parse(bytes);
    if (!message.complete) return error.Truncated;
    return message;
}

/// Append one record. Returns the new offset.
pub fn writeRecord(
    buffer: []u8,
    offset: usize,
    critical: bool,
    kind: u16,
    body: []const u8,
) error{ BufferTooSmall, BodyTooLong }!usize {
    if (body.len > std.math.maxInt(u16)) return error.BodyTooLong;
    if (buffer.len < offset + 4 + body.len) return error.BufferTooSmall;

    const first: u8 = (@as(u8, if (critical) 0x80 else 0)) | @as(u8, @intCast(kind >> 8));
    buffer[offset] = first;
    buffer[offset + 1] = @truncate(kind);
    putU16(buffer, offset + 2, @intCast(body.len));
    @memcpy(buffer[offset + 4 .. offset + 4 + body.len], body);
    return offset + 4 + body.len;
}

fn readU16(bytes: []const u8, offset: usize) u16 {
    return (@as(u16, bytes[offset]) << 8) | bytes[offset + 1];
}

fn putU16(bytes: []u8, offset: usize, value: u16) void {
    bytes[offset] = @truncate(value >> 8);
    bytes[offset + 1] = @truncate(value);
}

test "records parse and terminate" {
    var buffer: [64]u8 = undefined;
    var offset = try writeRecord(&buffer, 0, true, record_next_protocol, &.{0});
    offset = try writeRecord(&buffer, offset, false, record_new_cookie, &.{ 1, 2, 3, 4 });
    offset = try writeRecord(&buffer, offset, true, record_end, &.{});

    const message = try parseComplete(buffer[0..offset]);
    try std.testing.expectEqual(@as(usize, 3), message.count);
    try std.testing.expectEqual(@as(u16, 1), message.countKind(record_new_cookie));
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, message.find(record_new_cookie).?.body);
}

test "partial message is incomplete" {
    var buffer: [32]u8 = undefined;
    const offset = try writeRecord(&buffer, 0, true, record_next_protocol, &.{0});
    const message = try parse(buffer[0..offset]);
    try std.testing.expect(!message.complete);
    try std.testing.expectEqual(@as(usize, 1), message.count);

    // A trailing partial record is ignored rather than rejected.
    const partial = try parse(buffer[0 .. offset + 2]);
    try std.testing.expect(!partial.complete);
    try std.testing.expectEqual(@as(usize, 1), partial.count);
}

test "missing end and trailing data are rejected" {
    var buffer: [64]u8 = undefined;
    const offset = try writeRecord(&buffer, 0, true, record_next_protocol, &.{0});
    try std.testing.expectError(error.Truncated, parseComplete(buffer[0..offset]));

    var second: [64]u8 = undefined;
    var at = try writeRecord(&second, 0, true, record_end, &.{});
    at = try writeRecord(&second, at, false, record_new_cookie, &.{});
    try std.testing.expectError(error.TrailingData, parseComplete(second[0..at]));
}

test "malformed end record is rejected" {
    var buffer: [8]u8 = undefined;
    _ = try writeRecord(&buffer, 0, false, record_end, &.{});
    try std.testing.expectError(error.InvalidEndRecord, parseComplete(&buffer));
}

test "fuzz NTS-KE record parser" {
    try std.testing.fuzz({}, fuzzRecords, .{});
}

fn fuzzRecords(_: void, smith: *std.testing.Smith) !void {
    var buffer: [1024]u8 = undefined;
    const len = smith.slice(&buffer);
    const message = parse(buffer[0..len]) catch return;
    var total: usize = 0;
    for (message.records[0..message.count]) |record| {
        total += 4 + record.body.len;
    }
    if (message.complete) try std.testing.expectEqual(len, total);
    try std.testing.expect(total <= len);
}
