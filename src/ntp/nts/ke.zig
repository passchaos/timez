//! NTS-KE client negotiation (RFC 8915 section 4).
//!
//! TLS is abstracted behind `Channel`: an adapter supplies authenticated
//! application-data transport plus the RFC 8446 exporter. This keeps the
//! record protocol testable without a TLS stack while allowing `vail` or any
//! other TLS 1.3 implementation to be plugged in.

const std = @import("std");
const records = @import("records.zig");
const keys = @import("keys.zig");
const cookie = @import("cookie.zig");

pub const max_response_len = 8192;
pub const max_server_name_len = 255;

pub const Channel = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (ctx: *anyopaque, bytes: []const u8) anyerror!void,
        /// Return the number of bytes written to `buffer`; zero means closed.
        receive: *const fn (ctx: *anyopaque, buffer: []u8) anyerror!usize,
        export_keying_material: *const fn (
            ctx: *anyopaque,
            label: []const u8,
            context: []const u8,
            output: []u8,
        ) anyerror!void,
        close: *const fn (ctx: *anyopaque) void,
    };

    pub fn send(self: Channel, bytes: []const u8) anyerror!void {
        return self.vtable.send(self.ctx, bytes);
    }

    pub fn receive(self: Channel, buffer: []u8) anyerror!usize {
        return self.vtable.receive(self.ctx, buffer);
    }

    pub fn close(self: Channel) void {
        return self.vtable.close(self.ctx);
    }

    /// Build an exporter that forwards to this channel. The caller must keep
    /// the `Channel` value alive for the duration of the export.
    pub fn exporter(self: *const Channel) keys.Exporter {
        const Adapter = struct {
            fn exportKeyingMaterial(
                ctx: *anyopaque,
                label: []const u8,
                context: []const u8,
                output: []u8,
            ) anyerror!void {
                const channel: *const Channel = @ptrCast(@alignCast(ctx));
                return channel.vtable.export_keying_material(channel.ctx, label, context, output);
            }
        };
        return .{
            .ctx = @constCast(self),
            .export_fn = Adapter.exportKeyingMaterial,
        };
    }
};

/// Fixed-size storage for the negotiated NTP server name.
pub const ServerName = struct {
    bytes: [max_server_name_len]u8 = undefined,
    len: usize = 0,

    pub fn set(self: *ServerName, name: []const u8) error{NameTooLong}!void {
        if (name.len > max_server_name_len) return error.NameTooLong;
        @memcpy(self.bytes[0..name.len], name);
        self.len = name.len;
    }

    pub fn slice(self: *const ServerName) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const Config = struct {
    /// Next protocols offered, in preference order. NTPv4 is 0.
    protocols: []const u16 = &.{records.protocol_ntpv4},
    /// AEAD algorithms offered, in preference order. AES-SIV-CMAC-256 is 15.
    aead_algorithms: []const u16 = &.{records.aead_aes_siv_cmac_256},
    /// Optional NTP server name to request.
    server_name: ?[]const u8 = null,
    /// Optional NTP server port to request.
    server_port: ?u16 = null,
};

pub const Negotiation = struct {
    keys: keys.KeyMaterial,
    cookies: cookie.Jar,
    aead_id: u16,
    server_name: ServerName,
    server_port: u16 = 123,
    warning_count: usize = 0,

    pub fn deinit(self: *Negotiation) void {
        self.keys.deinit();
    }
};

pub const NegotiateError = error{
    ResponseTooLarge,
    Closed,
    NoNextProtocol,
    NoAead,
    NoCookies,
    UnsupportedAead,
    UnsupportedProtocol,
    ServerError,
    ServerWarning,
    UnknownCriticalRecord,
    DuplicateRecord,
    InvalidRecord,
    NameTooLong,
    CookieTooLarge,
};

pub fn negotiate(channel: Channel, config: Config) anyerror!Negotiation {
    errdefer channel.close();

    var request_buffer: [512]u8 = undefined;
    var offset: usize = 0;

    var protocol_body: [2 * 8]u8 = undefined;
    if (config.protocols.len == 0 or config.protocols.len > 8) return error.InvalidRecord;
    for (config.protocols, 0..) |protocol, i| {
        putU16(&protocol_body, i * 2, protocol);
    }
    offset = try records.writeRecord(
        &request_buffer,
        offset,
        true,
        records.record_next_protocol,
        protocol_body[0 .. config.protocols.len * 2],
    );

    var aead_body: [2 * 8]u8 = undefined;
    if (config.aead_algorithms.len == 0 or config.aead_algorithms.len > 8) return error.InvalidRecord;
    for (config.aead_algorithms, 0..) |aead, i| {
        putU16(&aead_body, i * 2, aead);
    }
    offset = try records.writeRecord(
        &request_buffer,
        offset,
        true,
        records.record_aead,
        aead_body[0 .. config.aead_algorithms.len * 2],
    );

    if (config.server_name) |name| {
        offset = try records.writeRecord(
            &request_buffer,
            offset,
            false,
            records.record_ntp_server,
            name,
        );
    }
    if (config.server_port) |port| {
        var port_body: [2]u8 = undefined;
        putU16(&port_body, 0, port);
        offset = try records.writeRecord(
            &request_buffer,
            offset,
            false,
            records.record_ntp_port,
            &port_body,
        );
    }
    offset = try records.writeRecord(&request_buffer, offset, true, records.record_end, &.{});

    try channel.send(request_buffer[0..offset]);

    var response_buffer: [max_response_len]u8 = undefined;
    var response_len: usize = 0;
    var message: records.Message = undefined;
    while (true) {
        if (response_len == response_buffer.len) return error.ResponseTooLarge;
        const n = try channel.receive(response_buffer[response_len..]);
        if (n == 0) return error.Closed;
        response_len += n;
        message = try records.parse(response_buffer[0..response_len]);
        if (message.complete) break;
    }

    var result = Negotiation{
        .keys = undefined,
        .cookies = .{},
        .aead_id = records.aead_aes_siv_cmac_256,
        .server_name = .{},
    };

    var next_protocol_count: usize = 0;
    var aead_count: usize = 0;
    var cookie_count: usize = 0;
    var server_name_count: usize = 0;
    var port_count: usize = 0;

    for (message.records[0..message.count]) |record| {
        if (record.critical and record.kind > records.record_ntp_port) {
            return error.UnknownCriticalRecord;
        }
        switch (record.kind) {
            records.record_error => {
                if (record.body.len != 2) return error.InvalidRecord;
                return error.ServerError;
            },
            records.record_warning => {
                if (record.body.len != 2) return error.InvalidRecord;
                result.warning_count += 1;
            },
            records.record_next_protocol => {
                next_protocol_count += 1;
                if (next_protocol_count > 1) return error.DuplicateRecord;
                if (record.body.len % 2 != 0) return error.InvalidRecord;
                var found = false;
                var i: usize = 0;
                while (i < record.body.len) : (i += 2) {
                    if (readU16(record.body, i) == records.protocol_ntpv4) found = true;
                }
                if (!found) return error.UnsupportedProtocol;
            },
            records.record_aead => {
                aead_count += 1;
                if (aead_count > 1) return error.DuplicateRecord;
                if (record.body.len != 2) return error.InvalidRecord;
                const aead_id = readU16(record.body, 0);
                if (aead_id != records.aead_aes_siv_cmac_256) return error.UnsupportedAead;
                result.aead_id = aead_id;
            },
            records.record_new_cookie => {
                cookie_count += 1;
                try result.cookies.add(record.body);
            },
            records.record_ntp_server => {
                server_name_count += 1;
                if (server_name_count > 1) return error.DuplicateRecord;
                try result.server_name.set(record.body);
            },
            records.record_ntp_port => {
                port_count += 1;
                if (port_count > 1) return error.DuplicateRecord;
                if (record.body.len != 2) return error.InvalidRecord;
                result.server_port = readU16(record.body, 0);
            },
            records.record_end => {},
            else => {},
        }
    }

    if (next_protocol_count == 0) return error.NoNextProtocol;
    if (aead_count == 0) return error.NoAead;
    if (cookie_count == 0) return error.NoCookies;
    if (result.warning_count != 0) return error.ServerWarning;

    result.keys = try keys.derive(channel.exporter(), result.aead_id);
    channel.close();
    return result;
}

fn readU16(bytes: []const u8, offset: usize) u16 {
    return (@as(u16, bytes[offset]) << 8) | bytes[offset + 1];
}

fn putU16(bytes: []u8, offset: usize, value: u16) void {
    bytes[offset] = @truncate(value >> 8);
    bytes[offset + 1] = @truncate(value);
}

pub const ServerConfig = struct {
    /// Cookie key ring used to mint opaque cookies for the client.
    key_ring: *cookie.KeyRing,
    /// Number of replacement cookies to send. RFC 8915 recommends eight.
    cookies_per_response: usize = 8,
    /// Optional NTP server name/port advertised to the client.
    server_name: ?[]const u8 = null,
    server_port: ?u16 = null,
};

pub const ServerNegotiation = struct {
    keys: keys.KeyMaterial,
    aead_id: u16,
    cookie_count: usize,

    pub fn deinit(self: *ServerNegotiation) void {
        self.keys.deinit();
    }
};

pub const ServerError = error{
    BadRequest,
    UnknownCriticalRecord,
    NoSharedProtocol,
    NoSharedAead,
    ResponseTooLarge,
    Closed,
};

/// Server side of an NTS-KE exchange. The caller supplies a TLS channel that
/// has already completed its handshake and a cookie key ring. On success the
/// response is sent and the derived keys are returned.
pub fn negotiateServer(channel: Channel, config: ServerConfig) anyerror!ServerNegotiation {
    errdefer channel.close();

    var request_buffer: [max_response_len]u8 = undefined;
    var request_len: usize = 0;
    var message: records.Message = undefined;
    while (true) {
        if (request_len == request_buffer.len) return error.ResponseTooLarge;
        const n = try channel.receive(request_buffer[request_len..]);
        if (n == 0) return error.Closed;
        request_len += n;
        message = try records.parse(request_buffer[0..request_len]);
        if (message.complete) break;
    }

    // RFC 8915: unknown critical records must produce error code 0.
    for (message.records[0..message.count]) |record| {
        if (record.critical and record.kind > records.record_ntp_port) {
            try sendError(channel, 0);
            return error.UnknownCriticalRecord;
        }
    }

    var protocol_count: usize = 0;
    var aead_count: usize = 0;
    var protocol_seen = false;
    var aead_seen = false;
    var requested_name: ?[]const u8 = null;
    var requested_port: ?u16 = null;

    for (message.records[0..message.count]) |record| {
        switch (record.kind) {
            records.record_end => {},
            records.record_next_protocol => {
                protocol_count += 1;
                if (protocol_count > 1 or record.body.len % 2 != 0) {
                    try sendError(channel, 1);
                    return error.BadRequest;
                }
                var i: usize = 0;
                while (i < record.body.len) : (i += 2) {
                    if (readU16(record.body, i) == records.protocol_ntpv4) protocol_seen = true;
                }
            },
            records.record_aead => {
                aead_count += 1;
                if (aead_count > 1 or record.body.len != 2) {
                    try sendError(channel, 1);
                    return error.BadRequest;
                }
                if (readU16(record.body, 0) == records.aead_aes_siv_cmac_256) aead_seen = true;
            },
            records.record_ntp_server => {
                if (requested_name != null) {
                    try sendError(channel, 1);
                    return error.BadRequest;
                }
                requested_name = record.body;
            },
            records.record_ntp_port => {
                if (requested_port != null or record.body.len != 2) {
                    try sendError(channel, 1);
                    return error.BadRequest;
                }
                requested_port = readU16(record.body, 0);
            },
            records.record_error, records.record_warning, records.record_new_cookie => {
                try sendError(channel, 1);
                return error.BadRequest;
            },
            else => {
                if (record.critical) {
                    try sendError(channel, 0);
                    return error.UnknownCriticalRecord;
                }
            },
        }
    }

    if (protocol_count == 0 or !protocol_seen) {
        try sendError(channel, 1);
        return error.NoSharedProtocol;
    }
    if (aead_count == 0 or !aead_seen) {
        try sendError(channel, 1);
        return error.NoSharedAead;
    }

    const keys_value = try keys.derive(channel.exporter(), records.aead_aes_siv_cmac_256);

    var response: [max_response_len]u8 = undefined;
    var offset: usize = 0;
    offset = try records.writeRecord(&response, offset, true, records.record_next_protocol, &.{ 0, 0 });
    offset = try records.writeRecord(&response, offset, false, records.record_aead, &.{ 0, 15 });

    if (config.server_name orelse requested_name) |name| {
        offset = try records.writeRecord(&response, offset, false, records.record_ntp_server, name);
    }
    if (config.server_port orelse requested_port) |port| {
        var body: [2]u8 = undefined;
        putU16(&body, 0, port);
        offset = try records.writeRecord(&response, offset, false, records.record_ntp_port, &body);
    }

    const cookie_count = std.math.clamp(config.cookies_per_response, 1, 8);
    var cookie_buffer: [cookie.max_cookie_len]u8 = undefined;
    var i: usize = 0;
    while (i < cookie_count) : (i += 1) {
        const value = try config.key_ring.encode(&cookie_buffer, keys_value);
        offset = try records.writeRecord(&response, offset, false, records.record_new_cookie, value);
    }
    offset = try records.writeRecord(&response, offset, true, records.record_end, &.{});

    try channel.send(response[0..offset]);
    channel.close();

    return .{
        .keys = keys_value,
        .aead_id = records.aead_aes_siv_cmac_256,
        .cookie_count = cookie_count,
    };
}

fn sendError(channel: Channel, code: u16) !void {
    var buffer: [16]u8 = undefined;
    var body: [2]u8 = undefined;
    putU16(&body, 0, code);
    var offset = try records.writeRecord(&buffer, 0, true, records.record_error, &body);
    offset = try records.writeRecord(&buffer, offset, true, records.record_end, &.{});
    try channel.send(buffer[0..offset]);
}

test "negotiation accepts a complete response" {
    const Mock = struct {
        response: []const u8,
        response_offset: usize = 0,
        exporter_calls: usize = 0,
        closed: bool = false,

        pub fn sendBytes(_: *@This(), _: []const u8) !void {}

        pub fn receiveBytes(self: *@This(), buffer: []u8) !usize {
            if (self.response_offset == self.response.len) return 0;
            const remaining = self.response.len - self.response_offset;
            const n = @min(buffer.len, remaining);
            @memcpy(buffer[0..n], self.response[self.response_offset .. self.response_offset + n]);
            self.response_offset += n;
            return n;
        }

        pub fn exportKeyingMaterial(
            self: *@This(),
            label: []const u8,
            context: []const u8,
            output: []u8,
        ) !void {
            try std.testing.expectEqualStrings(keys.exporter_label, label);
            try std.testing.expectEqual(@as(usize, 5), context.len);
            self.exporter_calls += 1;
            @memset(output, @truncate(self.exporter_calls));
        }

        pub fn closeChannel(self: *@This()) void {
            self.closed = true;
        }

        fn vtSend(ctx: *anyopaque, bytes: []const u8) anyerror!void {
            const ptr: *@This() = @ptrCast(@alignCast(ctx));
            return ptr.sendBytes(bytes);
        }

        fn vtReceive(ctx: *anyopaque, buffer: []u8) anyerror!usize {
            const ptr: *@This() = @ptrCast(@alignCast(ctx));
            return ptr.receiveBytes(buffer);
        }

        fn vtExport(ctx: *anyopaque, label: []const u8, context: []const u8, output: []u8) anyerror!void {
            const ptr: *@This() = @ptrCast(@alignCast(ctx));
            return ptr.exportKeyingMaterial(label, context, output);
        }

        fn vtClose(ctx: *anyopaque) void {
            const ptr: *@This() = @ptrCast(@alignCast(ctx));
            ptr.closeChannel();
        }

        fn channel(self: *@This()) Channel {
            return .{
                .ctx = self,
                .vtable = &.{
                    .send = vtSend,
                    .receive = vtReceive,
                    .export_keying_material = vtExport,
                    .close = vtClose,
                },
            };
        }
    };

    var response_buffer: [256]u8 = undefined;
    var offset: usize = 0;
    offset = try records.writeRecord(&response_buffer, offset, true, records.record_next_protocol, &.{ 0, 0 });
    offset = try records.writeRecord(&response_buffer, offset, false, records.record_aead, &.{ 0, 15 });
    offset = try records.writeRecord(&response_buffer, offset, false, records.record_new_cookie, &[_]u8{0xaa} ** 16);
    offset = try records.writeRecord(&response_buffer, offset, false, records.record_new_cookie, &[_]u8{0xbb} ** 16);
    offset = try records.writeRecord(&response_buffer, offset, false, records.record_ntp_server, "ntp.example.com");
    offset = try records.writeRecord(&response_buffer, offset, false, records.record_ntp_port, &.{ 0, 123 });
    offset = try records.writeRecord(&response_buffer, offset, true, records.record_end, &.{});

    var mock = Mock{ .response = response_buffer[0..offset] };
    var result = try negotiate(mock.channel(), .{});
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), mock.exporter_calls);
    try std.testing.expectEqual(@as(usize, 2), result.cookies.len());
    try std.testing.expectEqualStrings("ntp.example.com", result.server_name.slice());
    try std.testing.expectEqual(@as(u16, 123), result.server_port);
    try std.testing.expect(mock.closed);
}

test "negotiation rejects server errors and unknown critical records" {
    const Mock = struct {
        response: []const u8,
        offset: usize = 0,
        pub fn sendBytes(_: *@This(), _: []const u8) !void {}
        pub fn receiveBytes(self: *@This(), buffer: []u8) !usize {
            const n = @min(buffer.len, self.response.len - self.offset);
            @memcpy(buffer[0..n], self.response[self.offset .. self.offset + n]);
            self.offset += n;
            return n;
        }
        pub fn exportKeyingMaterial(_: *@This(), _: []const u8, _: []const u8, _: []u8) !void {}
        pub fn closeChannel(_: *@This()) void {}
        fn vtSend(_: *anyopaque, _: []const u8) anyerror!void {}

        fn vtReceive(ctx: *anyopaque, buffer: []u8) anyerror!usize {
            const ptr: *@This() = @ptrCast(@alignCast(ctx));
            return ptr.receiveBytes(buffer);
        }

        fn vtExport(_: *anyopaque, _: []const u8, _: []const u8, _: []u8) anyerror!void {}

        fn vtClose(_: *anyopaque) void {}

        fn channel(self: *@This()) Channel {
            return .{
                .ctx = self,
                .vtable = &.{
                    .send = vtSend,
                    .receive = vtReceive,
                    .export_keying_material = vtExport,
                    .close = vtClose,
                },
            };
        }
    };

    var buffer: [64]u8 = undefined;
    var at = try records.writeRecord(&buffer, 0, true, records.record_error, &.{ 0, 1 });
    at = try records.writeRecord(&buffer, at, true, records.record_end, &.{});
    var mock = Mock{ .response = buffer[0..at] };
    try std.testing.expectError(error.ServerError, negotiate(mock.channel(), .{}));

    var second: [64]u8 = undefined;
    var offset = try records.writeRecord(&second, 0, true, 0x1234, &.{});
    offset = try records.writeRecord(&second, offset, true, records.record_end, &.{});
    var unknown = Mock{ .response = second[0..offset] };
    try std.testing.expectError(error.UnknownCriticalRecord, negotiate(unknown.channel(), .{}));
}

const ServerMock = struct {
    request: []const u8,
    request_offset: usize = 0,
    response: [1024]u8 = undefined,
    response_len: usize = 0,
    exporter_calls: usize = 0,
    closed: bool = false,

    fn vtSend(ctx: *anyopaque, bytes: []const u8) anyerror!void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        if (self.response_len + bytes.len > self.response.len) return error.BufferTooSmall;
        @memcpy(self.response[self.response_len .. self.response_len + bytes.len], bytes);
        self.response_len += bytes.len;
    }

    fn vtReceive(ctx: *anyopaque, buffer: []u8) anyerror!usize {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        const remaining = self.request.len - self.request_offset;
        const n = @min(buffer.len, remaining);
        @memcpy(buffer[0..n], self.request[self.request_offset .. self.request_offset + n]);
        self.request_offset += n;
        return n;
    }

    fn vtExport(ctx: *anyopaque, label: []const u8, context: []const u8, output: []u8) anyerror!void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        try std.testing.expectEqualStrings(keys.exporter_label, label);
        try std.testing.expectEqual(@as(usize, 5), context.len);
        self.exporter_calls += 1;
        @memset(output, @truncate(self.exporter_calls));
    }

    fn vtClose(ctx: *anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.closed = true;
    }

    fn channel(self: *@This()) Channel {
        return .{
            .ctx = self,
            .vtable = &.{
                .send = vtSend,
                .receive = vtReceive,
                .export_keying_material = vtExport,
                .close = vtClose,
            },
        };
    }
};

test "server negotiation mints cookies and derives keys" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const codec = cookie.Codec.init(io, 7, [_]u8{0x33} ** 32);
    var key_ring = cookie.KeyRing{ .current = codec };

    var request_buffer: [128]u8 = undefined;
    var offset: usize = 0;
    offset = try records.writeRecord(&request_buffer, offset, true, records.record_next_protocol, &.{ 0, 0 });
    offset = try records.writeRecord(&request_buffer, offset, true, records.record_aead, &.{ 0, 15 });
    offset = try records.writeRecord(&request_buffer, offset, false, records.record_ntp_server, "ntp.example.com");
    offset = try records.writeRecord(&request_buffer, offset, true, records.record_end, &.{});

    var mock = ServerMock{ .request = request_buffer[0..offset] };
    var negotiation = try negotiateServer(mock.channel(), .{
        .key_ring = &key_ring,
        .cookies_per_response = 2,
    });
    defer negotiation.deinit();

    try std.testing.expectEqual(@as(usize, 2), negotiation.cookie_count);
    try std.testing.expectEqual(@as(usize, 2), mock.exporter_calls);
    try std.testing.expect(mock.closed);

    const response = try records.parseComplete(mock.response[0..mock.response_len]);
    try std.testing.expectEqual(@as(usize, 2), response.countKind(records.record_new_cookie));
    try std.testing.expectEqualSlices(u8, "ntp.example.com", response.find(records.record_ntp_server).?.body);

    const cookie_body = response.find(records.record_new_cookie).?.body;
    const recovered = try codec.decode(cookie_body);
    try std.testing.expect(negotiation.keys.eql(recovered));
}

test "server negotiation rejects a request without AEAD" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const codec = cookie.Codec.init(io, 7, [_]u8{0x33} ** 32);
    var key_ring = cookie.KeyRing{ .current = codec };

    var request_buffer: [64]u8 = undefined;
    var offset: usize = 0;
    offset = try records.writeRecord(&request_buffer, offset, true, records.record_next_protocol, &.{ 0, 0 });
    offset = try records.writeRecord(&request_buffer, offset, true, records.record_end, &.{});

    var mock = ServerMock{ .request = request_buffer[0..offset] };
    try std.testing.expectError(
        error.NoSharedAead,
        negotiateServer(mock.channel(), .{ .key_ring = &key_ring }),
    );

    const response = try records.parseComplete(mock.response[0..mock.response_len]);
    try std.testing.expectEqual(@as(usize, 1), response.countKind(records.record_error));
    try std.testing.expectEqual(@as(u16, 1), readU16(response.find(records.record_error).?.body, 0));
}
