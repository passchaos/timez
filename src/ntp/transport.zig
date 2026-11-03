//! Transport abstraction for NTP and NTS.
//!
//! The protocol logic is transport-agnostic so tests can inject deterministic
//! in-memory transports. `UdpTransport` uses `std.Io` (and therefore works
//! with either `std.Io.Threaded` or a zio runtime).

const std = @import("std");
const clock = @import("../clock/mod.zig");

pub const Duration = clock.Duration;

pub const Received = struct {
    bytes: []const u8,
    from: std.Io.net.IpAddress,
    /// Monotonic receive time supplied by the transport when available.
    received_at: ?Duration = null,
};

pub const SendError = std.Io.net.Socket.SendError;
pub const ReceiveError = std.Io.net.Socket.ReceiveTimeoutError;

pub const Transport = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (ctx: *anyopaque, bytes: []const u8) SendError!void,
        receive: *const fn (ctx: *anyopaque, buffer: []u8, timeout: Duration) ReceiveError!Received,
    };

    pub fn send(self: Transport, bytes: []const u8) SendError!void {
        return self.vtable.send(self.ctx, bytes);
    }

    pub fn receive(self: Transport, buffer: []u8, timeout: Duration) ReceiveError!Received {
        return self.vtable.receive(self.ctx, buffer, timeout);
    }

    /// Adapt a type exposing `sendBytes(self, bytes)` and
    /// `receiveBytes(self, buffer, timeout)`.
    pub fn from(comptime T: type, ptr: *T) Transport {
        const Adapter = struct {
            fn send(ctx: *anyopaque, bytes: []const u8) SendError!void {
                const self: *T = @ptrCast(@alignCast(ctx));
                return self.sendBytes(bytes);
            }

            fn receive(ctx: *anyopaque, buffer: []u8, timeout: Duration) ReceiveError!Received {
                const self: *T = @ptrCast(@alignCast(ctx));
                return self.receiveBytes(buffer, timeout);
            }
        };
        return .{
            .ctx = ptr,
            .vtable = &.{ .send = Adapter.send, .receive = Adapter.receive },
        };
    }
};

/// Connected-by-address UDP transport. A single instance talks to one server.
pub const UdpTransport = struct {
    io: std.Io,
    socket: std.Io.net.Socket,
    peer: std.Io.net.IpAddress,

    pub const InitError = std.Io.net.IpAddress.BindError ||
        std.Io.net.Ip4Address.ParseError || std.Io.net.Ip6Address.ParseError;

    pub fn init(io: std.Io, peer: std.Io.net.IpAddress, local: ?std.Io.net.IpAddress) InitError!UdpTransport {
        const bind_address = local orelse switch (peer) {
            .ip4 => try std.Io.net.IpAddress.parseIp4("0.0.0.0", 0),
            .ip6 => try std.Io.net.IpAddress.parseIp6("::", 0),
        };
        const socket = try bind_address.bind(io, .{
            .mode = .dgram,
            .protocol = .udp,
        });
        return .{
            .io = io,
            .socket = socket,
            .peer = peer,
        };
    }

    pub fn deinit(self: *UdpTransport) void {
        self.socket.close(self.io);
    }

    pub fn transport(self: *UdpTransport) Transport {
        return Transport.from(UdpTransport, self);
    }

    pub fn sendBytes(self: *UdpTransport, bytes: []const u8) SendError!void {
        return self.socket.send(self.io, &self.peer, bytes);
    }

    pub fn receiveBytes(self: *UdpTransport, buffer: []u8, timeout: Duration) ReceiveError!Received {
        const io_timeout: std.Io.Timeout = .{
            .duration = .{
                .raw = std.Io.Duration.fromNanoseconds(timeout.ns),
                .clock = .awake,
            },
        };
        const message = try self.socket.receiveTimeout(self.io, buffer, io_timeout);
        return .{
            .bytes = message.data,
            .from = message.from,
        };
    }
};

/// In-memory transport for deterministic protocol tests.
pub const MemoryTransport = struct {
    /// Packet that the next `send` will deliver to the peer.
    request: ?[]const u8 = null,
    /// Packet returned by the next `receive`.
    response: ?[]const u8 = null,
    sent_count: usize = 0,
    receive_count: usize = 0,
    /// If set, `receive` returns this error instead of `response`.
    receive_error: ?ReceiveError = null,
    /// Source address reported for responses.
    from: std.Io.net.IpAddress,

    pub fn init(from: std.Io.net.IpAddress) MemoryTransport {
        return .{ .from = from };
    }

    pub fn transport(self: *MemoryTransport) Transport {
        return Transport.from(MemoryTransport, self);
    }

    pub fn sendBytes(self: *MemoryTransport, bytes: []const u8) SendError!void {
        self.request = bytes;
        self.sent_count += 1;
    }

    pub fn receiveBytes(self: *MemoryTransport, buffer: []u8, timeout: Duration) ReceiveError!Received {
        _ = timeout;
        self.receive_count += 1;
        if (self.receive_error) |err| return err;
        const response = self.response orelse return error.Timeout;
        const len = @min(buffer.len, response.len);
        @memcpy(buffer[0..len], response[0..len]);
        return .{ .bytes = buffer[0..len], .from = self.from };
    }
};

test "memory transport adapter" {
    var transport = MemoryTransport.init(try std.Io.net.IpAddress.parseIp4("127.0.0.1", 123));
    const adapter = transport.transport();
    try adapter.send("hello");
    try std.testing.expectEqualStrings("hello", transport.request.?);
    try std.testing.expectEqual(@as(usize, 1), transport.sent_count);
}
