//! Linux raw Ethernet access for PTP/IEEE 1588 frames.
//!
//! Opens an `AF_PACKET`/`SOCK_RAW` socket bound to one interface and the PTP
//! EtherType (0x88F7). This is the transport used by 802.1AS and other
//! Layer-2 PTP profiles. Opening it normally requires `CAP_NET_RAW`; the
//! returned errors distinguish missing permissions from unsupported
//! interfaces.

const std = @import("std");
const clock = @import("../../clock/mod.zig");
const timestamping = @import("timestamping.zig");

pub const AF_PACKET: u32 = 17;
pub const ETH_P_1588: u16 = 0x88F7;
pub const SIOCGIFINDEX: u32 = 0x8933;
pub const IFNAMSIZ = 16;

pub const SockAddrLl = extern struct {
    family: u16,
    protocol: u16,
    ifindex: i32,
    hatype: u16,
    pkttype: u8,
    halen: u8,
    addr: [8]u8,
};

pub const Error = error{
    AccessDenied,
    NoSuchInterface,
    Unsupported,
    InvalidArgument,
    MessageOversize,
    SystemResources,
    Timeout,
    Unexpected,
};

pub const Received = struct {
    bytes: []const u8,
    source_mac: [6]u8,
    ifindex: u32,
};

pub const RawEthernet = struct {
    fd: std.posix.fd_t,
    ifindex: u32,

    pub fn open(interface: []const u8) Error!RawEthernet {
        if (interface.len == 0 or interface.len >= IFNAMSIZ) return error.InvalidArgument;

        const rc = std.os.linux.socket(
            AF_PACKET,
            std.posix.SOCK.RAW,
            htons(ETH_P_1588),
        );
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {},
            .PERM, .ACCES => return error.AccessDenied,
            .AFNOSUPPORT, .PROTONOSUPPORT, .OPNOTSUPP => return error.Unsupported,
            .NOMEM, .NOBUFS => return error.SystemResources,
            .INVAL => return error.InvalidArgument,
            else => return error.Unexpected,
        }
        const fd: std.posix.fd_t = @intCast(rc);
        errdefer _ = std.os.linux.close(fd);

        const index = try interfaceIndex(fd, interface);

        var address: SockAddrLl = .{
            .family = AF_PACKET,
            .protocol = htons(ETH_P_1588),
            .ifindex = @intCast(index),
            .hatype = 0,
            .pkttype = 0,
            .halen = 6,
            .addr = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
        };
        const bind_rc = std.os.linux.bind(
            fd,
            @ptrCast(&address),
            @sizeOf(SockAddrLl),
        );
        switch (std.os.linux.errno(bind_rc)) {
            .SUCCESS => {},
            .PERM, .ACCES => return error.AccessDenied,
            .NODEV, .NOENT => return error.NoSuchInterface,
            .INVAL => return error.InvalidArgument,
            else => return error.Unexpected,
        }

        return .{ .fd = fd, .ifindex = index };
    }

    pub fn close(self: *RawEthernet) void {
        _ = std.os.linux.close(self.fd);
        self.fd = -1;
    }

    /// Enable hardware and software timestamping on this socket.
    pub fn enableTimestamping(self: RawEthernet, flags: timestamping.Flags) timestamping.Error!void {
        return timestamping.enable(self.fd, flags);
    }

    pub fn send(self: RawEthernet, frame: []const u8) Error!void {
        if (frame.len == 0) return error.InvalidArgument;
        const rc = std.os.linux.sendto(self.fd, frame.ptr, frame.len, 0, null, 0);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {},
            .PERM, .ACCES => return error.AccessDenied,
            .NODEV, .NOENT => return error.NoSuchInterface,
            .MSGSIZE => return error.MessageOversize,
            .NOMEM, .NOBUFS => return error.SystemResources,
            .AGAIN => return error.Timeout,
            else => return error.Unexpected,
        }
    }

    pub fn receive(self: RawEthernet, buffer: []u8, timeout: clock.Duration) Error!Received {
        var poll_fd = [_]std.os.linux.pollfd{.{
            .fd = self.fd,
            .events = std.os.linux.POLL.IN,
            .revents = 0,
        }};
        const timeout_ms: i32 = if (timeout.ns < 0)
            0
        else
            @intCast(@min(@divTrunc(timeout.ns, std.time.ns_per_ms), std.math.maxInt(i32)));

        const poll_rc = std.os.linux.poll(&poll_fd, 1, timeout_ms);
        switch (std.os.linux.errno(poll_rc)) {
            .SUCCESS => {},
            .INTR => return error.Timeout,
            else => return error.Unexpected,
        }
        if (poll_rc == 0) return error.Timeout;

        var address: SockAddrLl = undefined;
        var address_len: std.os.linux.socklen_t = @sizeOf(SockAddrLl);
        const rc = std.os.linux.recvfrom(
            self.fd,
            buffer.ptr,
            buffer.len,
            0,
            @ptrCast(&address),
            &address_len,
        );
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {},
            .AGAIN => return error.Timeout,
            .INTR => return error.Timeout,
            .MSGSIZE => return error.MessageOversize,
            .NOMEM, .NOBUFS => return error.SystemResources,
            else => return error.Unexpected,
        }

        const length: usize = @intCast(rc);
        if (length > buffer.len) return error.MessageOversize;

        return .{
            .bytes = buffer[0..length],
            .source_mac = address.addr[0..6].*,
            .ifindex = self.ifindex,
        };
    }
};

fn interfaceIndex(fd: std.posix.fd_t, interface: []const u8) Error!u32 {
    const IfReq = extern struct {
        name: [IFNAMSIZ]u8,
        data: [24]u8,
    };
    var request: IfReq = .{
        .name = @splat(0),
        .data = @splat(0),
    };
    @memcpy(request.name[0..interface.len], interface);

    const rc = std.os.linux.ioctl(fd, SIOCGIFINDEX, @intFromPtr(&request));
    switch (std.os.linux.errno(rc)) {
        .SUCCESS => {},
        .NODEV, .NOENT => return error.NoSuchInterface,
        .INVAL => return error.InvalidArgument,
        .PERM, .ACCES => return error.AccessDenied,
        else => return error.Unexpected,
    }

    const index_ptr: *align(1) i32 = @ptrCast(&request.data);
    if (index_ptr.* <= 0) return error.NoSuchInterface;
    return @intCast(index_ptr.*);
}

fn htons(value: u16) u16 {
    return std.mem.nativeToBig(u16, value);
}

test "ethernet framing helpers" {
    try std.testing.expectEqual(@as(u16, 0x88F7), htons(htons(0x88F7)));
    try std.testing.expectEqual(@as(usize, 20), @sizeOf(SockAddrLl));
}

test "raw socket open reports permission or unsupported errors" {
    const result = RawEthernet.open("lo");
    if (result) |socket_value| {
        var socket = socket_value;
        defer socket.close();
        try std.testing.expect(socket.ifindex > 0);
    } else |err| {
        try std.testing.expect(
            err == error.AccessDenied or
                err == error.Unsupported or
                err == error.NoSuchInterface,
        );
    }
}

test "empty interface name is rejected" {
    try std.testing.expectError(error.InvalidArgument, RawEthernet.open(""));
}
