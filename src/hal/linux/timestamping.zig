//! Linux `SO_TIMESTAMPING` socket configuration and ancillary-data parsing.
//!
//! The kernel can deliver receive/transmit timestamps through `SCM_TIMESTAMPING`
//! control messages. This module exposes the flag set, enables timestamping on
//! a socket, and parses the three `timespec` values (software, legacy
//! hardware/sys, raw PHC).

const std = @import("std");
const clock = @import("../../clock/mod.zig");

pub const SO_TIMESTAMPING: u32 = 37;
pub const SOL_SOCKET: i32 = 1;

pub const SOF_TIMESTAMPING_TX_HARDWARE: u32 = 1 << 0;
pub const SOF_TIMESTAMPING_TX_SOFTWARE: u32 = 1 << 1;
pub const SOF_TIMESTAMPING_RX_HARDWARE: u32 = 1 << 2;
pub const SOF_TIMESTAMPING_RX_SOFTWARE: u32 = 1 << 3;
pub const SOF_TIMESTAMPING_SOFTWARE: u32 = 1 << 4;
pub const SOF_TIMESTAMPING_SYS_HARDWARE: u32 = 1 << 5;
pub const SOF_TIMESTAMPING_RAW_HARDWARE: u32 = 1 << 6;
pub const SOF_TIMESTAMPING_OPT_ID: u32 = 1 << 7;
pub const SOF_TIMESTAMPING_TX_SCHED: u32 = 1 << 8;
pub const SOF_TIMESTAMPING_TX_ACK: u32 = 1 << 9;
pub const SOF_TIMESTAMPING_OPT_CMSG: u32 = 1 << 10;
pub const SOF_TIMESTAMPING_OPT_TSONLY: u32 = 1 << 11;
pub const SOF_TIMESTAMPING_OPT_STATS: u32 = 1 << 12;
pub const SOF_TIMESTAMPING_OPT_PKTINFO: u32 = 1 << 13;
pub const SOF_TIMESTAMPING_OPT_TX_SWHW: u32 = 1 << 14;
pub const SOF_TIMESTAMPING_BIND_PHC: u32 = 1 << 15;
pub const SOF_TIMESTAMPING_OPT_ID_TCP: u32 = 1 << 16;
pub const SOF_TIMESTAMPING_OPT_RX_FILTER: u32 = 1 << 17;

/// Typed view of the `SOF_TIMESTAMPING_*` bit set.
pub const Flags = packed struct(u32) {
    tx_hardware: bool = false,
    tx_software: bool = false,
    rx_hardware: bool = false,
    rx_software: bool = false,
    software: bool = false,
    sys_hardware: bool = false,
    raw_hardware: bool = false,
    opt_id: bool = false,
    tx_sched: bool = false,
    tx_ack: bool = false,
    opt_cmsg: bool = false,
    opt_tsonly: bool = false,
    opt_stats: bool = false,
    opt_pktinfo: bool = false,
    opt_tx_swhw: bool = false,
    bind_phc: bool = false,
    opt_id_tcp: bool = false,
    opt_rx_filter: bool = false,
    _: u14 = 0,

    pub fn bits(self: Flags) u32 {
        return @bitCast(self);
    }

    /// Common receive path: request software and hardware receive timestamps
    /// and ask the kernel to report both.
    pub const receive_all: Flags = .{
        .rx_software = true,
        .rx_hardware = true,
        .software = true,
        .raw_hardware = true,
    };
};

pub const Error = error{
    AccessDenied,
    SocketUnsupported,
    InvalidArgument,
    Unexpected,
};

/// Enable (or disable) timestamping on `fd`.
pub fn enable(fd: std.posix.socket_t, flags: Flags) Error!void {
    var bits = flags.bits();
    std.posix.setsockopt(
        fd,
        SOL_SOCKET,
        SO_TIMESTAMPING,
        std.mem.asBytes(&bits),
    ) catch |err| return mapSockoptError(err);
}

fn mapSockoptError(err: anyerror) Error {
    return switch (err) {
        error.PermissionDenied => error.AccessDenied,
        error.OperationUnsupported => error.SocketUnsupported,
        error.InvalidProtocolOption => error.InvalidArgument,
        else => error.Unexpected,
    };
}

pub const Timespec = struct {
    sec: i64,
    nsec: i64,

    pub fn isZero(self: Timespec) bool {
        return self.sec == 0 and self.nsec == 0;
    }

    pub fn toTimestamp(self: Timespec) clock.Timestamp {
        return .{ .ns = @as(i96, self.sec) * std.time.ns_per_s + @as(i96, self.nsec) };
    }
};

pub const TimestampingResult = struct {
    /// Software timestamp in the system clock domain.
    software: ?Timespec = null,
    /// Legacy `SOF_TIMESTAMPING_SYS_HARDWARE` timestamp.
    sys_hardware: ?Timespec = null,
    /// Raw hardware timestamp in the PHC clock domain.
    raw_hardware: ?Timespec = null,

    pub fn softwareTimestamp(self: TimestampingResult) ?clock.Timestamp {
        return if (self.software) |value| value.toTimestamp() else null;
    }
};

pub const ParseError = error{
    MalformedControl,
    TooShort,
};

const cmsghdr = std.os.linux.cmsghdr;
const cmsg_align: usize = @sizeOf(usize);

fn alignCmsg(length: usize) usize {
    return (length + cmsg_align - 1) & ~(cmsg_align - 1);
}

/// Parse the control buffer returned by `recvmsg` for `SCM_TIMESTAMPING`.
/// Unknown control messages are ignored.
pub fn parseControl(control: []const u8) ParseError!TimestampingResult {
    var result = TimestampingResult{};
    var offset: usize = 0;

    while (offset < control.len) {
        if (control.len - offset < @sizeOf(cmsghdr)) break;
        const header: *align(1) const cmsghdr = @ptrCast(control[offset..].ptr);
        if (header.len < @sizeOf(cmsghdr) or header.len > control.len - offset) {
            return error.MalformedControl;
        }

        const data_offset = offset + @sizeOf(cmsghdr);
        const data_len = header.len - @sizeOf(cmsghdr);
        const data = control[data_offset .. data_offset + data_len];

        if (header.level == SOL_SOCKET and header.type == SO_TIMESTAMPING) {
            if (data.len < 3 * @sizeOf(TimespecRaw)) return error.TooShort;
            const values: [*]align(1) const TimespecRaw = @ptrCast(data.ptr);
            if (!values[0].isZero()) result.software = values[0].toTimespec();
            if (!values[1].isZero()) result.sys_hardware = values[1].toTimespec();
            if (!values[2].isZero()) result.raw_hardware = values[2].toTimespec();
        }

        offset += alignCmsg(header.len);
    }

    return result;
}

const TimespecRaw = extern struct {
    sec: isize,
    nsec: isize,

    fn isZero(self: TimespecRaw) bool {
        return self.sec == 0 and self.nsec == 0;
    }

    fn toTimespec(self: TimespecRaw) Timespec {
        return .{ .sec = self.sec, .nsec = self.nsec };
    }
};

test "parse software and hardware timestamp control data" {
    const Header = struct {
        len: usize,
        level: i32,
        type: i32,
    };
    var buffer: [@sizeOf(Header) + 3 * @sizeOf(TimespecRaw) + 8]u8 = @splat(0);
    const header: *align(1) Header = @ptrCast(&buffer);
    header.len = @sizeOf(Header) + 3 * @sizeOf(TimespecRaw);
    header.level = SOL_SOCKET;
    header.type = SO_TIMESTAMPING;

    const values: [*]align(1) TimespecRaw = @ptrCast(buffer[@sizeOf(Header)..].ptr);
    values[0] = .{ .sec = 1_700_000_000, .nsec = 123 };
    values[1] = .{ .sec = 0, .nsec = 0 };
    values[2] = .{ .sec = 42, .nsec = 7 };

    const result = try parseControl(buffer[0..header.len]);
    try std.testing.expectEqual(@as(i64, 1_700_000_000), result.software.?.sec);
    try std.testing.expectEqual(@as(i64, 123), result.software.?.nsec);
    try std.testing.expect(result.sys_hardware == null);
    try std.testing.expectEqual(@as(i64, 42), result.raw_hardware.?.sec);
}

test "malformed control data is rejected" {
    var buffer: [32]u8 = @splat(0);
    const header: *align(1) cmsghdr = @ptrCast(&buffer);
    header.len = 1000;
    header.level = SOL_SOCKET;
    header.type = SO_TIMESTAMPING;
    try std.testing.expectError(error.MalformedControl, parseControl(&buffer));
}

test "flag bits match kernel constants" {
    try std.testing.expectEqual(SOF_TIMESTAMPING_RX_SOFTWARE, (Flags{ .rx_software = true }).bits());
    try std.testing.expectEqual(
        SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE,
        Flags.receive_all.bits() & (SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE),
    );
}
