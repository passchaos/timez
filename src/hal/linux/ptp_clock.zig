//! Linux `/dev/ptp*` clock access.
//!
//! Implements the `PTP_CLOCK_GETCAPS`, `PTP_SYS_OFFSET`, and
//! `PTP_SYS_OFFSET_PRECISE` ioctls. The sys-offset samples compare the PHC
//! against the system realtime clock; `PTP_SYS_OFFSET_PRECISE` is preferred
//! when the driver supports it because it avoids a user-space timestamp read.

const std = @import("std");
const clock = @import("../../clock/mod.zig");

pub const max_samples = 25;

pub const PtpClockTime = extern struct {
    sec: i64,
    nsec: u32,
    rsv: u32,

    pub fn isZero(self: PtpClockTime) bool {
        return self.sec == 0 and self.nsec == 0;
    }

    pub fn toNanoseconds(self: PtpClockTime) i96 {
        return @as(i96, self.sec) * std.time.ns_per_s + @as(i96, self.nsec);
    }

    pub fn toTimestamp(self: PtpClockTime) clock.Timestamp {
        return .{ .ns = self.toNanoseconds() };
    }
};

pub const PtpClockCaps = extern struct {
    max_adj: c_int,
    n_alarm: c_int,
    n_ext_ts: c_int,
    n_per_out: c_int,
    n_pins: c_int,
    pps: c_int,
    cross_timestamping: c_int,
    adjust_phase: c_int,
    max_phase_adj: c_int,
    rsv: [11]c_int,
};

pub const PtpSysOffset = extern struct {
    n_samples: u32,
    rsv: [3]u32,
    ts: [2 * max_samples + 1]PtpClockTime,
};

pub const PtpSysOffsetPrecise = extern struct {
    device: PtpClockTime,
    sys_realtime: PtpClockTime,
    sys_monoraw: PtpClockTime,
};

pub const PtpSysOffsetExtended = extern struct {
    n_samples: u32,
    rsv: [3]u32,
    ts: [max_samples][3]PtpClockTime,
};

fn ioc(dir: u2, nr: u8, comptime T: type) u32 {
    const size: u32 = @sizeOf(T);
    return (@as(u32, dir) << 30) |
        (@as(u32, 0x3D) << 8) | // '='
        @as(u32, nr) |
        ((size & 0x3FFF) << 16);
}

pub const PTP_CLOCK_GETCAPS: u32 = ioc(2, 1, PtpClockCaps);
pub const PTP_SYS_OFFSET: u32 = ioc(1, 5, PtpSysOffset);
pub const PTP_SYS_OFFSET_PRECISE: u32 = ioc(3, 8, PtpSysOffsetPrecise);
pub const PTP_SYS_OFFSET_EXTENDED: u32 = ioc(3, 9, PtpSysOffsetExtended);

pub const Error = error{
    FileNotFound,
    AccessDenied,
    NoDevice,
    Unsupported,
    InvalidArgument,
    Unexpected,
};

pub const OffsetSample = struct {
    /// PHC time.
    device: PtpClockTime,
    /// System realtime time sampled by the kernel.
    system: PtpClockTime,

    pub fn offset(self: OffsetSample) clock.Duration {
        return .{ .ns = self.device.toNanoseconds() - self.system.toNanoseconds() };
    }
};

pub const OffsetResult = struct {
    count: usize,
    /// Median PHC - system offset.
    offset: clock.Duration,
    /// Half the spread between the minimum and maximum sample.
    uncertainty: clock.Duration,

    /// Build a discipline sample from the system UTC reading captured at the
    /// same time as the PTP clock sample.
    pub fn sample(
        self: OffsetResult,
        system_utc: clock.Timestamp,
        monotonic: clock.Duration,
    ) clock.Sample {
        return .{
            .monotonic = monotonic,
            .reference = system_utc.add(self.offset),
            .uncertainty = self.uncertainty,
        };
    }
};

pub const PtpClock = struct {
    fd: std.posix.fd_t,

    pub fn open(path: []const u8) Error!PtpClock {
        const fd = std.posix.openat(
            std.posix.AT.FDCWD,
            path,
            .{ .ACCMODE = .RDWR, .CLOEXEC = true },
            0,
        ) catch |err| return mapOpenError(err);
        return .{ .fd = fd };
    }

    pub fn close(self: *PtpClock) void {
        _ = std.os.linux.close(self.fd);
        self.fd = -1;
    }

    pub fn caps(self: PtpClock) Error!PtpClockCaps {
        var value: PtpClockCaps = undefined;
        try self.ioctl(PTP_CLOCK_GETCAPS, &value);
        return value;
    }

    /// Sample the PHC against the system clock `n_samples` times.
    pub fn sysOffset(self: PtpClock, requested: usize) Error!OffsetResult {
        const count = std.math.clamp(requested, 1, max_samples);
        var value: PtpSysOffset = undefined;
        value.n_samples = @intCast(count);
        value.rsv = .{ 0, 0, 0 };
        value.ts = undefined;
        try self.ioctl(PTP_SYS_OFFSET, &value);

        const actual: usize = @intCast(value.n_samples);
        if (actual == 0 or actual > max_samples) return error.InvalidArgument;

        var offsets: [max_samples]i96 = undefined;
        var samples: usize = 0;
        var i: usize = 0;
        while (i < actual) : (i += 1) {
            const sample: OffsetSample = .{
                .system = value.ts[2 * i],
                .device = value.ts[2 * i + 1],
            };
            offsets[samples] = sample.offset().ns;
            samples += 1;
        }

        std.mem.sort(i96, offsets[0..samples], {}, std.sort.asc(i96));
        const median = offsets[samples / 2];
        const spread = offsets[samples - 1] - offsets[0];
        return .{
            .count = samples,
            .offset = .{ .ns = median },
            .uncertainty = .{ .ns = @divTrunc(spread, 2) },
        };
    }

    /// Use the precise ioctl when supported.
    pub fn sysOffsetPrecise(self: PtpClock) Error!OffsetResult {
        var value: PtpSysOffsetPrecise = undefined;
        try self.ioctl(PTP_SYS_OFFSET_PRECISE, &value);
        const offset = OffsetSample{ .device = value.device, .system = value.sys_realtime };
        return .{
            .count = 1,
            .offset = offset.offset(),
            .uncertainty = .zero,
        };
    }

    fn ioctl(self: PtpClock, request: u32, value: anytype) Error!void {
        const rc = std.os.linux.ioctl(self.fd, request, @intFromPtr(value));
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {},
            .ACCES, .PERM => return error.AccessDenied,
            .NOENT => return error.FileNotFound,
            .NODEV, .NXIO => return error.NoDevice,
            .INVAL => return error.InvalidArgument,
            .NOTTY, .OPNOTSUPP => return error.Unsupported,
            else => return error.Unexpected,
        }
    }
};

fn mapOpenError(err: anyerror) Error {
    return switch (err) {
        error.FileNotFound => error.FileNotFound,
        error.AccessDenied, error.PermissionDenied => error.AccessDenied,
        error.NoDevice => error.NoDevice,
        error.BadPathName => error.InvalidArgument,
        else => error.Unexpected,
    };
}

test "ptp time conversion" {
    const time: PtpClockTime = .{ .sec = 42, .nsec = 7, .rsv = 0 };
    try std.testing.expectEqual(@as(i96, 42 * std.time.ns_per_s + 7), time.toNanoseconds());
}

test "offset sample and median" {
    const sample: OffsetSample = .{
        .device = .{ .sec = 1_700_000_002, .nsec = 0, .rsv = 0 },
        .system = .{ .sec = 1_700_000_000, .nsec = 0, .rsv = 0 },
    };
    try std.testing.expectEqual(clock.Duration.fromSeconds(2), sample.offset());

    // The ioctl number encodes the write direction and struct size.
    try std.testing.expectEqual(@as(u32, 1), (PTP_SYS_OFFSET >> 30) & 0x3);
    try std.testing.expectEqual(@as(u32, @sizeOf(PtpSysOffset)), (PTP_SYS_OFFSET >> 16) & 0x3FFF);
}

test "opening a missing ptp device reports a typed error" {
    const result = PtpClock.open("/dev/ptp-nonexistent");
    if (result) |clock_device| {
        var device = clock_device;
        device.close();
    } else |err| {
        try std.testing.expect(err == error.FileNotFound or err == error.AccessDenied);
    }
}
