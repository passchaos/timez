//! IEEE 1588-2019 / 802.1AS shared value types.

const std = @import("std");
const clock = @import("../clock/mod.zig");

pub const Duration = clock.Duration;

pub const MessageType = enum(u4) {
    sync = 0x0,
    delay_req = 0x1,
    pdelay_req = 0x2,
    pdelay_resp = 0x3,
    follow_up = 0x8,
    delay_resp = 0x9,
    pdelay_resp_follow_up = 0xa,
    announce = 0xb,
    signaling = 0xc,
    management = 0xd,
    _,

    pub fn isSyncLike(self: MessageType) bool {
        return self == .sync or self == .follow_up;
    }

    /// Deprecated control-field value for this message type (IEEE 1588
    /// Table 26). Receivers ignore it, but emitters should match the table.
    pub fn controlField(self: MessageType) u8 {
        return switch (self) {
            .sync => 0,
            .delay_req => 1,
            .follow_up => 2,
            .delay_resp => 3,
            .management => 4,
            .signaling => 5,
            .announce => 6,
            else => 0,
        };
    }
};

pub const Version = enum(u4) {
    v1 = 1,
    v2 = 2,
    _,
};

pub const Flags = packed struct(u16) {
    alternate_master: bool = false,
    two_step: bool = false,
    unicast: bool = false,
    profile_specific1: bool = false,
    profile_specific2: bool = false,
    _reserved1: bool = false,
    leap61: bool = false,
    leap59: bool = false,
    current_utc_offset_valid: bool = false,
    ptp_timescale: bool = false,
    time_traceable: bool = false,
    frequency_traceable: bool = false,
    synchronization_uncertain: bool = false,
    profile_specific3: bool = false,
    _reserved2: u2 = 0,
};

pub const ClockIdentity = struct {
    bytes: [8]u8 = @splat(0),

    pub fn fromU64(value: u64) ClockIdentity {
        var result: ClockIdentity = .{};
        inline for (0..8) |i| {
            result.bytes[i] = @truncate(value >> @intCast(56 - i * 8));
        }
        return result;
    }

    pub fn toU64(self: ClockIdentity) u64 {
        var value: u64 = 0;
        inline for (0..8) |i| {
            value |= @as(u64, self.bytes[i]) << @intCast(56 - i * 8);
        }
        return value;
    }

    /// Derive an EUI-64 clock identity from a 48-bit MAC as required by
    /// 802.1AS (insert 0xff 0xfe between the OUI and NIC parts).
    pub fn fromMac(mac: [6]u8) ClockIdentity {
        return .{ .bytes = .{
            mac[0], mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5],
        } };
    }

    pub fn eql(a: ClockIdentity, b: ClockIdentity) bool {
        return std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    pub fn order(a: ClockIdentity, b: ClockIdentity) std.math.Order {
        return std.math.order(a.toU64(), b.toU64());
    }

    pub fn format(self: ClockIdentity, w: *std.Io.Writer) std.Io.Writer.Error!void {
        for (self.bytes, 0..) |byte, i| {
            if (i > 0 and i % 2 == 0) try w.writeByte('-');
            try w.print("{x:0>2}", .{byte});
        }
    }
};

pub const PortIdentity = struct {
    clock_identity: ClockIdentity = .{},
    port_number: u16 = 1,

    pub fn eql(a: PortIdentity, b: PortIdentity) bool {
        return ClockIdentity.eql(a.clock_identity, b.clock_identity) and
            a.port_number == b.port_number;
    }

    pub fn format(self: PortIdentity, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try self.clock_identity.format(w);
        try w.print("/{d}", .{self.port_number});
    }
};

/// 48-bit seconds plus 32-bit nanoseconds. PTP uses a 48-bit seconds field.
pub const Timestamp = struct {
    seconds: u48 = 0,
    nanoseconds: u32 = 0,

    pub const zero: Timestamp = .{};

    pub fn fromClock(ts: clock.Timestamp) error{ Negative, OutOfRange }!Timestamp {
        if (ts.ns < 0) return error.Negative;
        const seconds = @divFloor(ts.ns, std.time.ns_per_s);
        if (seconds > std.math.maxInt(u48)) return error.OutOfRange;
        return .{
            .seconds = @intCast(seconds),
            .nanoseconds = @intCast(ts.ns - seconds * std.time.ns_per_s),
        };
    }

    pub fn toClock(self: Timestamp) clock.Timestamp {
        return .{ .ns = @as(i96, self.seconds) * std.time.ns_per_s + @as(i96, self.nanoseconds) };
    }

    pub fn eql(a: Timestamp, b: Timestamp) bool {
        return a.seconds == b.seconds and a.nanoseconds == b.nanoseconds;
    }

    pub fn add(a: Timestamp, duration: Duration) Timestamp {
        const total = a.toClock().add(duration);
        return fromClock(total) catch .zero;
    }

    pub fn difference(a: Timestamp, b: Timestamp) Duration {
        return a.toClock().difference(b.toClock());
    }

    pub fn format(self: Timestamp, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("{d}.{d:0>9}", .{ self.seconds, self.nanoseconds });
    }
};

/// Correction field: signed nanoseconds scaled by 2^-16.
pub const CorrectionField = struct {
    raw: i64 = 0,

    pub fn fromDuration(duration: Duration) CorrectionField {
        // PTP stores nanoseconds scaled by 2^-16, so one nanosecond is 65536.
        const limit: i96 = @divTrunc(std.math.maxInt(i64), 65536);
        if (duration.ns > limit) return .{ .raw = std.math.maxInt(i64) };
        if (duration.ns < -limit) return .{ .raw = std.math.minInt(i64) };
        return .{ .raw = @intCast(duration.ns * 65536) };
    }

    pub fn toDuration(self: CorrectionField) Duration {
        return .{ .ns = @divTrunc(@as(i96, self.raw), 65536) };
    }

    pub fn add(self: CorrectionField, other: CorrectionField) CorrectionField {
        return .{ .raw = self.raw +| other.raw };
    }
};

pub const ClockAccuracy = enum(u8) {
    within_25ns = 0x20,
    within_100ns = 0x21,
    within_250ns = 0x22,
    within_1us = 0x23,
    within_2us = 0x24,
    within_4us = 0x25,
    within_8us = 0x26,
    within_16us = 0x27,
    within_32us = 0x28,
    within_64us = 0x29,
    within_128us = 0x2a,
    within_256us = 0x2b,
    within_512us = 0x2c,
    within_1ms = 0x2d,
    within_2ms = 0x2e,
    within_4ms = 0x2f,
    within_8ms = 0x30,
    within_16ms = 0x31,
    within_32ms = 0x32,
    within_64ms = 0x33,
    within_128ms = 0x34,
    within_256ms = 0x35,
    within_512ms = 0x36,
    within_1s = 0x37,
    within_2s = 0x38,
    within_10s = 0x39,
    within_10s_plus = 0x3a,
    unknown = 0xfe,
    _,
};

pub const ClockQuality = struct {
    clock_class: u8 = 248,
    clock_accuracy: ClockAccuracy = .unknown,
    offset_scaled_log_variance: u16 = 0xffff,

    pub fn order(a: ClockQuality, b: ClockQuality) std.math.Order {
        if (a.clock_class != b.clock_class) return std.math.order(a.clock_class, b.clock_class);
        if (@intFromEnum(a.clock_accuracy) != @intFromEnum(b.clock_accuracy)) {
            return std.math.order(@intFromEnum(a.clock_accuracy), @intFromEnum(b.clock_accuracy));
        }
        return std.math.order(a.offset_scaled_log_variance, b.offset_scaled_log_variance);
    }
};

pub const TimeSource = enum(u8) {
    atomic_clock = 0x10,
    gps = 0x20,
    terrestrial_radio = 0x30,
    ptp = 0x40,
    ntp = 0x50,
    hand_set = 0x60,
    other = 0x90,
    _,
};

pub const UtcOffset = struct {
    /// Current UTC offset in seconds, e.g. 37.
    seconds: i16 = 0,
    valid: bool = false,
};

test "clock identity and MAC derivation" {
    const mac = [6]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const identity = ClockIdentity.fromMac(mac);
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55 },
        &identity.bytes,
    );
    const round = ClockIdentity.fromU64(identity.toU64());
    try std.testing.expect(ClockIdentity.eql(identity, round));
}

test "ptp timestamp conversion" {
    const ts = clock.Timestamp.fromSeconds(1_700_000_000);
    const ptp = try Timestamp.fromClock(ts);
    try std.testing.expectEqual(@as(i96, 1_700_000_000), ptp.toClock().toSeconds());
    try std.testing.expectError(error.Negative, Timestamp.fromClock(clock.Timestamp.fromNanoseconds(-1)));
}

test "correction field scales by 2^-16" {
    const correction = CorrectionField.fromDuration(Duration.fromNanoseconds(1));
    try std.testing.expectEqual(@as(i64, 65536), correction.raw);
    try std.testing.expectEqual(Duration.fromNanoseconds(1), correction.toDuration());
    const negative = CorrectionField{ .raw = -65536 };
    try std.testing.expectEqual(Duration.fromNanoseconds(-1), negative.toDuration());
}

test "clock quality ordering" {
    const better: ClockQuality = .{ .clock_class = 6, .clock_accuracy = .within_100ns, .offset_scaled_log_variance = 0 };
    const worse: ClockQuality = .{ .clock_class = 7, .clock_accuracy = .within_1us, .offset_scaled_log_variance = 0 };
    try std.testing.expectEqual(std.math.Order.lt, ClockQuality.order(better, worse));
}
