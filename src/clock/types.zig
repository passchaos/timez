//! Fundamental time value types shared by every `timez` module.
//!
//! `Timestamp` is a POSIX/Unix UTC timestamp: nanoseconds since
//! 1970-01-01T00:00:00Z, *ignoring* leap seconds. `TaiTimestamp` is
//! nanoseconds since the TAI epoch, and `Duration` is a signed elapsed-time
//! interval. All three use `i96` so they can represent the full range of
//! `std.Io.Timestamp` without overflow.
//!
//! Leap-second conversion lives in `leap.zig` because it needs the leap table.

const std = @import("std");

pub const ns_per_us: i96 = 1000;
pub const ns_per_ms: i96 = 1000 * ns_per_us;
pub const ns_per_s: i96 = 1000 * ns_per_ms;
pub const ns_per_min: i96 = 60 * ns_per_s;
pub const ns_per_hour: i96 = 60 * ns_per_min;
pub const ns_per_day: i96 = 24 * ns_per_hour;

/// A signed interval of time, in nanoseconds.
pub const Duration = struct {
    ns: i96,

    pub const zero: Duration = .{ .ns = 0 };
    pub const max: Duration = .{ .ns = std.math.maxInt(i96) };
    pub const min: Duration = .{ .ns = std.math.minInt(i96) };

    pub fn fromNanoseconds(ns: anytype) Duration {
        return .{ .ns = @intCast(ns) };
    }

    pub fn fromMicroseconds(us: anytype) Duration {
        return .{ .ns = @as(i96, @intCast(us)) * ns_per_us };
    }

    pub fn fromMilliseconds(ms: anytype) Duration {
        return .{ .ns = @as(i96, @intCast(ms)) * ns_per_ms };
    }

    pub fn fromSeconds(s: anytype) Duration {
        return switch (@typeInfo(@TypeOf(s))) {
            .comptime_float, .float => fromFloatSeconds(@as(f64, s)),
            .comptime_int, .int => .{ .ns = @as(i96, @intCast(s)) * ns_per_s },
            else => @compileError("Duration.fromSeconds expects an integer or float"),
        };
    }

    pub fn fromMinutes(m: anytype) Duration {
        return .{ .ns = @as(i96, @intCast(m)) * ns_per_min };
    }

    pub fn fromHours(h: anytype) Duration {
        return .{ .ns = @as(i96, @intCast(h)) * ns_per_hour };
    }

    pub fn fromDays(d: anytype) Duration {
        return .{ .ns = @as(i96, @intCast(d)) * ns_per_day };
    }

    /// Build a duration from a possibly fractional number of seconds.
    /// Rejects NaN, infinities, and values outside the `i96` range.
    pub fn fromFloatSeconds(s: f64) Duration {
        if (!std.math.isFinite(s)) return .{ .ns = if (s < 0) std.math.minInt(i96) else std.math.maxInt(i96) };
        const ns = s * @as(f64, @floatFromInt(ns_per_s));
        if (ns >= @as(f64, @floatFromInt(std.math.maxInt(i96)))) return .{ .ns = std.math.maxInt(i96) };
        if (ns <= @as(f64, @floatFromInt(std.math.minInt(i96)))) return .{ .ns = std.math.minInt(i96) };
        return .{ .ns = @intFromFloat(ns) };
    }

    pub fn toNanoseconds(self: Duration) i96 {
        return self.ns;
    }

    pub fn toMicroseconds(self: Duration) i96 {
        return @divTrunc(self.ns, ns_per_us);
    }

    pub fn toMilliseconds(self: Duration) i96 {
        return @divTrunc(self.ns, ns_per_ms);
    }

    pub fn toSeconds(self: Duration) i96 {
        return @divTrunc(self.ns, ns_per_s);
    }

    pub fn toFloatSeconds(self: Duration) f64 {
        return @as(f64, @floatFromInt(self.ns)) / @as(f64, @floatFromInt(ns_per_s));
    }

    pub fn add(self: Duration, other: Duration) Duration {
        return .{ .ns = self.ns + other.ns };
    }

    pub fn sub(self: Duration, other: Duration) Duration {
        return .{ .ns = self.ns - other.ns };
    }

    pub fn mul(self: Duration, factor: f64) Duration {
        const ns = @as(f64, @floatFromInt(self.ns)) * factor;
        if (ns >= @as(f64, @floatFromInt(std.math.maxInt(i96)))) return max;
        if (ns <= @as(f64, @floatFromInt(std.math.minInt(i96)))) return min;
        return .{ .ns = @intFromFloat(ns) };
    }

    pub fn negate(self: Duration) Duration {
        return .{ .ns = -self.ns };
    }

    pub fn abs(self: Duration) Duration {
        return .{ .ns = if (self.ns < 0) -self.ns else self.ns };
    }

    pub fn eql(self: Duration, other: Duration) bool {
        return self.ns == other.ns;
    }

    pub fn order(self: Duration, other: Duration) std.math.Order {
        return std.math.order(self.ns, other.ns);
    }

    pub fn format(self: Duration, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const sign: u8 = if (self.ns < 0) '-' else 0;
        const magnitude: u96 = @intCast(if (self.ns < 0) -self.ns else self.ns);
        if (sign == '-') try w.writeByte('-');
        try formatUnsignedNs(w, magnitude);
    }
};

fn formatUnsignedNs(w: *std.Io.Writer, magnitude: u96) std.Io.Writer.Error!void {
    var remaining = magnitude;
    const units = [_]struct { ns: u96, suffix: []const u8 }{
        .{ .ns = @intCast(ns_per_day), .suffix = "d" },
        .{ .ns = @intCast(ns_per_hour), .suffix = "h" },
        .{ .ns = @intCast(ns_per_min), .suffix = "m" },
        .{ .ns = @intCast(ns_per_s), .suffix = "s" },
        .{ .ns = @intCast(ns_per_ms), .suffix = "ms" },
        .{ .ns = @intCast(ns_per_us), .suffix = "us" },
        .{ .ns = 1, .suffix = "ns" },
    };
    var wrote = false;
    for (units, 0..) |unit, i| {
        if (remaining >= unit.ns) {
            const whole = remaining / unit.ns;
            remaining -= whole * unit.ns;
            if (i >= 3 and remaining != 0 and i + 1 < units.len) {
                try w.printInt(whole, 10, .lower, .{});
                try w.writeByte('.');
                // Print up to three fractional digits of the next smaller unit.
                const next = units[i + 1].ns;
                const frac = (remaining * 1000) / next;
                try w.printInt(frac, 10, .lower, .{ .width = 3, .fill = '0' });
                remaining = 0;
            } else {
                try w.printInt(whole, 10, .lower, .{});
            }
            try w.writeAll(unit.suffix);
            wrote = true;
            if (remaining == 0) break;
        }
    }
    if (!wrote) try w.writeAll("0ns");
}

/// A POSIX/Unix UTC timestamp: nanoseconds since 1970-01-01T00:00:00Z.
/// Leap seconds are not represented; use `leap.zig` for TAI conversion.
pub const Timestamp = struct {
    ns: i96,

    pub const zero: Timestamp = .{ .ns = 0 };

    pub fn fromNanoseconds(ns: anytype) Timestamp {
        return .{ .ns = @intCast(ns) };
    }

    pub fn fromMicroseconds(us: anytype) Timestamp {
        return .{ .ns = @as(i96, @intCast(us)) * ns_per_us };
    }

    pub fn fromMilliseconds(ms: anytype) Timestamp {
        return .{ .ns = @as(i96, @intCast(ms)) * ns_per_ms };
    }

    pub fn fromSeconds(s: anytype) Timestamp {
        return .{ .ns = @as(i96, @intCast(s)) * ns_per_s };
    }

    pub fn fromFloatSeconds(s: f64) Timestamp {
        if (!std.math.isFinite(s)) return .{ .ns = if (s < 0) std.math.minInt(i96) else std.math.maxInt(i96) };
        return .{ .ns = @intFromFloat(s * @as(f64, @floatFromInt(ns_per_s))) };
    }

    pub const Parts = struct {
        seconds: i64,
        nanoseconds: u32,
    };

    /// Split into whole seconds and a non-negative nanosecond remainder.
    /// Uses floor division so pre-epoch timestamps have positive nanoseconds.
    pub fn toParts(self: Timestamp) Parts {
        const seconds = @divFloor(self.ns, ns_per_s);
        const remainder = self.ns - seconds * ns_per_s;
        return .{
            .seconds = @intCast(seconds),
            .nanoseconds = @intCast(remainder),
        };
    }

    pub fn fromParts(seconds: i64, nanoseconds: u32) error{InvalidNanoseconds}!Timestamp {
        if (nanoseconds >= ns_per_s) return error.InvalidNanoseconds;
        return .{ .ns = @as(i96, seconds) * ns_per_s + @as(i96, nanoseconds) };
    }

    pub fn add(self: Timestamp, duration: Duration) Timestamp {
        return .{ .ns = self.ns + duration.ns };
    }

    pub fn sub(self: Timestamp, duration: Duration) Timestamp {
        return .{ .ns = self.ns - duration.ns };
    }

    pub fn difference(self: Timestamp, earlier: Timestamp) Duration {
        return .{ .ns = self.ns - earlier.ns };
    }

    pub fn toSeconds(self: Timestamp) i96 {
        return @divFloor(self.ns, ns_per_s);
    }

    pub fn toFloatSeconds(self: Timestamp) f64 {
        return @as(f64, @floatFromInt(self.ns)) / @as(f64, @floatFromInt(ns_per_s));
    }

    pub fn eql(self: Timestamp, other: Timestamp) bool {
        return self.ns == other.ns;
    }

    pub fn order(self: Timestamp, other: Timestamp) std.math.Order {
        return std.math.order(self.ns, other.ns);
    }

    pub fn format(self: Timestamp, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const parts = self.toParts();
        try w.print("{d}.{d:0>9}", .{ parts.seconds, parts.nanoseconds });
    }
};

/// Nanoseconds since the TAI epoch (1970-01-01T00:00:00 TAI).
pub const TaiTimestamp = struct {
    ns: i96,

    pub const zero: TaiTimestamp = .{ .ns = 0 };

    pub fn fromNanoseconds(ns: anytype) TaiTimestamp {
        return .{ .ns = @intCast(ns) };
    }

    pub fn add(self: TaiTimestamp, duration: Duration) TaiTimestamp {
        return .{ .ns = self.ns + duration.ns };
    }

    pub fn sub(self: TaiTimestamp, duration: Duration) TaiTimestamp {
        return .{ .ns = self.ns - duration.ns };
    }

    pub fn difference(self: TaiTimestamp, earlier: TaiTimestamp) Duration {
        return .{ .ns = self.ns - earlier.ns };
    }

    pub fn eql(self: TaiTimestamp, other: TaiTimestamp) bool {
        return self.ns == other.ns;
    }

    pub fn format(self: TaiTimestamp, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("TAI {d}", .{self.ns});
    }
};

/// The four NTP clock offset samples (RFC 5905 section 8).
pub const OffsetSample = struct {
    /// Client transmit time (T1).
    t1: Timestamp,
    /// Server receive time (T2).
    t2: Timestamp,
    /// Server transmit time (T3).
    t3: Timestamp,
    /// Client receive time (T4).
    t4: Timestamp,

    /// The clock offset of the server relative to the client.
    pub fn offset(self: OffsetSample) Duration {
        return .{ .ns = @divTrunc((self.t2.ns - self.t1.ns) + (self.t3.ns - self.t4.ns), 2) };
    }

    /// The round-trip delay between client and server.
    pub fn delay(self: OffsetSample) Duration {
        return .{ .ns = (self.t4.ns - self.t1.ns) - (self.t3.ns - self.t2.ns) };
    }
};

test "duration arithmetic and formatting" {
    const d = Duration.fromSeconds(90);
    try std.testing.expectEqual(@as(i96, 90 * ns_per_s), d.toNanoseconds());
    try std.testing.expectEqual(Duration.fromSeconds(30), d.sub(Duration.fromSeconds(60)));
    try std.testing.expectEqual(@as(i96, -1), Duration.fromSeconds(-1).toSeconds());
    try std.testing.expectEqual(@as(i96, 1), Duration.fromSeconds(-1).abs().toSeconds());

    var buf: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try Duration.fromSeconds(3661).format(&w);
    try std.testing.expectEqualStrings("1h1m1s", w.buffered());
}

test "timestamp parts round-trip around the epoch" {
    const cases = [_]Timestamp{
        Timestamp.fromSeconds(0),
        Timestamp.fromSeconds(-1),
        Timestamp.fromNanoseconds(-1),
        Timestamp.fromNanoseconds(1_500_000_000),
    };
    for (cases) |ts| {
        const parts = ts.toParts();
        const round = try Timestamp.fromParts(parts.seconds, parts.nanoseconds);
        try std.testing.expectEqual(ts, round);
    }
    const pre = Timestamp.fromNanoseconds(-1);
    try std.testing.expectEqual(@as(i64, -1), pre.toParts().seconds);
    try std.testing.expectEqual(@as(u32, 999_999_999), pre.toParts().nanoseconds);
}

test "offset sample formulas" {
    // T1=1000, T2=1010, T3=1012, T4=1020 -> offset 1, delay 18.
    const sample: OffsetSample = .{
        .t1 = Timestamp.fromNanoseconds(1000),
        .t2 = Timestamp.fromNanoseconds(1010),
        .t3 = Timestamp.fromNanoseconds(1012),
        .t4 = Timestamp.fromNanoseconds(1020),
    };
    try std.testing.expectEqual(Duration.fromNanoseconds(1), sample.offset());
    try std.testing.expectEqual(Duration.fromNanoseconds(18), sample.delay());
}
