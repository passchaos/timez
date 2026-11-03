//! NTP 64-bit timestamp conversion.
//!
//! An NTP timestamp is a 32-bit seconds counter since 1900-01-01 followed by
//! a 32-bit binary fraction. The seconds counter wraps every 2^32 seconds
//! (~136 years); RFC 5905 calls each wrap an "era". Wire packets do not carry
//! the era, so decoding must pick the era closest to a known pivot.

const std = @import("std");
const clock = @import("../clock/mod.zig");

pub const Timestamp = clock.Timestamp;
pub const Duration = clock.Duration;

/// Seconds from 1900-01-01 (NTP epoch) to 1970-01-01 (Unix epoch).
pub const unix_epoch_offset: i64 = 2_208_988_800;

/// Length of one NTP era in seconds.
pub const era_seconds: i64 = 1 << 32;

pub const NtpTimestamp = struct {
    seconds: u32 = 0,
    fraction: u32 = 0,

    pub const zero: NtpTimestamp = .{};

    pub fn fromRaw(raw: u64) NtpTimestamp {
        return .{
            .seconds = @intCast(raw >> 32),
            .fraction = @truncate(raw),
        };
    }

    pub fn toRaw(self: NtpTimestamp) u64 {
        return (@as(u64, self.seconds) << 32) | self.fraction;
    }

    /// Encode a Unix timestamp into an NTP timestamp. The era is implicit;
    /// the seconds field is the low 32 bits of the NTP seconds count.
    pub fn fromTimestamp(ts: Timestamp) NtpTimestamp {
        const parts = ts.toParts();
        const ntp_seconds = parts.seconds + unix_epoch_offset;
        const low_seconds: u32 = @truncate(@as(u64, @bitCast(ntp_seconds)));
        const fraction: u32 = @intCast(
            @as(u64, parts.nanoseconds) * (@as(u64, 1) << 32) / std.time.ns_per_s,
        );
        return .{ .seconds = low_seconds, .fraction = fraction };
    }

    /// Decode using an explicit era number. Era 0 covers 1900-2036.
    pub fn toTimestamp(self: NtpTimestamp, era: i32) Timestamp {
        const total_ntp_seconds: i96 =
            @as(i96, self.seconds) + @as(i96, era) * era_seconds;
        const unix_seconds = total_ntp_seconds - unix_epoch_offset;
        const fractional_ns: i96 = @divTrunc(
            @as(i96, self.fraction) * std.time.ns_per_s,
            @as(i96, 1) << 32,
        );
        return .{ .ns = unix_seconds * std.time.ns_per_s + fractional_ns };
    }

    /// Decode choosing the era that puts the result within +/- 68 years of
    /// `pivot`. This is the standard RFC 5905 era disambiguation rule.
    pub fn toTimestampNear(self: NtpTimestamp, pivot: Timestamp) Timestamp {
        const pivot_ntp_seconds = pivot.toSeconds() + unix_epoch_offset;
        const candidate = pivot_ntp_seconds - @as(i96, self.seconds);
        const era: i32 = @intCast(@divFloor(candidate + era_seconds / 2, era_seconds));
        return self.toTimestamp(era);
    }

    /// Unix seconds for an explicit era, without the fractional part.
    pub fn unixSeconds(self: NtpTimestamp, era: i32) i64 {
        return @intCast(@as(i96, self.seconds) + @as(i96, era) * era_seconds - unix_epoch_offset);
    }

    pub fn eql(self: NtpTimestamp, other: NtpTimestamp) bool {
        return self.seconds == other.seconds and self.fraction == other.fraction;
    }

    /// Whether the timestamp is the all-zero value used by some servers as
    /// "not set".
    pub fn isZero(self: NtpTimestamp) bool {
        return self.seconds == 0 and self.fraction == 0;
    }
};

/// Convert a signed 16.16 fixed-point NTP value to a duration.
pub fn fixed16_16ToDuration(raw: i32) Duration {
    return .{ .ns = @divTrunc(@as(i96, raw) * std.time.ns_per_s, 65536) };
}

/// Convert an unsigned 16.16 fixed-point NTP value to a duration.
pub fn ufixed16_16ToDuration(raw: u32) Duration {
    return .{ .ns = @divTrunc(@as(i96, raw) * std.time.ns_per_s, 65536) };
}

/// Convert a duration to a signed 16.16 fixed-point NTP value, saturating.
pub fn durationToFixed16_16(duration: Duration) i32 {
    const raw = @divTrunc(duration.ns * 65536, std.time.ns_per_s);
    if (raw > std.math.maxInt(i32)) return std.math.maxInt(i32);
    if (raw < std.math.minInt(i32)) return std.math.minInt(i32);
    return @intCast(raw);
}

/// Convert a duration to an unsigned 16.16 fixed-point NTP value, saturating
/// at zero and `maxInt(u32)`.
pub fn durationToUfixed16_16(duration: Duration) u32 {
    if (duration.ns <= 0) return 0;
    const raw = @divTrunc(duration.ns * 65536, std.time.ns_per_s);
    if (raw > std.math.maxInt(u32)) return std.math.maxInt(u32);
    return @intCast(raw);
}

/// The interval represented by an NTP poll exponent (log2 seconds).
pub fn pollInterval(poll: i8) Duration {
    return Duration.fromFloatSeconds(std.math.pow(f64, 2.0, @floatFromInt(poll)));
}

/// The interval represented by an NTP precision exponent (log2 seconds).
pub fn precisionInterval(precision: i8) Duration {
    return Duration.fromFloatSeconds(std.math.pow(f64, 2.0, @floatFromInt(precision)));
}

test "known NTP epoch values" {
    // 1970-01-01 is 2_208_988_800 NTP seconds.
    const ts = Timestamp.zero;
    const ntp = NtpTimestamp.fromTimestamp(ts);
    try std.testing.expectEqual(@as(u32, @intCast(unix_epoch_offset)), ntp.seconds);
    try std.testing.expectEqual(@as(u32, 0), ntp.fraction);
    const back = ntp.toTimestamp(0);
    try std.testing.expectEqual(@as(i96, 0), back.ns);
}

test "fractional second round-trip" {
    const ts = Timestamp.fromNanoseconds(1_700_000_000 * std.time.ns_per_s + 500_000_000);
    const ntp = NtpTimestamp.fromTimestamp(ts);
    const back = ntp.toTimestampNear(ts);
    // 2^-32 second resolution means sub-nanosecond rounding error.
    try std.testing.expect(@abs(back.ns - ts.ns) <= 1);
}

test "era disambiguation" {
    // NTP era 1 begins at 2036-02-07, Unix 2_085_978_496.
    const pivot = Timestamp.fromSeconds(2_085_978_496);
    const wrapped = NtpTimestamp{ .seconds = 0, .fraction = 0 };
    const decoded = wrapped.toTimestampNear(pivot);
    try std.testing.expectEqual(@as(i96, 2_085_978_496), decoded.toSeconds());

    // A timestamp 70 years in the past should decode backwards, not forwards.
    const old_pivot = Timestamp.fromSeconds(1_700_000_000);
    const old = NtpTimestamp.fromTimestamp(Timestamp.fromSeconds(1_500_000_000));
    const old_decoded = old.toTimestampNear(old_pivot);
    try std.testing.expectEqual(@as(i96, 1_500_000_000), old_decoded.toSeconds());
}

test "fixed point conversions" {
    try std.testing.expectEqual(Duration.fromSeconds(1), fixed16_16ToDuration(65536));
    try std.testing.expectEqual(Duration.fromSeconds(-1), fixed16_16ToDuration(-65536));
    try std.testing.expectEqual(@as(i32, 65536), durationToFixed16_16(Duration.fromSeconds(1)));
    try std.testing.expectEqual(@as(u32, 65536), durationToUfixed16_16(Duration.fromSeconds(1)));
    try std.testing.expectEqual(@as(u32, 0), durationToUfixed16_16(Duration.fromSeconds(-1)));
}

test "poll and precision exponents" {
    try std.testing.expectEqual(Duration.fromSeconds(1), pollInterval(0));
    try std.testing.expectEqual(Duration.fromSeconds(64), pollInterval(6));
    try std.testing.expectEqual(Duration.fromNanoseconds(953), precisionInterval(-20));
}
