//! UTC/TAI conversion and leap-second metadata.
//!
//! The table below contains every leap second announced by the IERS since
//! 1972. No leap second has been inserted since 2017-01-01, so 37 seconds is
//! the current TAI-UTC offset. Pre-1972 UTC used fractional offsets that are
//! outside this table; conversions before 1972 use the 1972 value of 10
//! seconds and are explicitly approximate.
//!
//! `timez` does not own a tzdata database. This module only converts between
//! the uniform TAI scale and the UTC scale used by NTP/PTP.

const std = @import("std");
const types = @import("types.zig");
const quality = @import("quality.zig");

pub const Duration = types.Duration;
pub const Timestamp = types.Timestamp;
pub const TaiTimestamp = types.TaiTimestamp;
pub const LeapIndicator = quality.LeapIndicator;

pub const LeapSecond = struct {
    /// Effective UTC time as seconds since the Unix epoch.
    utc_seconds: i64,
    /// TAI - UTC in seconds from this instant onward.
    tai_minus_utc: i32,
};

/// Historical leap-second table. Keep this sorted by `utc_seconds`.
pub const default_table = [_]LeapSecond{
    .{ .utc_seconds = 63_072_000, .tai_minus_utc = 10 }, // 1972-01-01
    .{ .utc_seconds = 78_796_800, .tai_minus_utc = 11 }, // 1972-07-01
    .{ .utc_seconds = 94_694_400, .tai_minus_utc = 12 }, // 1973-01-01
    .{ .utc_seconds = 126_230_400, .tai_minus_utc = 13 }, // 1974-01-01
    .{ .utc_seconds = 157_766_400, .tai_minus_utc = 14 }, // 1975-01-01
    .{ .utc_seconds = 189_302_400, .tai_minus_utc = 15 }, // 1976-01-01
    .{ .utc_seconds = 220_924_800, .tai_minus_utc = 16 }, // 1977-01-01
    .{ .utc_seconds = 252_460_800, .tai_minus_utc = 17 }, // 1978-01-01
    .{ .utc_seconds = 283_996_800, .tai_minus_utc = 18 }, // 1979-01-01
    .{ .utc_seconds = 315_532_800, .tai_minus_utc = 19 }, // 1980-01-01
    .{ .utc_seconds = 362_793_600, .tai_minus_utc = 20 }, // 1981-07-01
    .{ .utc_seconds = 394_329_600, .tai_minus_utc = 21 }, // 1982-07-01
    .{ .utc_seconds = 425_865_600, .tai_minus_utc = 22 }, // 1983-07-01
    .{ .utc_seconds = 489_024_000, .tai_minus_utc = 23 }, // 1985-07-01
    .{ .utc_seconds = 567_993_600, .tai_minus_utc = 24 }, // 1988-01-01
    .{ .utc_seconds = 599_529_600, .tai_minus_utc = 25 }, // 1990-01-01
    .{ .utc_seconds = 631_065_600, .tai_minus_utc = 26 }, // 1991-01-01
    .{ .utc_seconds = 662_688_000, .tai_minus_utc = 27 }, // 1992-07-01
    .{ .utc_seconds = 709_948_800, .tai_minus_utc = 28 }, // 1993-07-01
    .{ .utc_seconds = 741_484_800, .tai_minus_utc = 29 }, // 1994-07-01
    .{ .utc_seconds = 788_918_400, .tai_minus_utc = 30 }, // 1996-01-01
    .{ .utc_seconds = 820_454_400, .tai_minus_utc = 31 }, // 1997-07-01
    .{ .utc_seconds = 851_990_400, .tai_minus_utc = 32 }, // 1999-01-01
    .{ .utc_seconds = 1_072_915_200, .tai_minus_utc = 33 }, // 2006-01-01
    .{ .utc_seconds = 1_230_768_000, .tai_minus_utc = 34 }, // 2009-01-01
    .{ .utc_seconds = 1_342_204_800, .tai_minus_utc = 35 }, // 2012-07-01
    .{ .utc_seconds = 1_436_448_000, .tai_minus_utc = 36 }, // 2015-07-01
    .{ .utc_seconds = 1_483_228_800, .tai_minus_utc = 37 }, // 2017-01-01
};

/// A leap second announced for the near future but not yet in the table.
pub const PendingLeap = struct {
    /// UTC instant at which the new offset takes effect.
    effective: Timestamp,
    /// +1 for a positive leap second, -1 for a negative one.
    delta: i8,
};

/// Leap-second converter with an optional pending leap announcement.
pub const LeapSeconds = struct {
    table: []const LeapSecond = &default_table,
    pending: ?PendingLeap = null,

    pub const ConversionError = error{
        BeforeEpoch,
    };

    /// TAI - UTC at the given UTC instant. Returns 10 s before 1972.
    pub fn taiMinusUtc(self: LeapSeconds, utc: Timestamp) Duration {
        const secs = utc.toSeconds();
        var offset: i32 = if (self.table.len == 0) 10 else self.table[0].tai_minus_utc;
        for (self.table) |entry| {
            if (secs >= entry.utc_seconds) offset = entry.tai_minus_utc else break;
        }
        if (self.pending) |pending| {
            if (utc.ns >= pending.effective.ns) offset += pending.delta;
        }
        return Duration.fromNanoseconds(@as(i96, offset) * types.ns_per_s);
    }

    pub fn utcToTai(self: LeapSeconds, utc: Timestamp) TaiTimestamp {
        return .{ .ns = utc.ns + self.taiMinusUtc(utc).ns };
    }

    /// Convert a TAI timestamp back to UTC.
    ///
    /// The search is performed on the piecewise-constant offset intervals,
    /// which also makes the conversion unambiguous around inserted leap
    /// seconds.
    pub fn taiToUtc(self: LeapSeconds, tai: TaiTimestamp) Timestamp {
        if (self.table.len == 0) return .{ .ns = tai.ns - 10 * types.ns_per_s };

        var chosen: i32 = self.table[0].tai_minus_utc;
        for (self.table, 0..) |entry, i| {
            const start_tai: i96 = @as(i96, entry.utc_seconds) * types.ns_per_s +
                @as(i96, entry.tai_minus_utc) * types.ns_per_s;
            const end_tai: i96 = if (i + 1 < self.table.len)
                @as(i96, self.table[i + 1].utc_seconds) * types.ns_per_s +
                    @as(i96, self.table[i + 1].tai_minus_utc) * types.ns_per_s
            else
                std.math.maxInt(i96);
            if (tai.ns >= start_tai and tai.ns < end_tai) {
                chosen = entry.tai_minus_utc;
                break;
            }
            // For timestamps before the first entry, use the first offset.
            if (tai.ns < start_tai) {
                chosen = entry.tai_minus_utc;
                break;
            }
        }

        if (self.pending) |pending| {
            const effective_tai = pending.effective.ns + self.taiMinusUtc(pending.effective).ns;
            if (tai.ns >= effective_tai) chosen += pending.delta;
        }

        return .{ .ns = tai.ns - @as(i96, chosen) * types.ns_per_s };
    }

    /// NTP leap indicator for the current UTC instant.
    ///
    /// A warning is raised during the 24 hours preceding an announced leap.
    pub fn leapIndicator(self: LeapSeconds, utc: Timestamp) LeapIndicator {
        if (self.pending) |pending| {
            const window_start = pending.effective.sub(Duration.fromHours(24));
            if (utc.ns >= window_start.ns and utc.ns < pending.effective.ns) {
                return if (pending.delta > 0) .last_minute_61 else .last_minute_59;
            }
        }

        // Historical table entries do not announce future leaps, but a
        // caller may append a future entry to `table`. Detect one within 24h.
        const window = 24 * types.ns_per_hour;
        for (self.table, 0..) |entry, i| {
            const start = @as(i96, entry.utc_seconds) * types.ns_per_s;
            if (utc.ns >= start - window and utc.ns < start) {
                const previous: i32 = if (i > 0) self.table[i - 1].tai_minus_utc else entry.tai_minus_utc;
                return if (entry.tai_minus_utc > previous) .last_minute_61 else .last_minute_59;
            }
        }
        return .no_warning;
    }
};

test "tai minus utc at known epochs" {
    const leap = LeapSeconds{};
    try std.testing.expectEqual(@as(i96, 10), leap.taiMinusUtc(Timestamp.fromSeconds(63_072_000)).toSeconds());
    try std.testing.expectEqual(@as(i96, 37), leap.taiMinusUtc(Timestamp.fromSeconds(1_700_000_000)).toSeconds());
    try std.testing.expectEqual(@as(i96, 37), leap.taiMinusUtc(Timestamp.fromSeconds(1_483_228_800)).toSeconds());
    try std.testing.expectEqual(@as(i96, 36), leap.taiMinusUtc(Timestamp.fromSeconds(1_483_228_799)).toSeconds());
}

test "utc tai round-trip" {
    const leap = LeapSeconds{};
    const instants = [_]Timestamp{
        Timestamp.fromSeconds(0),
        Timestamp.fromSeconds(63_072_000),
        Timestamp.fromSeconds(1_483_228_799),
        Timestamp.fromSeconds(1_483_228_800),
        Timestamp.fromSeconds(1_700_000_000),
    };
    for (instants) |utc| {
        const tai = leap.utcToTai(utc);
        const back = leap.taiToUtc(tai);
        try std.testing.expectEqual(utc.ns, back.ns);
    }
}

test "pending leap is applied and announced" {
    const effective = Timestamp.fromSeconds(1_700_000_000);
    const leap = LeapSeconds{ .pending = .{ .effective = effective, .delta = 1 } };
    try std.testing.expectEqual(@as(i96, 37), leap.taiMinusUtc(effective.sub(Duration.fromSeconds(1))).toSeconds());
    try std.testing.expectEqual(@as(i96, 38), leap.taiMinusUtc(effective).toSeconds());
    try std.testing.expectEqual(LeapIndicator.last_minute_61, leap.leapIndicator(effective.sub(Duration.fromHours(2))));
    try std.testing.expectEqual(LeapIndicator.no_warning, leap.leapIndicator(effective.sub(Duration.fromHours(48))));
}

test "negative pending leap" {
    const effective = Timestamp.fromSeconds(1_700_000_000);
    const leap = LeapSeconds{ .pending = .{ .effective = effective, .delta = -1 } };
    try std.testing.expectEqual(@as(i96, 36), leap.taiMinusUtc(effective).toSeconds());
    try std.testing.expectEqual(LeapIndicator.last_minute_59, leap.leapIndicator(effective.sub(Duration.fromHours(1))));
}
