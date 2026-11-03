//! Clock quality metadata: leap warning, stratum, precision, and root
//! distance/dispersion. These fields follow the NTPv4 clock-quality model
//! (RFC 5905 section 7.1) but are usable by PTP and application code too.

const std = @import("std");
const types = @import("types.zig");

pub const Duration = types.Duration;
pub const Timestamp = types.Timestamp;

/// NTP leap indicator (two-bit field).
pub const LeapIndicator = enum(u2) {
    /// No leap second is pending.
    no_warning = 0,
    /// The last minute of the current UTC day has 61 seconds.
    last_minute_61 = 1,
    /// The last minute of the current UTC day has 59 seconds.
    last_minute_59 = 2,
    /// The clock is not synchronized or the leap state is unknown.
    unknown = 3,
};

/// NTP clock source / stratum classification.
pub const Stratum = enum(u8) {
    unspecified = 0,
    primary = 1,
    _,

    pub fn fromByte(value: u8) Stratum {
        return @enumFromInt(value);
    }

    pub fn isUnsynchronized(self: Stratum) bool {
        return self == .unspecified;
    }
};

/// A bounded estimate of clock quality.
pub const Quality = struct {
    leap: LeapIndicator = .unknown,
    stratum: u8 = 0,
    /// log2 of the clock precision in seconds (e.g. -20 ~= 1 us).
    precision: i8 = -20,
    /// Total round-trip delay to the reference, as an NTP fixed-point value
    /// converted to a Duration.
    root_delay: Duration = .zero,
    /// Total dispersion to the reference.
    root_dispersion: Duration = .zero,
    /// NTP reference identifier (IPv4 address or four ASCII bytes).
    reference_id: u32 = 0,
    /// Last time the source was updated from its reference.
    reference_time: ?Timestamp = null,

    /// RFC 5905 root distance: root delay / 2 + root dispersion.
    pub fn rootDistance(self: Quality) Duration {
        return .{ .ns = @divTrunc(self.root_delay.ns, 2) + self.root_dispersion.ns };
    }

    /// Precision as a duration (2^precision seconds).
    pub fn precisionDuration(self: Quality) Duration {
        const seconds = std.math.pow(f64, 2.0, @floatFromInt(self.precision));
        return Duration.fromFloatSeconds(seconds);
    }

    pub fn isSynchronized(self: Quality) bool {
        return self.stratum != 0 and self.leap != .unknown;
    }

    pub fn eql(self: Quality, other: Quality) bool {
        return self.leap == other.leap and
            self.stratum == other.stratum and
            self.precision == other.precision and
            self.root_delay.eql(other.root_delay) and
            self.root_dispersion.eql(other.root_dispersion) and
            self.reference_id == other.reference_id;
    }
};

test "root distance combines delay and dispersion" {
    const quality: Quality = .{
        .root_delay = Duration.fromMilliseconds(20),
        .root_dispersion = Duration.fromMilliseconds(5),
    };
    try std.testing.expectEqual(Duration.fromMilliseconds(15), quality.rootDistance());
}

test "precision duration is a power of two" {
    try std.testing.expectEqual(Duration.fromNanoseconds(976_562), (Quality{ .precision = -10 }).precisionDuration());
    try std.testing.expectEqual(Duration.fromSeconds(1), (Quality{ .precision = 0 }).precisionDuration());
}
