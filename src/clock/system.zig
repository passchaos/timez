//! `SystemClock` reads the host's realtime and monotonic clocks through
//! `std.Io` and exposes them as a `TimeSource`.
//!
//! The operating system already maintains UTC; this source does not discipline
//! it. An NTP/PTP client can consume `SystemClock` readings and publish its
//! correction metadata through `setReference`/`setCorrection` so downstream
//! consumers see one coherent clock.

const std = @import("std");
const types = @import("types.zig");
const source = @import("source.zig");
const quality_mod = @import("quality.zig");
const leap_mod = @import("leap.zig");

pub const Duration = types.Duration;
pub const Timestamp = types.Timestamp;
pub const TaiTimestamp = types.TaiTimestamp;
pub const Snapshot = source.Snapshot;
pub const Discontinuity = source.Discontinuity;
pub const TimeSource = source.TimeSource;
pub const Monotonic = source.Monotonic;
pub const Quality = quality_mod.Quality;
pub const LeapSeconds = leap_mod.LeapSeconds;

pub const SystemClock = struct {
    io: std.Io,
    leap: LeapSeconds = .{},
    jump_detector: source.JumpDetector = .{},
    quality: Quality = .{},
    synchronized: bool = false,
    offset: Duration = .zero,
    frequency: f64 = 0.0,
    uncertainty: Duration = .zero,
    /// The most recent discontinuity observed by this source, if any.
    last_discontinuity: ?Discontinuity = null,

    pub fn init(io: std.Io) SystemClock {
        return .{ .io = io };
    }

    /// Read a coherent snapshot of the host clocks.
    ///
    /// Not thread-safe: callers must serialize access to the same instance.
    pub fn nowSnapshot(self: *SystemClock) source.Error!Snapshot {
        const mono_ts = std.Io.Clock.awake.now(self.io);
        const utc_ts = std.Io.Clock.real.now(self.io);

        const monotonic = Duration.fromNanoseconds(mono_ts.nanoseconds);
        const utc = Timestamp.fromNanoseconds(utc_ts.nanoseconds);

        const discontinuity = self.jump_detector.update(monotonic, utc);
        self.last_discontinuity = discontinuity;

        var quality = self.quality;
        if (!self.synchronized) {
            quality.leap = .unknown;
            quality.stratum = 0;
        } else {
            quality.leap = self.leap.leapIndicator(utc);
        }

        return .{
            .monotonic = monotonic,
            .utc = utc,
            .tai = self.leap.utcToTai(utc),
            .offset = self.offset,
            .frequency = self.frequency,
            .uncertainty = self.uncertainty,
            .quality = quality,
            .discontinuity = discontinuity,
            .synchronized = self.synchronized,
        };
    }

    pub fn timeSource(self: *SystemClock) TimeSource {
        return TimeSource.from(SystemClock, self);
    }

    pub fn monotonicSource(self: *SystemClock) Monotonic {
        return Monotonic.from(SystemClock, self);
    }

    pub fn monotonicNow(self: *SystemClock) Duration {
        return Duration.fromNanoseconds(std.Io.Clock.awake.now(self.io).nanoseconds);
    }

    pub fn utcNow(self: *SystemClock) Timestamp {
        return Timestamp.fromNanoseconds(std.Io.Clock.real.now(self.io).nanoseconds);
    }

    /// Publish the correction metadata derived from an external reference.
    pub fn setCorrection(
        self: *SystemClock,
        offset: Duration,
        frequency: f64,
        uncertainty: Duration,
        quality: Quality,
    ) void {
        self.offset = offset;
        self.frequency = frequency;
        self.uncertainty = uncertainty;
        self.quality = quality;
        self.synchronized = quality.isSynchronized();
    }

    pub fn setSynchronized(self: *SystemClock, value: bool) void {
        self.synchronized = value;
        if (!value) {
            self.quality.leap = .unknown;
            self.quality.stratum = 0;
        }
    }
};

test "system clock exposes coherent monotonic and utc readings" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var clock = SystemClock.init(io);
    const first = try clock.nowSnapshot();
    const second = try clock.nowSnapshot();

    try std.testing.expect(first.monotonic.ns >= 0);
    try std.testing.expect(second.monotonic.ns >= first.monotonic.ns);
    try std.testing.expect(first.utc.ns > 0);
    try std.testing.expect(first.tai.ns > first.utc.ns);
    // Two back-to-back reads must not look like a step.
    try std.testing.expectEqual(@as(?Discontinuity, null), second.discontinuity);
    try std.testing.expect(!first.synchronized);
}

test "system clock publishes external correction metadata" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var clock = SystemClock.init(io);
    clock.setCorrection(
        Duration.fromMilliseconds(-3),
        1e-6,
        Duration.fromMilliseconds(2),
        .{ .leap = .no_warning, .stratum = 2, .precision = -20 },
    );
    const snapshot = try clock.nowSnapshot();
    try std.testing.expect(snapshot.synchronized);
    try std.testing.expectEqual(@as(i96, 2), @as(i96, snapshot.quality.stratum));
    try std.testing.expectEqual(Duration.fromMilliseconds(-3), snapshot.offset);
}
