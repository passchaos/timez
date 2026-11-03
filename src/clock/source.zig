//! The common clock interface used by NTP, PTP, diagnostics, and consumers.
//!
//! A `TimeSource` reports one coherent snapshot: the monotonic clock reading,
//! the corresponding UTC and TAI instants, the current correction metadata,
//! and whether a discontinuity was observed since the previous snapshot.

const std = @import("std");
const types = @import("types.zig");
const quality_mod = @import("quality.zig");

pub const Duration = types.Duration;
pub const Timestamp = types.Timestamp;
pub const TaiTimestamp = types.TaiTimestamp;
pub const Quality = quality_mod.Quality;
pub const LeapIndicator = quality_mod.LeapIndicator;

pub const Error = error{
    ClockUnavailable,
    Unexpected,
};

pub const DiscontinuityKind = enum {
    /// The UTC clock was stepped by the reported delta.
    step,
    /// The source changed (for example, switched from holdover to a network
    /// reference).
    source_change,
    /// A leap second was applied.
    leap_second,
    /// The disciplined clock entered holdover.
    holdover_enter,
    /// The disciplined clock left holdover.
    holdover_exit,
};

pub const Discontinuity = struct {
    kind: DiscontinuityKind,
    /// Monotonic reading at which the discontinuity was observed.
    at: Duration,
    /// UTC change caused by the discontinuity.
    delta: Duration,
};

/// A coherent view of a clock at one instant.
pub const Snapshot = struct {
    /// Monotonic elapsed time. Never affected by UTC steps.
    monotonic: Duration,
    /// POSIX UTC instant (ignoring leap seconds).
    utc: Timestamp,
    /// TAI instant corresponding to `utc`.
    tai: TaiTimestamp,
    /// Last measured correction (reference - local) or zero if unknown.
    offset: Duration = .zero,
    /// Estimated fractional frequency error of the local clock. Positive
    /// means the local clock runs fast relative to the reference.
    frequency: f64 = 0.0,
    /// Estimated 1-sigma (or configured confidence) uncertainty of `utc`.
    uncertainty: Duration = .zero,
    quality: Quality = .{},
    discontinuity: ?Discontinuity = null,
    /// True when the clock has a valid reference and is not in holdover.
    synchronized: bool = false,
};

/// Type-erased time source.
pub const TimeSource = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        now: *const fn (ctx: *anyopaque) Error!Snapshot,
    };

    pub fn now(self: TimeSource) Error!Snapshot {
        return self.vtable.now(self.ctx);
    }

    /// Build a `TimeSource` from any type exposing
    /// `fn nowSnapshot(self: *T) source.Error!Snapshot`.
    pub fn from(comptime T: type, ptr: *T) TimeSource {
        const Adapter = struct {
            fn now(ctx: *anyopaque) Error!Snapshot {
                const self: *T = @ptrCast(@alignCast(ctx));
                return self.nowSnapshot();
            }
        };
        return .{
            .ctx = ptr,
            .vtable = &.{ .now = Adapter.now },
        };
    }
};

/// Type-erased monotonic clock reading, for discipline and transport code.
pub const Monotonic = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        now: *const fn (ctx: *anyopaque) Duration,
    };

    pub fn now(self: Monotonic) Duration {
        return self.vtable.now(self.ctx);
    }

    pub fn from(comptime T: type, ptr: *T) Monotonic {
        const Adapter = struct {
            fn now(ctx: *anyopaque) Duration {
                const self: *T = @ptrCast(@alignCast(ctx));
                return self.monotonicNow();
            }
        };
        return .{
            .ctx = ptr,
            .vtable = &.{ .now = Adapter.now },
        };
    }
};

/// Detects UTC steps by comparing the UTC delta against the monotonic delta.
///
/// A tolerance proportional to elapsed time allows normal NTP/PTP slewing
/// (bounded by `max_rate_ppm`) without false positives.
pub const JumpDetector = struct {
    threshold: Duration = Duration.fromMilliseconds(50),
    /// Largest expected rate correction, in parts per million.
    max_rate_ppm: f64 = 1000.0,
    last_monotonic: ?Duration = null,
    last_utc: ?Timestamp = null,

    pub fn reset(self: *JumpDetector) void {
        self.last_monotonic = null;
        self.last_utc = null;
    }

    /// Feed a new coherent pair. Returns a discontinuity when one is found.
    pub fn update(self: *JumpDetector, monotonic: Duration, utc: Timestamp) ?Discontinuity {
        defer {
            self.last_monotonic = monotonic;
            self.last_utc = utc;
        }

        const last_mono = self.last_monotonic orelse return null;
        const last_utc = self.last_utc orelse return null;

        const elapsed = monotonic.sub(last_mono);
        if (elapsed.ns <= 0) {
            // The monotonic clock is not allowed to go backwards. Report a
            // source change rather than inventing a UTC step.
            return .{ .kind = .source_change, .at = monotonic, .delta = .zero };
        }

        const expected = last_utc.add(elapsed);
        const delta = utc.difference(expected);
        const tolerance_ns: i96 = @intFromFloat(
            @as(f64, @floatFromInt(self.threshold.ns)) +
                @as(f64, @floatFromInt(elapsed.ns)) * (self.max_rate_ppm * 1e-6),
        );

        if (delta.ns > tolerance_ns or delta.ns < -tolerance_ns) {
            return .{ .kind = .step, .at = monotonic, .delta = delta };
        }
        return null;
    }
};

/// A simple source useful in tests and for deterministic simulations.
pub const FixedSource = struct {
    snapshot_value: Snapshot,

    pub fn init(snapshot_value: Snapshot) FixedSource {
        return .{ .snapshot_value = snapshot_value };
    }

    pub fn nowSnapshot(self: *FixedSource) Error!Snapshot {
        return self.snapshot_value;
    }

    pub fn timeSource(self: *FixedSource) TimeSource {
        return TimeSource.from(FixedSource, self);
    }

    pub fn monotonicSource(self: *FixedSource) Monotonic {
        return Monotonic.from(FixedSource, self);
    }

    pub fn monotonicNow(self: *FixedSource) Duration {
        return self.snapshot_value.monotonic;
    }
};

test "jump detector distinguishes slew from step" {
    var detector = JumpDetector{};
    try std.testing.expectEqual(@as(?Discontinuity, null), detector.update(Duration.fromSeconds(0), Timestamp.zero));

    // 500 ppm slew over 10 seconds is 5 ms, below the 50 ms threshold.
    const mono1 = Duration.fromSeconds(10);
    const utc1 = Timestamp.fromNanoseconds(10 * types.ns_per_s + 5 * types.ns_per_ms);
    try std.testing.expectEqual(@as(?Discontinuity, null), detector.update(mono1, utc1));

    // A 2 second step is well outside the tolerance.
    const mono2 = Duration.fromSeconds(20);
    const utc2 = Timestamp.fromNanoseconds(30 * types.ns_per_s);
    const jump = detector.update(mono2, utc2).?;
    try std.testing.expectEqual(DiscontinuityKind.step, jump.kind);
    try std.testing.expectEqual(Duration.fromNanoseconds(9_995 * types.ns_per_ms), jump.delta);
}

test "jump detector reports monotonic regression as source change" {
    var detector = JumpDetector{};
    _ = detector.update(Duration.fromSeconds(10), Timestamp.fromSeconds(10));
    const jump = detector.update(Duration.fromSeconds(5), Timestamp.fromSeconds(5)).?;
    try std.testing.expectEqual(DiscontinuityKind.source_change, jump.kind);
}

test "fixed source adapter" {
    var fixed = FixedSource.init(.{
        .monotonic = Duration.fromSeconds(42),
        .utc = Timestamp.fromSeconds(1_700_000_000),
        .tai = TaiTimestamp.fromNanoseconds(1_700_000_037 * types.ns_per_s),
        .synchronized = true,
    });
    const source = fixed.timeSource();
    const snapshot = try source.now();
    try std.testing.expectEqual(@as(i96, 42), snapshot.monotonic.toSeconds());
    try std.testing.expectEqual(@as(i96, 1_700_000_000), snapshot.utc.toSeconds());
}
