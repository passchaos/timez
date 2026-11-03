//! Diagnostics: offset/drift/jitter statistics, holdover prediction, and
//! metrics suitable for logs or monitoring exporters.

const std = @import("std");
const clock = @import("../clock/mod.zig");

pub const Duration = clock.Duration;
pub const Timestamp = clock.Timestamp;
pub const Quality = clock.Quality;

pub const window_capacity = 64;

pub const OffsetStats = struct {
    count: usize = 0,
    min: Duration = .zero,
    max: Duration = .zero,
    mean: Duration = .zero,
    rms: Duration = .zero,
    last: Duration = .zero,
    /// RMS of successive offset differences (an estimate of local jitter).
    jitter: Duration = .zero,
    /// Estimated fractional frequency error in parts per million.
    drift_ppm: f64 = 0.0,

    pub fn format(self: OffsetStats, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print(
            "count={d} offset={d}ns min={d}ns max={d}ns mean={d}ns rms={d}ns jitter={d}ns drift={d:.3}ppm",
            .{
                self.count,
                self.last.ns,
                self.min.ns,
                self.max.ns,
                self.mean.ns,
                self.rms.ns,
                self.jitter.ns,
                self.drift_ppm,
            },
        );
    }
};

/// Fixed-window offset/delay/jitter tracker.
pub const Tracker = struct {
    offsets: [window_capacity]i96 = undefined,
    delays: [window_capacity]i96 = undefined,
    monos: [window_capacity]i96 = undefined,
    len: usize = 0,
    next: usize = 0,
    frequency: clock.FrequencyEstimator = .{},

    pub fn reset(self: *Tracker) void {
        self.len = 0;
        self.next = 0;
        self.frequency.reset();
    }

    pub fn record(self: *Tracker, offset: Duration, delay: Duration, monotonic: Duration) void {
        self.offsets[self.next] = offset.ns;
        self.delays[self.next] = delay.ns;
        self.monos[self.next] = monotonic.ns;
        self.next = (self.next + 1) % window_capacity;
        if (self.len < window_capacity) self.len += 1;
        self.frequency.add(monotonic, offset);
    }

    fn at(self: *const Tracker, index: usize) struct { offset: i96, delay: i96, mono: i96 } {
        const start = if (self.len == window_capacity) self.next else 0;
        const slot = (start + index) % window_capacity;
        return .{
            .offset = self.offsets[slot],
            .delay = self.delays[slot],
            .mono = self.monos[slot],
        };
    }

    pub fn stats(self: *const Tracker) OffsetStats {
        if (self.len == 0) return .{};

        var min: i96 = std.math.maxInt(i96);
        var max: i96 = std.math.minInt(i96);
        var sum: f64 = 0;
        var square_sum: f64 = 0;
        var jitter_sum: f64 = 0;
        var last_offset: i96 = 0;
        var have_last = false;
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            const value = self.at(i);
            min = @min(min, value.offset);
            max = @max(max, value.offset);
            sum += @floatFromInt(value.offset);
            square_sum += @as(f64, @floatFromInt(value.offset)) * @as(f64, @floatFromInt(value.offset));
            if (have_last) {
                const difference = @as(f64, @floatFromInt(value.offset - last_offset));
                jitter_sum += difference * difference;
            }
            last_offset = value.offset;
            have_last = true;
        }

        const count: f64 = @floatFromInt(self.len);
        const mean_ns = sum / count;
        const rms_ns = @sqrt(square_sum / count);
        const jitter_ns = if (self.len > 1)
            @sqrt(jitter_sum / @as(f64, @floatFromInt(self.len - 1)))
        else
            0.0;

        const last = self.at(self.len - 1).offset;
        const drift = self.frequency.estimate(1e-2) orelse 0.0;

        return .{
            .count = self.len,
            .min = .{ .ns = min },
            .max = .{ .ns = max },
            .mean = .{ .ns = @intFromFloat(mean_ns) },
            .rms = .{ .ns = @intFromFloat(rms_ns) },
            .last = .{ .ns = last },
            .jitter = .{ .ns = @intFromFloat(jitter_ns) },
            .drift_ppm = drift * 1e6,
        };
    }
};

/// Holdover prediction from the last synchronized anchor.
pub const Holdover = struct {
    anchor_monotonic: Duration,
    anchor_utc: Timestamp,
    frequency: f64 = 0.0,
    /// Assumed worst-case drift while free-running, in ppm.
    drift_bound_ppm: f64 = 50.0,
    base_uncertainty: Duration = Duration.fromMilliseconds(1),

    pub fn init(anchor_monotonic: Duration, anchor_utc: Timestamp) Holdover {
        return .{ .anchor_monotonic = anchor_monotonic, .anchor_utc = anchor_utc };
    }

    pub fn elapsed(self: Holdover, now: Duration) Duration {
        return if (now.ns > self.anchor_monotonic.ns) now.sub(self.anchor_monotonic) else .zero;
    }

    pub fn utcAt(self: Holdover, now: Duration) Timestamp {
        const age = self.elapsed(now);
        return self.anchor_utc.add(age.mul(1.0 + self.frequency));
    }

    pub fn uncertaintyAt(self: Holdover, now: Duration) Duration {
        const age = self.elapsed(now);
        const growth_ns: i96 = @intFromFloat(
            @as(f64, @floatFromInt(age.ns)) * (self.drift_bound_ppm * 1e-6),
        );
        return Duration.fromNanoseconds(self.base_uncertainty.ns + growth_ns);
    }
};

pub const Metrics = struct {
    offset: Duration = .zero,
    delay: Duration = .zero,
    jitter: Duration = .zero,
    uncertainty: Duration = .zero,
    drift_ppm: f64 = 0.0,
    holdover: Duration = .zero,
    synchronized: bool = false,
    quality: Quality = .{},
    steps: u64 = 0,
    slews: u64 = 0,
    sync_requests: u64 = 0,
    sync_responses: u64 = 0,
    sync_failures: u64 = 0,

    pub fn format(self: Metrics, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print(
            "offset={d}ns delay={d}ns jitter={d}ns uncertainty={d}ns drift={d:.3}ppm holdover={d}ms synchronized={} stratum={d} steps={d} slews={d} requests={d} responses={d} failures={d}",
            .{
                self.offset.ns,
                self.delay.ns,
                self.jitter.ns,
                self.uncertainty.ns,
                self.drift_ppm,
                self.holdover.toMilliseconds(),
                self.synchronized,
                self.quality.stratum,
                self.steps,
                self.slews,
                self.sync_requests,
                self.sync_responses,
                self.sync_failures,
            },
        );
    }
};

/// Combines a tracker with protocol counters and the last clock snapshot.
pub const Collector = struct {
    tracker: Tracker = .{},
    metrics: Metrics = .{},

    pub fn recordSuccess(self: *Collector, offset: Duration, delay: Duration, monotonic: Duration) void {
        self.tracker.record(offset, delay, monotonic);
        self.metrics.offset = offset;
        self.metrics.delay = delay;
        self.metrics.sync_responses += 1;
        const stats = self.tracker.stats();
        self.metrics.jitter = stats.jitter;
        self.metrics.drift_ppm = stats.drift_ppm;
    }

    pub fn recordFailure(self: *Collector) void {
        self.metrics.sync_failures += 1;
    }

    pub fn recordRequest(self: *Collector) void {
        self.metrics.sync_requests += 1;
    }

    pub fn recordClock(self: *Collector, clock_snapshot: clock.Snapshot) void {
        self.metrics.offset = clock_snapshot.offset;
        self.metrics.uncertainty = clock_snapshot.uncertainty;
        self.metrics.drift_ppm = clock_snapshot.frequency * 1e6;
        self.metrics.synchronized = clock_snapshot.synchronized;
        self.metrics.quality = clock_snapshot.quality;
    }

    pub fn recordStep(self: *Collector) void {
        self.metrics.steps += 1;
    }

    pub fn recordSlew(self: *Collector) void {
        self.metrics.slews += 1;
    }

    pub fn snapshot(self: *const Collector) Metrics {
        return self.metrics;
    }
};

test "offset statistics and jitter" {
    var tracker = Tracker{};
    const offsets = [_]Duration{
        Duration.fromMilliseconds(10),
        Duration.fromMilliseconds(12),
        Duration.fromMilliseconds(9),
        Duration.fromMilliseconds(11),
    };
    for (offsets, 0..) |offset, i| {
        tracker.record(offset, Duration.fromMilliseconds(5), Duration.fromSeconds(@as(i96, @intCast(i))));
    }
    const stats = tracker.stats();
    try std.testing.expectEqual(@as(usize, 4), stats.count);
    try std.testing.expectEqual(Duration.fromMilliseconds(9), stats.min);
    try std.testing.expectEqual(Duration.fromMilliseconds(12), stats.max);
    try std.testing.expectEqual(Duration.fromMilliseconds(11), stats.last);
    try std.testing.expect(stats.jitter.ns > 0);
}

test "holdover prediction grows uncertainty" {
    const anchor_utc = Timestamp.fromSeconds(1_700_000_000);
    var holdover = Holdover.init(.zero, anchor_utc);
    holdover.frequency = 1e-6;
    holdover.drift_bound_ppm = 100.0;
    holdover.base_uncertainty = .zero;

    const predicted = holdover.utcAt(Duration.fromSeconds(100));
    const expected_ns = anchor_utc.ns + 100 * std.time.ns_per_s + 100_000;
    try std.testing.expect(@abs(predicted.ns - expected_ns) <= 1);

    const uncertainty = holdover.uncertaintyAt(Duration.fromSeconds(100));
    try std.testing.expectEqual(Duration.fromMilliseconds(10), uncertainty);
}

test "collector counters and formatting" {
    var collector = Collector{};
    collector.recordRequest();
    collector.recordSuccess(Duration.fromMilliseconds(3), Duration.fromMilliseconds(5), .zero);
    collector.recordFailure();
    collector.recordStep();

    const metrics = collector.snapshot();
    try std.testing.expectEqual(@as(u64, 1), metrics.sync_requests);
    try std.testing.expectEqual(@as(u64, 1), metrics.sync_responses);
    try std.testing.expectEqual(@as(u64, 1), metrics.sync_failures);
    try std.testing.expectEqual(@as(u64, 1), metrics.steps);
    try std.testing.expectEqual(Duration.fromMilliseconds(3), metrics.offset);

    var buffer: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try metrics.format(&writer);
    try std.testing.expect(writer.buffered().len > 0);
}

test "collector records disciplined clock snapshots" {
    var collector = Collector{};
    const snapshot: clock.Snapshot = .{
        .monotonic = Duration.fromSeconds(1),
        .utc = Timestamp.fromSeconds(1_700_000_000),
        .tai = clock.TaiTimestamp.fromNanoseconds(1_700_000_037 * std.time.ns_per_s),
        .offset = Duration.fromMilliseconds(-2),
        .frequency = 1.5e-6,
        .uncertainty = Duration.fromMilliseconds(4),
        .quality = .{ .leap = .no_warning, .stratum = 1 },
        .synchronized = true,
    };
    collector.recordClock(snapshot);
    const metrics = collector.snapshot();
    try std.testing.expect(metrics.synchronized);
    try std.testing.expectEqual(@as(u8, 1), metrics.quality.stratum);
    try std.testing.expectApproxEqAbs(@as(f64, 1.5), metrics.drift_ppm, 1e-6);
}
