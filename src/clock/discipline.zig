//! Clock discipline: offset filtering, frequency estimation, step/slew
//! control, and holdover.
//!
//! `DisciplinedClock` is a local clock model driven by a monotonic source and
//! a stream of reference samples. It deliberately keeps the control loop
//! independent from NTP/PTP wire formats so the same discipline works for both
//! protocols and can be unit-tested deterministically.

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
pub const DiscontinuityKind = source.DiscontinuityKind;
pub const Monotonic = source.Monotonic;
pub const Quality = quality_mod.Quality;
pub const LeapSeconds = leap_mod.LeapSeconds;

pub const filter_capacity = 8;
pub const estimator_capacity = 16;

/// One reference observation: the reference UTC at a local monotonic instant.
pub const Sample = struct {
    monotonic: Duration,
    reference: Timestamp,
    /// Measured round-trip delay to the reference (NTP delay or PTP path
    /// delay), if known.
    delay: Duration = .zero,
    /// Additional dispersion associated with this sample.
    dispersion: Duration = .zero,
    /// Explicit uncertainty bound supplied by the protocol.
    uncertainty: Duration = .zero,
    quality: Quality = .{},
};

pub const FilterSample = struct {
    offset: Duration,
    delay: Duration,
    dispersion: Duration,
    received: Duration,
    quality: Quality,
};

/// RFC 5905-style clock filter: retain the most recent samples and choose the
/// one with the lowest delay, aging its dispersion while it waits.
pub const OffsetFilter = struct {
    samples: [filter_capacity]FilterSample = undefined,
    len: usize = 0,
    next: usize = 0,

    pub fn reset(self: *OffsetFilter) void {
        self.len = 0;
        self.next = 0;
    }

    pub fn add(self: *OffsetFilter, sample: FilterSample) void {
        self.samples[self.next] = sample;
        self.next = (self.next + 1) % filter_capacity;
        if (self.len < filter_capacity) self.len += 1;
    }

    pub fn count(self: *const OffsetFilter) usize {
        return self.len;
    }

    fn at(self: *const OffsetFilter, index: usize) FilterSample {
        // Oldest first.
        const start = if (self.len == filter_capacity) self.next else 0;
        return self.samples[(start + index) % filter_capacity];
    }

    /// Return the sample with the smallest delay plus aged dispersion.
    pub fn best(self: *const OffsetFilter, now: Duration, drift_ppm: f64) ?FilterSample {
        if (self.len == 0) return null;
        var best_sample = self.at(0);
        var best_score = sampleScore(best_sample, now, drift_ppm);
        var i: usize = 1;
        while (i < self.len) : (i += 1) {
            const candidate = self.at(i);
            const score = sampleScore(candidate, now, drift_ppm);
            if (score.ns < best_score.ns) {
                best_sample = candidate;
                best_score = score;
            }
        }
        return best_sample;
    }

    /// RMS of offset deviations from the best sample, in nanoseconds.
    pub fn jitter(self: *const OffsetFilter, now: Duration, drift_ppm: f64) Duration {
        const best_sample = self.best(now, drift_ppm) orelse return .zero;
        if (self.len < 2) return .zero;
        var sum: f64 = 0;
        var sample_count: usize = 0;
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            const candidate = self.at(i);
            const deviation = @as(f64, @floatFromInt(candidate.offset.ns - best_sample.offset.ns));
            sum += deviation * deviation;
            sample_count += 1;
        }
        if (sample_count == 0) return .zero;
        return Duration.fromFloatSeconds(@sqrt(sum / @as(f64, @floatFromInt(sample_count))) / @as(f64, @floatFromInt(types.ns_per_s)));
    }

    /// Median offset across retained samples, robust against a single bad
    /// server response.
    pub fn medianOffset(self: *const OffsetFilter) ?Duration {
        if (self.len == 0) return null;
        var values: [filter_capacity]i96 = undefined;
        var i: usize = 0;
        while (i < self.len) : (i += 1) values[i] = self.at(i).offset.ns;
        std.mem.sort(i96, values[0..self.len], {}, std.sort.asc(i96));
        const mid = self.len / 2;
        if (self.len % 2 == 1) return .{ .ns = values[mid] };
        return .{ .ns = @divTrunc(values[mid - 1] + values[mid], 2) };
    }
};

fn sampleScore(sample: FilterSample, now: Duration, drift_ppm: f64) Duration {
    const age = if (now.ns > sample.received.ns) now.sub(sample.received) else Duration.zero;
    const aged_ns: i96 = @intFromFloat(
        @as(f64, @floatFromInt(age.ns)) * (drift_ppm * 1e-6),
    );
    return .{ .ns = sample.delay.ns + sample.dispersion.ns + aged_ns };
}

/// Least-squares estimate of fractional frequency error from
/// (monotonic, offset) pairs.
pub const FrequencyEstimator = struct {
    mono_ns: [estimator_capacity]f64 = undefined,
    offset_ns: [estimator_capacity]f64 = undefined,
    len: usize = 0,
    next: usize = 0,
    origin_mono: f64 = 0,

    pub fn reset(self: *FrequencyEstimator) void {
        self.len = 0;
        self.next = 0;
        self.origin_mono = 0;
    }

    pub fn add(self: *FrequencyEstimator, monotonic: Duration, offset: Duration) void {
        const mono_f = @as(f64, @floatFromInt(monotonic.ns));
        if (self.len == 0) self.origin_mono = mono_f;
        self.mono_ns[self.next] = mono_f - self.origin_mono;
        self.offset_ns[self.next] = @floatFromInt(offset.ns);
        self.next = (self.next + 1) % estimator_capacity;
        if (self.len < estimator_capacity) self.len += 1;
    }

    fn at(self: *const FrequencyEstimator, index: usize) struct { mono: f64, offset: f64 } {
        const start = if (self.len == estimator_capacity) self.next else 0;
        const slot = (start + index) % estimator_capacity;
        return .{ .mono = self.mono_ns[slot], .offset = self.offset_ns[slot] };
    }

    /// Estimated local clock rate error: positive means the local clock runs
    /// fast relative to the reference. `max_abs` bounds pathological input.
    pub fn estimate(self: *const FrequencyEstimator, max_abs: f64) ?f64 {
        if (self.len < 2) return null;
        var mean_x: f64 = 0;
        var mean_y: f64 = 0;
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            const pair = self.at(i);
            mean_x += pair.mono;
            mean_y += pair.offset;
        }
        const n: f64 = @floatFromInt(self.len);
        mean_x /= n;
        mean_y /= n;

        var covariance: f64 = 0;
        var variance: f64 = 0;
        i = 0;
        while (i < self.len) : (i += 1) {
            const pair = self.at(i);
            const dx = pair.mono - mean_x;
            covariance += dx * (pair.offset - mean_y);
            variance += dx * dx;
        }
        if (variance <= 0) return null;

        // offset = reference - local. A fast local clock makes offset decrease.
        const slope = covariance / variance;
        const frequency = -slope;
        if (!std.math.isFinite(frequency)) return null;
        return std.math.clamp(frequency, -max_abs, max_abs);
    }

    pub fn residualJitter(self: *const FrequencyEstimator) Duration {
        const frequency = self.estimate(std.math.inf(f64)) orelse return .zero;
        if (self.len < 2) return .zero;
        var mean_x: f64 = 0;
        var mean_y: f64 = 0;
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            const pair = self.at(i);
            mean_x += pair.mono;
            mean_y += pair.offset;
        }
        const n: f64 = @floatFromInt(self.len);
        mean_x /= n;
        mean_y /= n;
        var sum: f64 = 0;
        i = 0;
        while (i < self.len) : (i += 1) {
            const pair = self.at(i);
            const predicted = mean_y + (-frequency) * (pair.mono - mean_x);
            const residual = pair.offset - predicted;
            sum += residual * residual;
        }
        return Duration.fromFloatSeconds(@sqrt(sum / n) / @as(f64, @floatFromInt(types.ns_per_s)));
    }
};

pub const Config = struct {
    /// Step when the filtered offset exceeds this magnitude.
    step_threshold: Duration = Duration.fromMilliseconds(50),
    /// Never step by more than this magnitude automatically.
    max_automatic_step: Duration = Duration.fromSeconds(3600),
    /// Minimum number of filtered samples before an automatic step.
    min_samples_for_step: usize = 2,
    /// Maximum slew correction, in parts per million.
    max_slew_ppm: f64 = 500.0,
    /// Time constant used to steer the applied frequency toward the estimate.
    slew_time_constant: Duration = Duration.fromSeconds(30),
    /// Time without a reference sample before entering holdover.
    holdover_timeout: Duration = Duration.fromSeconds(3600),
    /// Maximum frequency error accepted from the estimator.
    max_frequency_ppm: f64 = 1000.0,
    /// Dispersion growth used when aging filtered samples.
    sample_drift_ppm: f64 = 10.0,
    /// Assumed drift bound while in holdover.
    holdover_drift_ppm: f64 = 50.0,
    /// Base uncertainty added to every estimate.
    base_uncertainty: Duration = Duration.fromMilliseconds(1),
};

pub const UpdateResult = struct {
    stepped: bool,
    slewed: bool,
    residual: Duration,
    filtered_offset: Duration,
    frequency: f64,
    applied_frequency: f64,
    discontinuity: ?Discontinuity,
};

pub const DisciplinedClock = struct {
    config: Config,
    monotonic: Monotonic,
    epoch_monotonic: Duration,
    epoch_utc: Timestamp,
    applied_frequency: f64 = 0.0,
    estimated_frequency: f64 = 0.0,
    offset_filter: OffsetFilter = .{},
    frequency_estimator: FrequencyEstimator = .{},
    last_sample_monotonic: ?Duration = null,
    last_sample_utc: ?Timestamp = null,
    quality: Quality = .{},
    synchronized: bool = false,
    holdover: bool = false,
    last_discontinuity: ?Discontinuity = null,
    leap: LeapSeconds = .{},
    steps: u64 = 0,
    slews: u64 = 0,

    pub fn init(monotonic: Monotonic, initial_utc: Timestamp, config: Config) DisciplinedClock {
        const now = monotonic.now();
        return .{
            .config = config,
            .monotonic = monotonic,
            .epoch_monotonic = now,
            .epoch_utc = initial_utc,
        };
    }

    /// Current UTC estimate without mutating holdover state.
    pub fn predict(self: *const DisciplinedClock, monotonic: Duration) Timestamp {
        const elapsed = monotonic.sub(self.epoch_monotonic);
        const scaled = elapsed.mul(1.0 + self.applied_frequency);
        return self.epoch_utc.add(scaled);
    }

    /// Feed a new reference sample and update the discipline state.
    pub fn update(self: *DisciplinedClock, sample: Sample) UpdateResult {
        const predicted = self.predict(sample.monotonic);
        const residual = sample.reference.difference(predicted);

        const filter_sample: FilterSample = .{
            .offset = residual,
            .delay = sample.delay,
            .dispersion = sample.dispersion.add(sample.uncertainty),
            .received = sample.monotonic,
            .quality = sample.quality,
        };
        self.offset_filter.add(filter_sample);
        self.frequency_estimator.add(sample.monotonic, residual);

        const filtered = self.offset_filter.best(sample.monotonic, self.config.sample_drift_ppm) orelse filter_sample;
        self.estimated_frequency = self.frequency_estimator.estimate(self.config.max_frequency_ppm * 1e-6) orelse 0.0;

        var stepped = false;
        var discontinuity: ?Discontinuity = null;

        const magnitude = filtered.offset.abs();
        const step_allowed = self.offset_filter.count() >= self.config.min_samples_for_step;
        if (step_allowed and magnitude.ns > self.config.step_threshold.ns and magnitude.ns <= self.config.max_automatic_step.ns) {
            self.epoch_utc = sample.reference;
            self.epoch_monotonic = sample.monotonic;
            self.applied_frequency = -self.estimated_frequency;
            self.offset_filter.reset();
            self.frequency_estimator.reset();
            self.steps += 1;
            stepped = true;
            discontinuity = .{
                .kind = .step,
                .at = sample.monotonic,
                .delta = filtered.offset,
            };
        } else {
            self.slewToward(sample, filtered.offset);
            self.slews += 1;
        }

        self.last_sample_monotonic = sample.monotonic;
        self.last_sample_utc = sample.reference;
        self.quality = sample.quality;
        self.quality.reference_time = sample.reference;
        self.synchronized = true;

        if (self.holdover) {
            self.holdover = false;
            if (discontinuity == null) {
                discontinuity = .{ .kind = .holdover_exit, .at = sample.monotonic, .delta = .zero };
            }
        }
        self.last_discontinuity = discontinuity;

        return .{
            .stepped = stepped,
            .slewed = !stepped,
            .residual = residual,
            .filtered_offset = filtered.offset,
            .frequency = self.estimated_frequency,
            .applied_frequency = self.applied_frequency,
            .discontinuity = discontinuity,
        };
    }

    fn slewToward(self: *DisciplinedClock, sample: Sample, filtered_offset: Duration) void {
        // Rate correction removes the estimated local frequency error.
        const target_rate = -self.estimated_frequency;

        // Offset correction: converge over the configured time constant.
        var offset_rate: f64 = 0.0;
        if (self.config.slew_time_constant.ns > 0) {
            offset_rate = @as(f64, @floatFromInt(filtered_offset.ns)) /
                @as(f64, @floatFromInt(self.config.slew_time_constant.ns));
        }

        const desired = std.math.clamp(
            target_rate + offset_rate,
            -self.config.max_slew_ppm * 1e-6,
            self.config.max_slew_ppm * 1e-6,
        );

        // First-order steering avoids abrupt rate changes.
        const elapsed = if (self.last_sample_monotonic) |last|
            sample.monotonic.sub(last)
        else
            Duration.zero;
        var alpha: f64 = 1.0;
        if (self.config.slew_time_constant.ns > 0 and elapsed.ns > 0) {
            alpha = std.math.clamp(
                @as(f64, @floatFromInt(elapsed.ns)) /
                    @as(f64, @floatFromInt(self.config.slew_time_constant.ns)),
                0.0,
                1.0,
            );
        }
        self.applied_frequency += (desired - self.applied_frequency) * alpha;
        self.applied_frequency = std.math.clamp(
            self.applied_frequency,
            -self.config.max_slew_ppm * 1e-6,
            self.config.max_slew_ppm * 1e-6,
        );
    }

    /// Force a UTC step, for example after an operator command or a very
    /// large correction.
    pub fn stepTo(self: *DisciplinedClock, utc: Timestamp) Discontinuity {
        const now = self.monotonic.now();
        const delta = utc.difference(self.predict(now));
        self.epoch_utc = utc;
        self.epoch_monotonic = now;
        self.offset_filter.reset();
        self.frequency_estimator.reset();
        self.applied_frequency = 0.0;
        self.steps += 1;
        const discontinuity = Discontinuity{ .kind = .step, .at = now, .delta = delta };
        self.last_discontinuity = discontinuity;
        return discontinuity;
    }

    pub fn nowSnapshot(self: *DisciplinedClock) source.Error!Snapshot {
        const now = self.monotonic.now();
        const utc = self.predict(now);
        const since_sample = if (self.last_sample_monotonic) |last| now.sub(last) else Duration.zero;

        var discontinuity: ?Discontinuity = null;
        if (self.synchronized and since_sample.ns > self.config.holdover_timeout.ns and !self.holdover) {
            self.holdover = true;
            self.synchronized = false;
            self.quality.leap = .unknown;
            discontinuity = .{ .kind = .holdover_enter, .at = now, .delta = .zero };
            self.last_discontinuity = discontinuity;
        }

        var uncertainty_ns = self.config.base_uncertainty.ns;
        uncertainty_ns += self.offset_filter.jitter(now, self.config.sample_drift_ppm).ns;
        uncertainty_ns += self.quality.rootDistance().ns;
        const growth_ppm = if (self.holdover)
            self.config.holdover_drift_ppm
        else
            self.config.sample_drift_ppm;
        uncertainty_ns += @intFromFloat(
            @as(f64, @floatFromInt(since_sample.ns)) * (growth_ppm * 1e-6),
        );

        var quality = self.quality;
        if (self.holdover or !self.synchronized) quality.leap = .unknown;

        return .{
            .monotonic = now,
            .utc = utc,
            .tai = self.leap.utcToTai(utc),
            .offset = self.offset_filter.medianOffset() orelse .zero,
            .frequency = self.estimated_frequency,
            .uncertainty = Duration.fromNanoseconds(uncertainty_ns),
            .quality = quality,
            .discontinuity = discontinuity,
            .synchronized = self.synchronized,
        };
    }

    pub fn timeSource(self: *DisciplinedClock) source.TimeSource {
        return source.TimeSource.from(DisciplinedClock, self);
    }
};

test "first large sample steps the clock" {
    var mono_value = Duration.zero;
    const TestMono = struct {
        value: *Duration,
        pub fn monotonicNow(self: *@This()) Duration {
            return self.value.*;
        }
    };
    var test_mono = TestMono{ .value = &mono_value };
    const mono = Monotonic.from(TestMono, &test_mono);

    var clock = DisciplinedClock.init(mono, Timestamp.zero, .{ .min_samples_for_step = 1 });
    const result = clock.update(.{
        .monotonic = Duration.fromSeconds(10),
        .reference = Timestamp.fromSeconds(12),
        .quality = .{ .leap = .no_warning, .stratum = 1 },
    });
    try std.testing.expect(result.stepped);
    try std.testing.expectEqual(Duration.fromSeconds(2), result.discontinuity.?.delta);

    mono_value = Duration.fromSeconds(10.5);
    const snapshot = try clock.nowSnapshot();
    try std.testing.expectEqual(@as(i96, 12), snapshot.utc.toSeconds());
    try std.testing.expectEqual(@as(i96, 500), @divTrunc(snapshot.utc.ns - 12 * types.ns_per_s, types.ns_per_ms));
}

test "small offset is slewed instead of stepped" {
    var mono_value = Duration.zero;
    const TestMono = struct {
        value: *Duration,
        pub fn monotonicNow(self: *@This()) Duration {
            return self.value.*;
        }
    };
    var test_mono = TestMono{ .value = &mono_value };
    const mono = Monotonic.from(TestMono, &test_mono);

    var clock = DisciplinedClock.init(mono, Timestamp.zero, .{});
    _ = clock.update(.{
        .monotonic = Duration.zero,
        .reference = Timestamp.fromNanoseconds(10 * types.ns_per_ms),
        .quality = .{ .leap = .no_warning, .stratum = 1 },
    });
    const result = clock.update(.{
        .monotonic = Duration.fromSeconds(1),
        .reference = Timestamp.fromNanoseconds(types.ns_per_s + 10 * types.ns_per_ms),
        .quality = .{ .leap = .no_warning, .stratum = 1 },
    });
    try std.testing.expect(!result.stepped);
    try std.testing.expect(result.applied_frequency > 0.0);
    try std.testing.expect(result.applied_frequency <= 500e-6);
}

test "frequency estimator recovers a constant rate error" {
    var estimator = FrequencyEstimator{};
    // Local runs 100 ppm fast: offset decreases 100 us per second.
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const t = Duration.fromSeconds(@as(i96, @intCast(i)));
        estimator.add(t, Duration.fromNanoseconds(-100 * types.ns_per_us * @as(i96, @intCast(i))));
    }
    const frequency = estimator.estimate(1e-3).?;
    try std.testing.expectApproxEqAbs(@as(f64, 100e-6), frequency, 1e-9);
}

test "holdover grows uncertainty and clears synchronization" {
    var mono_value = Duration.zero;
    const TestMono = struct {
        value: *Duration,
        pub fn monotonicNow(self: *@This()) Duration {
            return self.value.*;
        }
    };
    var test_mono = TestMono{ .value = &mono_value };
    const mono = Monotonic.from(TestMono, &test_mono);

    var clock = DisciplinedClock.init(mono, Timestamp.zero, .{
        .holdover_timeout = Duration.fromSeconds(10),
        .min_samples_for_step = 1,
    });
    _ = clock.update(.{
        .monotonic = Duration.zero,
        .reference = Timestamp.zero,
        .quality = .{ .leap = .no_warning, .stratum = 1 },
    });
    mono_value = Duration.fromSeconds(20);
    const snapshot = try clock.nowSnapshot();
    try std.testing.expect(!snapshot.synchronized);
    try std.testing.expectEqual(DiscontinuityKind.holdover_enter, snapshot.discontinuity.?.kind);
    try std.testing.expect(snapshot.uncertainty.ns > clock.config.base_uncertainty.ns);
}
