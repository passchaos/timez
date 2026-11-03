//! `timez.clock`: unified time source and clock discipline.

const std = @import("std");

pub const types = @import("types.zig");
pub const source = @import("source.zig");
pub const quality = @import("quality.zig");
pub const leap = @import("leap.zig");
pub const system = @import("system.zig");
pub const discipline = @import("discipline.zig");

pub const Duration = types.Duration;
pub const Timestamp = types.Timestamp;
pub const TaiTimestamp = types.TaiTimestamp;
pub const OffsetSample = types.OffsetSample;

pub const Error = source.Error;
pub const Snapshot = source.Snapshot;
pub const TimeSource = source.TimeSource;
pub const Monotonic = source.Monotonic;
pub const Discontinuity = source.Discontinuity;
pub const DiscontinuityKind = source.DiscontinuityKind;
pub const JumpDetector = source.JumpDetector;
pub const FixedSource = source.FixedSource;

pub const Quality = quality.Quality;
pub const LeapIndicator = quality.LeapIndicator;
pub const Stratum = quality.Stratum;

pub const LeapSeconds = leap.LeapSeconds;
pub const LeapSecond = leap.LeapSecond;
pub const PendingLeap = leap.PendingLeap;
pub const default_leap_table = leap.default_table;

pub const SystemClock = system.SystemClock;
pub const DisciplinedClock = discipline.DisciplinedClock;
pub const Sample = discipline.Sample;
pub const Config = discipline.Config;
pub const UpdateResult = discipline.UpdateResult;
pub const OffsetFilter = discipline.OffsetFilter;
pub const FrequencyEstimator = discipline.FrequencyEstimator;

test {
    std.testing.refAllDecls(@This());
    _ = types;
    _ = source;
    _ = quality;
    _ = leap;
    _ = system;
    _ = discipline;
}
