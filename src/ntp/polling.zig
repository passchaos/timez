//! Adaptive NTP polling schedule.
//!
//! RFC 5905 uses a poll exponent (log2 seconds) that grows while a server is
//! stable and shrinks after jitter or failures. This helper keeps that policy
//! separate from socket and selection code so it can be tested and reused by
//! callers driving their own runtime loop.

const std = @import("std");
const clock = @import("../clock/mod.zig");
const timestamp = @import("timestamp.zig");

pub const Duration = clock.Duration;

pub const Config = struct {
    min_poll: i8 = 4,
    max_poll: i8 = 10,
    /// Jitter above this prevents the poll exponent from increasing.
    jitter_threshold: Duration = Duration.fromMilliseconds(5),
    /// Jitter above this reduces the poll exponent.
    jitter_penalty_threshold: Duration = Duration.fromMilliseconds(20),
};

pub const Scheduler = struct {
    config: Config,
    poll: i8,

    pub fn init(config: Config) Scheduler {
        return .{
            .config = config,
            .poll = config.min_poll,
        };
    }

    pub fn interval(self: Scheduler) Duration {
        return timestamp.pollInterval(self.poll);
    }

    /// Called after a successful measurement. Stable servers are polled less
    /// often; noisy servers are polled more often.
    pub fn onSuccess(self: *Scheduler, jitter: Duration) void {
        if (jitter.ns > self.config.jitter_penalty_threshold.ns) {
            self.poll = @max(self.config.min_poll, self.poll - 1);
        } else if (jitter.ns <= self.config.jitter_threshold.ns) {
            self.poll = @min(self.config.max_poll, self.poll + 1);
        }
    }

    /// Called after a failed query. Reset to the fastest permitted polling.
    pub fn onFailure(self: *Scheduler) void {
        self.poll = self.config.min_poll;
    }

    /// Poll exponent, clamped to the configured bounds.
    pub fn exponent(self: Scheduler) i8 {
        return std.math.clamp(self.poll, self.config.min_poll, self.config.max_poll);
    }
};

test "poll exponent grows on stable measurements and resets on failure" {
    var scheduler = Scheduler.init(.{ .min_poll = 4, .max_poll = 8 });
    try std.testing.expectEqual(@as(i8, 4), scheduler.exponent());
    scheduler.onSuccess(Duration.zero);
    try std.testing.expectEqual(@as(i8, 5), scheduler.exponent());
    scheduler.onSuccess(Duration.zero);
    scheduler.onSuccess(Duration.zero);
    scheduler.onSuccess(Duration.zero);
    try std.testing.expectEqual(@as(i8, 8), scheduler.exponent());
    scheduler.onSuccess(Duration.zero);
    try std.testing.expectEqual(@as(i8, 8), scheduler.exponent());

    scheduler.onFailure();
    try std.testing.expectEqual(@as(i8, 4), scheduler.exponent());
    try std.testing.expectEqual(Duration.fromSeconds(16), scheduler.interval());
}

test "noisy measurements shorten the poll interval" {
    var scheduler = Scheduler.init(.{ .min_poll = 4, .max_poll = 8 });
    scheduler.poll = 7;
    scheduler.onSuccess(Duration.fromMilliseconds(30));
    try std.testing.expectEqual(@as(i8, 6), scheduler.exponent());
    scheduler.onSuccess(Duration.fromMilliseconds(10));
    try std.testing.expectEqual(@as(i8, 6), scheduler.exponent());
}
