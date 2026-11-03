//! Best Master Clock Algorithm (IEEE 1588-2019 section 9.3.4).
//!
//! The comparison order is the standard one:
//! priority1, clockClass, clockAccuracy, offsetScaledLogVariance, priority2,
//! clockIdentity, stepsRemoved. Profiles may constrain which clocks are
//! eligible, but the ordering itself is shared.

const std = @import("std");
const types = @import("types.zig");
const message = @import("message.zig");

pub const ClockIdentity = types.ClockIdentity;
pub const ClockQuality = types.ClockQuality;
pub const TimeSource = types.TimeSource;

pub const Dataset = struct {
    identity: ClockIdentity = .{},
    priority1: u8 = 128,
    priority2: u8 = 128,
    quality: ClockQuality = .{},
    steps_removed: u16 = 0,
    time_source: TimeSource = .other,

    pub fn fromAnnounce(announce: message.AnnounceBody) Dataset {
        return .{
            .identity = announce.grandmaster_identity,
            .priority1 = announce.grandmaster_priority1,
            .priority2 = announce.grandmaster_priority2,
            .quality = announce.grandmaster_quality,
            .steps_removed = announce.steps_removed,
            .time_source = announce.time_source,
        };
    }
};

pub const State = enum {
    /// No usable master has been selected yet.
    listening,
    /// This clock is the best master.
    master,
    /// This clock follows another master.
    slave,
    /// This clock is neither master nor slave (for example, a boundary port
    /// in the passive state).
    passive,
    /// Clock operation is disabled.
    disabled,
};

pub const CompareResult = enum {
    a_better,
    b_better,
    equal,
};

/// Compare two datasets using the BMCA ordering. Lower values are better.
pub fn compare(a: Dataset, b: Dataset) CompareResult {
    if (a.priority1 != b.priority1) return if (a.priority1 < b.priority1) .a_better else .b_better;

    switch (ClockQuality.order(a.quality, b.quality)) {
        .lt => return .a_better,
        .gt => return .b_better,
        .eq => {},
    }

    if (a.priority2 != b.priority2) return if (a.priority2 < b.priority2) .a_better else .b_better;

    switch (ClockIdentity.order(a.identity, b.identity)) {
        .lt => return .a_better,
        .gt => return .b_better,
        .eq => {},
    }

    if (a.steps_removed != b.steps_removed) {
        return if (a.steps_removed < b.steps_removed) .a_better else .b_better;
    }
    return .equal;
}

pub const Bmca = struct {
    local: Dataset,
    can_be_master: bool = true,
    state: State = .listening,
    current: ?Dataset = null,

    pub fn init(local: Dataset) Bmca {
        return .{ .local = local };
    }

    /// Feed the announce datasets currently visible on the network. The
    /// returned state is also stored in `self.state`.
    pub fn update(self: *Bmca, announces: []const Dataset) State {
        var best: ?Dataset = null;
        for (announces) |announce| {
            if (best) |current_best| {
                if (compare(announce, current_best) == .a_better) best = announce;
            } else {
                best = announce;
            }
        }

        if (best) |candidate| {
            switch (compare(self.local, candidate)) {
                .a_better => {
                    self.current = null;
                    self.state = if (self.can_be_master) .master else .passive;
                },
                .b_better => {
                    self.current = candidate;
                    self.state = .slave;
                },
                .equal => {
                    self.current = null;
                    self.state = if (self.can_be_master) .master else .passive;
                },
            }
        } else {
            self.current = null;
            self.state = if (self.can_be_master) .master else .listening;
        }
        return self.state;
    }
};

test "local clock becomes master when no announce is present" {
    var bmca = Bmca.init(.{
        .identity = ClockIdentity.fromU64(1),
        .priority1 = 10,
        .quality = .{ .clock_class = 6, .clock_accuracy = .within_100ns },
    });
    try std.testing.expectEqual(State.master, bmca.update(&.{}));
    try std.testing.expect(bmca.current == null);
}

test "better announce makes the clock a slave" {
    var bmca = Bmca.init(.{
        .identity = ClockIdentity.fromU64(0x100),
        .priority1 = 100,
        .quality = .{ .clock_class = 200, .clock_accuracy = .within_1ms },
    });
    const announce: Dataset = .{
        .identity = ClockIdentity.fromU64(1),
        .priority1 = 10,
        .quality = .{ .clock_class = 6, .clock_accuracy = .within_100ns },
        .steps_removed = 1,
    };
    try std.testing.expectEqual(State.slave, bmca.update(&.{announce}));
    try std.testing.expect(bmca.current != null);
}

test "bmca ordering follows the standard tie-breakers" {
    const base: Dataset = .{
        .identity = ClockIdentity.fromU64(2),
        .priority1 = 10,
        .quality = .{ .clock_class = 6, .clock_accuracy = .within_100ns, .offset_scaled_log_variance = 1 },
        .priority2 = 10,
        .steps_removed = 1,
    };

    var other = base;
    other.priority1 = 11;
    try std.testing.expectEqual(CompareResult.a_better, compare(base, other));

    other = base;
    other.quality.clock_class = 7;
    try std.testing.expectEqual(CompareResult.a_better, compare(base, other));

    other = base;
    other.quality.clock_accuracy = .within_1us;
    try std.testing.expectEqual(CompareResult.a_better, compare(base, other));

    other = base;
    other.priority2 = 11;
    try std.testing.expectEqual(CompareResult.a_better, compare(base, other));

    other = base;
    other.identity = ClockIdentity.fromU64(3);
    try std.testing.expectEqual(CompareResult.a_better, compare(base, other));

    other = base;
    other.steps_removed = 2;
    try std.testing.expectEqual(CompareResult.a_better, compare(base, other));

    try std.testing.expectEqual(CompareResult.equal, compare(base, base));
}

test "passive state when master capability is disabled" {
    var bmca = Bmca{ .local = .{ .identity = ClockIdentity.fromU64(1) }, .can_be_master = false };
    try std.testing.expectEqual(State.listening, bmca.update(&.{}));
    const announce: Dataset = .{ .identity = ClockIdentity.fromU64(1) };
    try std.testing.expectEqual(State.passive, bmca.update(&.{announce}));
    const worse: Dataset = .{ .identity = ClockIdentity.fromU64(2), .priority1 = 200, .quality = .{ .clock_class = 250 } };
    try std.testing.expectEqual(State.passive, bmca.update(&.{worse}));
}
