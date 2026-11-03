//! IEEE 1588 PTP types, messages, BMCA, and clock state.

const std = @import("std");

pub const types = @import("types.zig");
pub const message = @import("message.zig");
pub const bmca = @import("bmca.zig");
pub const clock = @import("clock.zig");

pub const MessageType = types.MessageType;
pub const Header = message.Header;
pub const Parsed = message.Parsed;
pub const OrdinaryClock = clock.OrdinaryClock;
pub const TransparentClock = clock.TransparentClock;
pub const BoundaryClock = clock.BoundaryClock;
pub const Bmca = bmca.Bmca;
pub const Dataset = bmca.Dataset;
pub const Role = bmca.State;

test {
    std.testing.refAllDecls(@This());
    _ = types;
    _ = message;
    _ = bmca;
    _ = clock;
}
