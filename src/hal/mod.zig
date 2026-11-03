//! Platform HAL adapters.
//!
//! Linux is implemented first because it owns `SO_TIMESTAMPING`, `/dev/ptp*`,
//! and `AF_PACKET`. macOS and Windows adapters can be added behind this module
//! without changing the clock or protocol layers.

const std = @import("std");
const builtin = @import("builtin");

pub const linux = if (builtin.os.tag == .linux) @import("linux/mod.zig") else struct {};

pub const PtpClock = if (builtin.os.tag == .linux) linux.PtpClock else void;
pub const RawEthernet = if (builtin.os.tag == .linux) linux.RawEthernet else void;
pub const TimestampingResult = if (builtin.os.tag == .linux) linux.TimestampingResult else void;

test {
    std.testing.refAllDecls(@This());
    if (builtin.os.tag == .linux) _ = linux;
}
