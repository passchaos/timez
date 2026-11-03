//! Platform HAL adapters.
//!
//! Linux is implemented first because it owns `SO_TIMESTAMPING`, `/dev/ptp*`,
//! and `AF_PACKET`. macOS and Windows adapters can be added behind this
//! module without changing the clock or protocol layers.

const std = @import("std");

pub const linux = @import("linux/mod.zig");

pub const PtpClock = linux.PtpClock;
pub const RawEthernet = linux.RawEthernet;
pub const TimestampingResult = linux.TimestampingResult;

test {
    std.testing.refAllDecls(@This());
    _ = linux;
}
