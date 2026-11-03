//! Linux HAL: timestamping, PTP clocks, and raw Ethernet.

const std = @import("std");

pub const timestamping = @import("timestamping.zig");
pub const ptp_clock = @import("ptp_clock.zig");
pub const raw_ethernet = @import("raw_ethernet.zig");

pub const Flags = timestamping.Flags;
pub const TimestampingResult = timestamping.TimestampingResult;
pub const PtpClock = ptp_clock.PtpClock;
pub const PtpClockCaps = ptp_clock.PtpClockCaps;
pub const OffsetResult = ptp_clock.OffsetResult;
pub const RawEthernet = raw_ethernet.RawEthernet;
pub const SockAddrLl = raw_ethernet.SockAddrLl;

test {
    std.testing.refAllDecls(@This());
    _ = timestamping;
    _ = ptp_clock;
    _ = raw_ethernet;
}
