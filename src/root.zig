//! timez: Project-Z time synchronization library.
//!
//! Modules:
//! - `clock`: unified time source, UTC/TAI, quality, discipline, holdover.
//! - `ntp`: NTPv4/SNTP wire protocol, client, server, selection, NTS.
//! - `hal`: platform clock and timestamping adapters.
//! - `ptp`: IEEE 1588 / 802.1AS wire protocol and clock state.
//! - `profiles`: PTP profiles for media and telecom applications.
//! - `diag`: offset, drift, jitter, holdover diagnostics and metrics.

const std = @import("std");

pub const clock = @import("clock/mod.zig");
pub const ntp = @import("ntp/mod.zig");
pub const hal = @import("hal/mod.zig");
pub const ptp = @import("ptp/mod.zig");
pub const profiles = @import("profiles/mod.zig");
pub const diag = @import("diag/mod.zig");

test {
    std.testing.refAllDecls(@This());
}
