//! PTP profiles used by Project-Z media and telecom consumers.
//!
//! The profile table captures the wire-level defaults that matter to a
//! synchronization library: domain, transport, message rates, delay
//! mechanism, two-step behavior, and hardware-timestamp requirements. It does
//! not attempt to encode every profile-specific management option.

const std = @import("std");

pub const Transport = enum {
    ethernet,
    udp_ipv4,
    udp_ipv6,
};

pub const DelayMechanism = enum {
    end_to_end,
    peer_to_peer,
};

pub const BmcaVariant = enum {
    /// IEEE 1588 default dataset comparison.
    default,
    /// 802.1AS/gPTP grandmaster selection.
    gptp,
    /// ITU-T G.8275.1 local-clock priority handling.
    telecom,
};

pub const Profile = struct {
    name: []const u8,
    domain: u8,
    transport: Transport,
    delay_mechanism: DelayMechanism,
    bmca_variant: BmcaVariant,
    /// log2 seconds between Sync messages.
    sync_interval_log: i8,
    /// log2 seconds between Announce messages.
    announce_interval_log: i8,
    /// log2 seconds between Delay_Req or Pdelay_Req messages.
    delay_interval_log: i8,
    two_step: bool,
    /// Whether the profile assumes hardware timestamping for accuracy.
    hardware_timestamps: bool,

    pub fn syncIntervalSeconds(self: Profile) f64 {
        return std.math.pow(f64, 2.0, @floatFromInt(self.sync_interval_log));
    }

    pub fn announceIntervalSeconds(self: Profile) f64 {
        return std.math.pow(f64, 2.0, @floatFromInt(self.announce_interval_log));
    }

    pub fn delayIntervalSeconds(self: Profile) f64 {
        return std.math.pow(f64, 2.0, @floatFromInt(self.delay_interval_log));
    }
};

/// IEEE 1588 default profile (UDP/IPv4, end-to-end delay, 1 s sync).
pub const default_profile: Profile = .{
    .name = "ieee1588-default",
    .domain = 0,
    .transport = .udp_ipv4,
    .delay_mechanism = .end_to_end,
    .bmca_variant = .default,
    .sync_interval_log = 0,
    .announce_interval_log = 1,
    .delay_interval_log = 0,
    .two_step = false,
    .hardware_timestamps = false,
};

/// IEEE 802.1AS / gPTP: Layer-2, peer-delay, 125 ms sync.
pub const gptp: Profile = .{
    .name = "802.1as-gptp",
    .domain = 0,
    .transport = .ethernet,
    .delay_mechanism = .peer_to_peer,
    .bmca_variant = .gptp,
    .sync_interval_log = -3,
    .announce_interval_log = 0,
    .delay_interval_log = 0,
    .two_step = true,
    .hardware_timestamps = true,
};

/// AES67 / SMPTE ST 2059-2 media profile.
pub const aes67_st2059_2: Profile = .{
    .name = "aes67-st2059-2",
    .domain = 0,
    .transport = .udp_ipv4,
    .delay_mechanism = .end_to_end,
    .bmca_variant = .default,
    .sync_interval_log = -3,
    .announce_interval_log = 0,
    .delay_interval_log = -3,
    .two_step = false,
    .hardware_timestamps = false,
};

/// ITU-T G.8275.1 full timing support profile (domain 24).
pub const g8275_1: Profile = .{
    .name = "g.8275.1",
    .domain = 24,
    .transport = .ethernet,
    .delay_mechanism = .peer_to_peer,
    .bmca_variant = .telecom,
    .sync_interval_log = -3,
    .announce_interval_log = 0,
    .delay_interval_log = -3,
    .two_step = true,
    .hardware_timestamps = true,
};

/// IEEE C37.238-2011 power profile.
pub const c37_238: Profile = .{
    .name = "c37.238-2011",
    .domain = 0,
    .transport = .ethernet,
    .delay_mechanism = .end_to_end,
    .bmca_variant = .default,
    .sync_interval_log = 0,
    .announce_interval_log = 1,
    .delay_interval_log = 0,
    .two_step = false,
    .hardware_timestamps = true,
};

pub const all = [_]Profile{
    default_profile,
    gptp,
    aes67_st2059_2,
    g8275_1,
    c37_238,
};

pub fn byName(name: []const u8) ?Profile {
    for (all) |profile| {
        if (std.mem.eql(u8, profile.name, name)) return profile;
    }
    return null;
}

test "profile table covers the requested standards" {
    try std.testing.expectEqual(@as(u8, 24), g8275_1.domain);
    try std.testing.expectEqual(Transport.ethernet, gptp.transport);
    try std.testing.expectEqual(DelayMechanism.peer_to_peer, gptp.delay_mechanism);
    try std.testing.expectEqual(@as(f64, 0.125), gptp.syncIntervalSeconds());
    try std.testing.expectEqual(@as(f64, 1.0), gptp.announceIntervalSeconds());
    try std.testing.expectEqual(@as(f64, 0.125), aes67_st2059_2.syncIntervalSeconds());
    try std.testing.expectEqual(@as(f64, 1.0), c37_238.syncIntervalSeconds());
}

test "profile lookup by name" {
    const profile = byName("g.8275.1").?;
    try std.testing.expectEqual(@as(u8, 24), profile.domain);
    try std.testing.expect(byName("missing") == null);
}
