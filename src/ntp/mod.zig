//! `timez.ntp`: NTPv4/SNTP wire protocol, client, server, selection, and NTS.

const std = @import("std");

pub const timestamp = @import("timestamp.zig");
pub const packet = @import("packet.zig");
pub const transport = @import("transport.zig");
pub const client = @import("client.zig");
pub const server = @import("server.zig");
pub const selection = @import("selection.zig");
pub const polling = @import("polling.zig");
pub const nts = @import("nts.zig");

pub const NtpTimestamp = timestamp.NtpTimestamp;
pub const Packet = packet.Packet;
pub const Parsed = packet.Parsed;
pub const Version = packet.Version;
pub const Mode = packet.Mode;
pub const Extension = packet.Extension;

pub const Transport = transport.Transport;
pub const UdpTransport = transport.UdpTransport;
pub const MemoryTransport = transport.MemoryTransport;

pub const Client = client.Client;
pub const ClientConfig = client.Config;
pub const Measurement = client.Measurement;
pub const QueryError = client.QueryError;

pub const Server = server.Server;
pub const ServerConfig = server.Config;
pub const RateLimiter = server.RateLimiter;

test {
    std.testing.refAllDecls(@This());
    _ = timestamp;
    _ = packet;
    _ = transport;
    _ = client;
    _ = server;
    _ = selection;
    _ = polling;
    _ = nts;
}
