//! IEEE 1588 ordinary/boundary/transparent clock state and message helpers.
//!
//! This module owns protocol logic, not sockets. A caller feeds received
//! frames and receives typed events, or asks the clock to build Sync,
//! Follow_Up, Delay_Req, Delay_Resp, and Announce messages.

const std = @import("std");
const clock_mod = @import("../clock/mod.zig");
const types = @import("types.zig");
const message = @import("message.zig");
const bmca = @import("bmca.zig");

pub const Duration = clock_mod.Duration;
pub const Timestamp = types.Timestamp;
pub const ClockIdentity = types.ClockIdentity;
pub const PortIdentity = types.PortIdentity;
pub const ClockQuality = types.ClockQuality;
pub const TimeSource = types.TimeSource;
pub const CorrectionField = types.CorrectionField;
pub const Header = message.Header;
pub const Parsed = message.Parsed;
pub const Role = bmca.State;
pub const Dataset = bmca.Dataset;

pub const Error = message.ParseError || error{
    WrongDomain,
    WrongVersion,
    UnexpectedMessageType,
};

pub const Config = struct {
    identity: ClockIdentity,
    port_number: u16 = 1,
    domain: u8 = 0,
    priority1: u8 = 128,
    priority2: u8 = 128,
    quality: ClockQuality = .{},
    time_source: TimeSource = .other,
    two_step: bool = true,
    log_message_interval: i8 = -3,
    control_field: u8 = 0,
};

pub const SyncEvent = struct {
    header: Header,
    timestamp: Timestamp,
    receive_time: Timestamp,
};

pub const FollowUpEvent = struct {
    header: Header,
    timestamp: Timestamp,
};

pub const DelayReqEvent = struct {
    header: Header,
    timestamp: Timestamp,
    receive_time: Timestamp,
};

pub const DelayRespEvent = struct {
    header: Header,
    body: message.DelayRespBody,
    receive_time: Timestamp,
};

pub const AnnounceEvent = struct {
    header: Header,
    body: message.AnnounceBody,
    receive_time: Timestamp,
};

pub const SignalingEvent = struct {
    header: Header,
    body: message.SignalingBody,
};

pub const Event = union(enum) {
    sync: SyncEvent,
    follow_up: FollowUpEvent,
    delay_req: DelayReqEvent,
    delay_resp: DelayRespEvent,
    announce: AnnounceEvent,
    signaling: SignalingEvent,
    ignored: void,
};

pub const SyncEstimate = struct {
    offset: Duration,
    correction: Duration,
    t1: Timestamp,
    t2: Timestamp,

    pub fn sample(self: SyncEstimate, monotonic: Duration) clock_mod.Sample {
        return .{
            .monotonic = monotonic,
            .reference = self.t2.toClock().add(self.offset),
            .delay = .zero,
            .dispersion = .zero,
            .uncertainty = .zero,
        };
    }
};

pub const OrdinaryClock = struct {
    config: Config,
    bmca: bmca.Bmca,
    role: Role = .listening,
    last_sync: ?SyncEvent = null,
    last_follow_up: ?FollowUpEvent = null,
    path_delay: Duration = .zero,
    last_delay_estimate: Duration = .zero,

    pub fn init(config: Config) OrdinaryClock {
        return .{
            .config = config,
            .bmca = bmca.Bmca.init(.{
                .identity = config.identity,
                .priority1 = config.priority1,
                .priority2 = config.priority2,
                .quality = config.quality,
                .steps_removed = 0,
                .time_source = config.time_source,
            }),
        };
    }

    pub fn portIdentity(self: *const OrdinaryClock) PortIdentity {
        return .{
            .clock_identity = self.config.identity,
            .port_number = self.config.port_number,
        };
    }

    pub fn localDataset(self: *const OrdinaryClock) Dataset {
        return self.bmca.local;
    }

    /// Feed the best announce datasets seen on the network.
    pub fn updateBmca(self: *OrdinaryClock, announces: []const Dataset) Role {
        self.role = self.bmca.update(announces);
        return self.role;
    }

    pub fn handleMessage(self: *OrdinaryClock, bytes: []const u8, receive_time: Timestamp) Error!Event {
        const parsed = try message.parse(bytes);
        if (parsed.header.domain != self.config.domain) return error.WrongDomain;
        if (parsed.header.version != .v2) return error.WrongVersion;

        switch (parsed.header.message_type) {
            .sync => {
                const body = try message.parseSync(parsed.body);
                const event: SyncEvent = .{
                    .header = parsed.header,
                    .timestamp = body.origin_timestamp,
                    .receive_time = receive_time,
                };
                self.last_sync = event;
                return .{ .sync = event };
            },
            .follow_up => {
                const body = try message.parseFollowUp(parsed.body);
                const event: FollowUpEvent = .{
                    .header = parsed.header,
                    .timestamp = body.precise_origin_timestamp,
                };
                self.last_follow_up = event;
                return .{ .follow_up = event };
            },
            .delay_req => {
                const body = try message.parseDelayReq(parsed.body);
                return .{ .delay_req = .{
                    .header = parsed.header,
                    .timestamp = body.origin_timestamp,
                    .receive_time = receive_time,
                } };
            },
            .delay_resp => {
                const body = try message.parseDelayResp(parsed.body);
                return .{ .delay_resp = .{
                    .header = parsed.header,
                    .body = body,
                    .receive_time = receive_time,
                } };
            },
            .announce => {
                const body = try message.parseAnnounce(parsed.body);
                _ = self.bmca.update(&.{Dataset.fromAnnounce(body)});
                self.role = self.bmca.state;
                return .{ .announce = .{
                    .header = parsed.header,
                    .body = body,
                    .receive_time = receive_time,
                } };
            },
            .signaling => {
                const body = try message.parseSignaling(parsed.body);
                return .{ .signaling = .{ .header = parsed.header, .body = body } };
            },
            else => return .{ .ignored = {} },
        }
    }

    /// Build a Sync message. For two-step clocks the precise timestamp is
    /// carried in a Follow_Up message.
    pub fn makeSync(
        self: *const OrdinaryClock,
        sequence_id: u16,
        origin: Timestamp,
        correction: CorrectionField,
        output: []u8,
    ) Error!usize {
        var body: [16]u8 = undefined;
        const body_len = try message.writeSync(&body, origin);
        return self.writeHeaderBody(.sync, sequence_id, correction, body[0..body_len], output);
    }

    pub fn makeFollowUp(
        self: *const OrdinaryClock,
        sequence_id: u16,
        precise_origin: Timestamp,
        correction: CorrectionField,
        output: []u8,
    ) Error!usize {
        var body: [16]u8 = undefined;
        const body_len = try message.writeFollowUp(&body, precise_origin);
        return self.writeHeaderBody(.follow_up, sequence_id, correction, body[0..body_len], output);
    }

    pub fn makeDelayReq(
        self: *const OrdinaryClock,
        sequence_id: u16,
        origin: Timestamp,
        correction: CorrectionField,
        output: []u8,
    ) Error!usize {
        var body: [16]u8 = undefined;
        const body_len = try message.writeDelayReq(&body, origin);
        return self.writeHeaderBody(.delay_req, sequence_id, correction, body[0..body_len], output);
    }

    pub fn makeDelayResp(
        self: *const OrdinaryClock,
        sequence_id: u16,
        receive_timestamp: Timestamp,
        requesting: PortIdentity,
        correction: CorrectionField,
        output: []u8,
    ) Error!usize {
        var body: [32]u8 = undefined;
        const body_len = try message.writeDelayResp(&body, receive_timestamp, requesting);
        return self.writeHeaderBody(.delay_resp, sequence_id, correction, body[0..body_len], output);
    }

    pub fn makeAnnounce(
        self: *const OrdinaryClock,
        sequence_id: u16,
        origin: Timestamp,
        steps_removed: u16,
        output: []u8,
    ) Error!usize {
        var body: [32]u8 = undefined;
        const body_len = try message.writeAnnounce(&body, .{
            .origin_timestamp = origin,
            .current_utc_offset = 37,
            .grandmaster_priority1 = self.config.priority1,
            .grandmaster_quality = self.config.quality,
            .grandmaster_priority2 = self.config.priority2,
            .grandmaster_identity = self.config.identity,
            .steps_removed = steps_removed,
            .time_source = self.config.time_source,
        });
        return self.writeHeaderBody(.announce, sequence_id, .{}, body[0..body_len], output);
    }

    fn writeHeaderBody(
        self: *const OrdinaryClock,
        message_type: types.MessageType,
        sequence_id: u16,
        correction: CorrectionField,
        body: []const u8,
        output: []u8,
    ) Error!usize {
        var header = Header{
            .message_type = message_type,
            .version = .v2,
            .domain = self.config.domain,
            .correction = correction,
            .source_port_identity = self.portIdentity(),
            .sequence_id = sequence_id,
            .control_field = self.config.control_field,
            .log_message_interval = self.config.log_message_interval,
            .flags = .{ .two_step = self.config.two_step },
        };
        if (message_type == .follow_up or message_type == .delay_resp) {
            header.flags.two_step = false;
        }
        return message.write(header, body, output);
    }

    /// Compute the offset from a one-step Sync or a two-step Sync+FollowUp.
    pub fn estimateSync(
        sync_timestamp: Timestamp,
        follow_up_timestamp: ?Timestamp,
        receive_time: Timestamp,
        correction: CorrectionField,
        path_delay: Duration,
    ) SyncEstimate {
        const t1 = follow_up_timestamp orelse sync_timestamp;
        const t2 = receive_time;
        const offset = Duration.fromNanoseconds(
            t2.difference(t1).ns - correction.toDuration().ns - path_delay.ns,
        );
        return .{
            .offset = offset,
            .correction = correction.toDuration(),
            .t1 = t1,
            .t2 = t2,
        };
    }

    /// Compute the path delay from a Delay_Req/Delay_Resp exchange.
    pub fn estimatePathDelay(
        t1: Timestamp,
        t2: Timestamp,
        t3: Timestamp,
        t4: Timestamp,
        correction: CorrectionField,
    ) Duration {
        const round_trip = t4.difference(t1).ns - (t3.difference(t2).ns) - correction.toDuration().ns;
        return .{ .ns = @divTrunc(round_trip, 2) };
    }
};

pub const TransparentClock = struct {
    /// Add ingress-to-egress residence time to the correction field.
    pub fn addResidence(
        correction: CorrectionField,
        ingress: Timestamp,
        egress: Timestamp,
    ) CorrectionField {
        return correction.add(CorrectionField.fromDuration(egress.difference(ingress)));
    }

    /// Rewrite a message's correction field in place.
    pub fn correctMessage(bytes: []u8, ingress: Timestamp, egress: Timestamp) Error!void {
        const parsed = try message.parse(bytes);
        const new_correction = addResidence(parsed.header.correction, ingress, egress);
        message.setCorrection(bytes, new_correction);
    }
};

pub const BoundaryPort = struct {
    clock: OrdinaryClock,
    enabled: bool = true,
};

/// A bounded boundary clock with independent per-port ordinary-clock state.
pub const BoundaryClock = struct {
    ports: [8]BoundaryPort = undefined,
    count: usize = 0,

    pub const AddError = error{TooManyPorts};

    pub fn addPort(self: *BoundaryClock, config: Config) AddError!*BoundaryPort {
        if (self.count == self.ports.len) return error.TooManyPorts;
        self.ports[self.count] = .{ .clock = OrdinaryClock.init(config) };
        self.count += 1;
        return &self.ports[self.count - 1];
    }

    pub fn updateBmca(self: *BoundaryClock, announces: []const Dataset) void {
        for (self.ports[0..self.count]) |*port| {
            _ = port.clock.updateBmca(announces);
        }
    }
};

test "ordinary clock builds and parses a sync message" {
    const config: Config = .{
        .identity = ClockIdentity.fromU64(0x0011223344556677),
        .domain = 0,
        .two_step = true,
    };
    var ordinary = OrdinaryClock.init(config);
    const origin: Timestamp = .{ .seconds = 1_700_000_000, .nanoseconds = 1 };

    var packet: [64]u8 = undefined;
    const len = try ordinary.makeSync(7, origin, .{ .raw = 0 }, &packet);
    const event = try ordinary.handleMessage(packet[0..len], .{ .seconds = 1_700_000_001, .nanoseconds = 0 });
    switch (event) {
        .sync => |sync| {
            try std.testing.expectEqual(@as(u16, 7), sync.header.sequence_id);
            try std.testing.expect(sync.header.twoStep());
            try std.testing.expectEqual(@as(u48, 1_700_000_000), sync.timestamp.seconds);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "two-step sync offset computation" {
    const sync: Timestamp = .{ .seconds = 1_700_000_000, .nanoseconds = 0 };
    const follow_up: Timestamp = .{ .seconds = 1_700_000_000, .nanoseconds = 500 };
    const received: Timestamp = .{ .seconds = 1_700_000_001, .nanoseconds = 0 };
    const estimate = OrdinaryClock.estimateSync(sync, follow_up, received, .{}, Duration.fromMilliseconds(10));
    // t2 - t1 = 1s - 500ns, minus 10ms path delay.
    try std.testing.expectEqual(@as(i96, 990_000_000 - 500), estimate.offset.ns);
}

test "path delay computation" {
    const t1: Timestamp = .{ .seconds = 1_700_000_000, .nanoseconds = 0 };
    const t2: Timestamp = .{ .seconds = 1_700_000_001, .nanoseconds = 0 };
    const t3: Timestamp = .{ .seconds = 1_700_000_002, .nanoseconds = 0 };
    const t4: Timestamp = .{ .seconds = 1_700_000_003, .nanoseconds = 0 };
    const delay = OrdinaryClock.estimatePathDelay(t1, t2, t3, t4, .{});
    // (3s - 1s) / 2 = 1s.
    try std.testing.expectEqual(Duration.fromSeconds(1), delay);
}

test "transparent clock adds residence time" {
    const ingress: Timestamp = .{ .seconds = 10, .nanoseconds = 0 };
    const egress: Timestamp = .{ .seconds = 10, .nanoseconds = 1000 };
    const corrected = TransparentClock.addResidence(.{}, ingress, egress);
    try std.testing.expectEqual(Duration.fromMicroseconds(1), corrected.toDuration());
}

test "boundary clock bounds its ports" {
    var boundary = BoundaryClock{};
    const config: Config = .{ .identity = ClockIdentity.fromU64(1), .port_number = 1 };
    _ = try boundary.addPort(config);
    var i: usize = 1;
    while (i < 8) : (i += 1) {
        var port_config = config;
        port_config.port_number = @intCast(i + 1);
        _ = try boundary.addPort(port_config);
    }
    try std.testing.expectError(error.TooManyPorts, boundary.addPort(config));
}
