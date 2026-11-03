const std = @import("std");
const timez = @import("timez");

const clock = timez.clock;
const ntp = timez.ntp;

const FakeClock = struct {
    utc: clock.Timestamp,
    mono: clock.Duration,
    quality: clock.Quality = .{ .leap = .no_warning, .stratum = 1, .precision = -20 },

    pub fn nowSnapshot(self: *FakeClock) clock.Error!clock.Snapshot {
        const leap: clock.LeapSeconds = .{};
        return .{
            .monotonic = self.mono,
            .utc = self.utc,
            .tai = leap.utcToTai(self.utc),
            .quality = self.quality,
            .synchronized = true,
        };
    }

    pub fn monotonicNow(self: *FakeClock) clock.Duration {
        return self.mono;
    }
};

test "udp transport carries an NTP request and response" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const placeholder = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var client_transport = try ntp.UdpTransport.init(io, placeholder, placeholder);
    defer client_transport.deinit();
    var server_transport = try ntp.UdpTransport.init(io, placeholder, placeholder);
    defer server_transport.deinit();

    client_transport.peer = server_transport.socket.address;
    server_transport.peer = client_transport.socket.address;

    var system_clock = clock.SystemClock.init(io);
    system_clock.setCorrection(.zero, 0.0, .zero, .{
        .leap = .no_warning,
        .stratum = 1,
        .precision = -20,
    });
    var server = ntp.Server.init(system_clock.timeSource(), .{ .stratum = 1 });

    const now = system_clock.utcNow();
    const request_packet: ntp.Packet = .{
        .version = .v4,
        .mode = .client,
        .transmit_timestamp = ntp.NtpTimestamp.fromTimestamp(now),
    };
    var request_buffer: [48]u8 = undefined;
    _ = try request_packet.write(&request_buffer);

    try client_transport.sendBytes(&request_buffer);
    var incoming_buffer: [128]u8 = undefined;
    const incoming = try server_transport.receiveBytes(&incoming_buffer, clock.Duration.fromSeconds(1));
    try std.testing.expectEqual(@as(usize, 48), incoming.bytes.len);

    var response_buffer: [64]u8 = undefined;
    const response_len = try server.handle(incoming.bytes, &response_buffer);
    try server_transport.sendBytes(response_buffer[0..response_len]);

    var reply_buffer: [128]u8 = undefined;
    const reply = try client_transport.receiveBytes(&reply_buffer, clock.Duration.fromSeconds(1));
    const parsed = try ntp.packet.parse(reply.bytes);
    try std.testing.expectEqual(ntp.Mode.server, parsed.packet.mode);
    try std.testing.expectEqual(@as(u8, 1), parsed.packet.stratum);
    try std.testing.expectEqual(
        request_packet.transmit_timestamp.toRaw(),
        parsed.packet.origin_timestamp.toRaw(),
    );
}

test "client, server pool, selection, and discipline compose" {
    var fake_clock = FakeClock{
        .utc = clock.Timestamp.fromSeconds(1_700_000_000),
        .mono = .zero,
    };
    const source = clock.TimeSource.from(FakeClock, &fake_clock);
    const monotonic = clock.Monotonic.from(FakeClock, &fake_clock);

    const peer = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 123);
    var memory = ntp.MemoryTransport.init(peer);

    var response_buffer: [64]u8 = undefined;
    const server_time = clock.Timestamp.fromSeconds(1_700_000_002);
    const response: ntp.Packet = .{
        .leap = .no_warning,
        .version = .v4,
        .mode = .server,
        .stratum = 1,
        .precision = -20,
        .origin_timestamp = ntp.NtpTimestamp.fromTimestamp(fake_clock.utc),
        .receive_timestamp = ntp.NtpTimestamp.fromTimestamp(server_time),
        .transmit_timestamp = ntp.NtpTimestamp.fromTimestamp(server_time),
    };
    _ = try response.write(&response_buffer);
    memory.response = response_buffer[0..48];

    var client = ntp.Client.init(source, monotonic, .{
        .attempts = 1,
        .randomize_transmit = false,
    });
    var request_buffer: [64]u8 = undefined;
    var reply_buffer: [64]u8 = undefined;
    const measurement = try client.query(memory.transport(), peer, &request_buffer, &reply_buffer);
    try std.testing.expectEqual(clock.Duration.fromSeconds(2), measurement.offset);

    var pool = ntp.selection.Pool{};
    try pool.addMeasurement(measurement);
    const selected = pool.select(fake_clock.mono).?;
    try std.testing.expectEqual(@as(usize, 1), selected.selected_count);

    var sample = measurement.sample();
    sample.uncertainty = selected.uncertainty;
    sample.quality = selected.quality;

    var disciplined = clock.DisciplinedClock.init(monotonic, fake_clock.utc, .{
        .min_samples_for_step = 1,
    });
    const result = disciplined.update(sample);
    try std.testing.expect(result.stepped);
    try std.testing.expectEqual(clock.Duration.fromSeconds(2), result.discontinuity.?.delta);

    fake_clock.mono = clock.Duration.fromSeconds(1);
    const snapshot = try disciplined.nowSnapshot();
    try std.testing.expectEqual(@as(i96, 1_700_000_003), snapshot.utc.toSeconds());
}

test "system clock reports leap-correct TAI" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var system_clock = clock.SystemClock.init(io);
    const snapshot = try system_clock.nowSnapshot();
    const tai_minus_utc = snapshot.tai.ns - snapshot.utc.ns;
    try std.testing.expectEqual(@as(i96, 37 * std.time.ns_per_s), tai_minus_utc);
    const leap = clock.LeapSeconds{};
    try std.testing.expectEqual(clock.LeapIndicator.no_warning, leap.leapIndicator(snapshot.utc));
}

const EchoTransport = struct {
    server: *ntp.Server,
    peer: std.Io.net.IpAddress,
    response: [2048]u8 = undefined,
    response_len: usize = 0,

    pub fn sendBytes(self: *EchoTransport, bytes: []const u8) ntp.transport.SendError!void {
        self.response_len = self.server.handle(bytes, &self.response) catch @panic("server handle failed");
    }

    pub fn receiveBytes(
        self: *EchoTransport,
        buffer: []u8,
        timeout: clock.Duration,
    ) ntp.transport.ReceiveError!ntp.transport.Received {
        _ = timeout;
        if (self.response_len == 0) return error.Timeout;
        const n = @min(buffer.len, self.response_len);
        @memcpy(buffer[0..n], self.response[0..n]);
        self.response_len = 0;
        return .{ .bytes = buffer[0..n], .from = self.peer };
    }

    pub fn transport(self: *EchoTransport) ntp.Transport {
        return ntp.Transport.from(EchoTransport, self);
    }
};

test "NTS client and server protect a query end to end" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_clock = FakeClock{
        .utc = clock.Timestamp.fromSeconds(1_700_000_000),
        .mono = .zero,
    };
    var server_clock = FakeClock{
        .utc = clock.Timestamp.fromSeconds(1_700_000_002),
        .mono = .zero,
    };

    const key_material: ntp.nts.KeyMaterial = .{
        .c2s = [_]u8{0x01} ** 32,
        .s2c = [_]u8{0x02} ** 32,
    };
    const codec = ntp.nts.CookieCodec.init(io, 7, [_]u8{0x33} ** 32);
    const key_ring = ntp.nts.CookieKeyRing{ .current = codec };

    var cookie_buffer: [ntp.nts.cookie.max_cookie_len]u8 = undefined;
    const initial_cookie = try codec.encode(&cookie_buffer, key_material);
    var jar = ntp.nts.CookieJar{};
    try jar.add(initial_cookie);

    var client_session = ntp.nts.ClientSession.init(io, key_material, jar);
    defer client_session.deinit();
    var server_session = ntp.nts.ServerSession.init(io, key_ring);

    var server = ntp.Server.init(clock.TimeSource.from(FakeClock, &server_clock), .{
        .stratum = 1,
        .precision = -20,
    });
    server.nts = &server_session;

    const peer = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 123);
    var echo = EchoTransport{ .server = &server, .peer = peer };

    var client = ntp.Client.init(
        clock.TimeSource.from(FakeClock, &client_clock),
        clock.Monotonic.from(FakeClock, &client_clock),
        .{ .attempts = 1, .randomize_transmit = false },
    );
    client.nts = &client_session;

    var request_buffer: [1024]u8 = undefined;
    var response_buffer: [2048]u8 = undefined;
    const measurement = try client.query(echo.transport(), peer, &request_buffer, &response_buffer);
    try std.testing.expectEqual(clock.Duration.fromSeconds(2), measurement.offset);
    try std.testing.expectEqual(@as(u8, 1), measurement.stratum);
    // One cookie was consumed and the server returned two replacements.
    try std.testing.expectEqual(@as(usize, 2), client_session.cookies.len());
}

test "NTS server returns a NAK for an invalid cookie" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_clock = FakeClock{
        .utc = clock.Timestamp.fromSeconds(1_700_000_000),
        .mono = .zero,
    };
    var server_clock = FakeClock{
        .utc = clock.Timestamp.fromSeconds(1_700_000_002),
        .mono = .zero,
    };

    const key_material: ntp.nts.KeyMaterial = .{
        .c2s = [_]u8{0x01} ** 32,
        .s2c = [_]u8{0x02} ** 32,
    };
    const server_codec = ntp.nts.CookieCodec.init(io, 7, [_]u8{0x33} ** 32);
    const other_codec = ntp.nts.CookieCodec.init(io, 99, [_]u8{0x44} ** 32);

    var cookie_buffer: [ntp.nts.cookie.max_cookie_len]u8 = undefined;
    const stale_cookie = try other_codec.encode(&cookie_buffer, key_material);
    var jar = ntp.nts.CookieJar{};
    try jar.add(stale_cookie);

    var client_session = ntp.nts.ClientSession.init(io, key_material, jar);
    defer client_session.deinit();
    var server_session = ntp.nts.ServerSession.init(io, .{ .current = server_codec });

    var server = ntp.Server.init(clock.TimeSource.from(FakeClock, &server_clock), .{
        .stratum = 1,
        .require_nts = true,
    });
    server.nts = &server_session;

    const peer = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 123);
    var echo = EchoTransport{ .server = &server, .peer = peer };

    var client = ntp.Client.init(
        clock.TimeSource.from(FakeClock, &client_clock),
        clock.Monotonic.from(FakeClock, &client_clock),
        .{ .attempts = 1, .randomize_transmit = false },
    );
    client.nts = &client_session;

    var request_buffer: [1024]u8 = undefined;
    var response_buffer: [2048]u8 = undefined;
    try std.testing.expectError(
        error.KissOfDeath,
        client.query(echo.transport(), peer, &request_buffer, &response_buffer),
    );
    try std.testing.expectEqual([_]u8{ 'N', 'T', 'S', 'N' }, client.last_kiss_code.?);
}

test "linux SO_TIMESTAMPING delivers a receive timestamp" {
    if (@import("builtin").os.tag != .linux) return;

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const placeholder = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var client_transport = try ntp.UdpTransport.init(io, placeholder, placeholder);
    defer client_transport.deinit();
    var server_transport = try ntp.UdpTransport.init(io, placeholder, placeholder);
    defer server_transport.deinit();

    client_transport.peer = server_transport.socket.address;
    server_transport.peer = client_transport.socket.address;

    timez.hal.linux.timestamping.enable(
        server_transport.socket.handle,
        timez.hal.linux.timestamping.Flags.receive_all,
    ) catch |err| switch (err) {
        error.AccessDenied, error.SocketUnsupported => return,
        else => return err,
    };

    var timestamps: timez.hal.linux.timestamping.TimestampingResult = .{};
    var attempt: usize = 0;
    while (attempt < 10) : (attempt += 1) {
        try client_transport.sendBytes("ntp");
        // Software receive timestamps are attached asynchronously; give the
        // kernel a moment and retry if the queue was drained too early.
        try io.sleep(.fromMilliseconds(20), .awake);

        var control_buffer: [256]u8 = undefined;
        var data_buffer: [64]u8 = undefined;
        var messages = [_]std.Io.net.IncomingMessage{std.Io.net.IncomingMessage.init};
        messages[0].control = control_buffer[0..];

        const io_timeout: std.Io.Timeout = .{
            .duration = .{
                .raw = std.Io.Duration.fromNanoseconds(clock.Duration.fromSeconds(1).ns),
                .clock = .awake,
            },
        };
        const maybe_error, const count = server_transport.socket.receiveManyTimeout(
            io,
            &messages,
            &data_buffer,
            .{},
            io_timeout,
        );
        if (maybe_error) |err| return err;
        try std.testing.expectEqual(@as(usize, 1), count);
        try std.testing.expectEqualStrings("ntp", messages[0].data);

        timestamps = try timez.hal.linux.timestamping.parseControl(messages[0].control);
        if (timestamps.software != null) break;
    }
    try std.testing.expect(timestamps.software != null);
    const software = timestamps.softwareTimestamp().?;
    try std.testing.expect(software.ns > 0);
}

test "PTP master announce, sync, and follow-up drive the discipline" {
    const ptp = timez.ptp;
    const master_config: ptp.clock.Config = .{
        .identity = ptp.types.ClockIdentity.fromU64(0x0011223344556677),
        .domain = 0,
        .two_step = true,
        .priority1 = 10,
        .quality = .{ .clock_class = 6, .clock_accuracy = .within_100ns },
        .time_source = .gps,
    };
    const slave_config: ptp.clock.Config = .{
        .identity = ptp.types.ClockIdentity.fromU64(0x0102030405060708),
        .domain = 0,
        .priority1 = 128,
        .quality = .{ .clock_class = 248, .clock_accuracy = .unknown },
    };

    var master = ptp.clock.OrdinaryClock.init(master_config);
    var slave = ptp.clock.OrdinaryClock.init(slave_config);

    const origin: ptp.types.Timestamp = .{ .seconds = 1_700_000_000, .nanoseconds = 0 };
    const received: ptp.types.Timestamp = .{ .seconds = 1_700_000_001, .nanoseconds = 0 };

    var announce_buffer: [64]u8 = undefined;
    const announce_len = try master.makeAnnounce(1, origin, 0, &announce_buffer);
    _ = try slave.handleMessage(announce_buffer[0..announce_len], received);
    try std.testing.expectEqual(ptp.clock.Role.slave, slave.role);

    var sync_buffer: [64]u8 = undefined;
    const sync_len = try master.makeSync(2, .zero, .{}, &sync_buffer);
    var follow_buffer: [64]u8 = undefined;
    const follow_len = try master.makeFollowUp(2, origin, .{}, &follow_buffer);

    _ = try slave.handleMessage(sync_buffer[0..sync_len], received);
    _ = try slave.handleMessage(follow_buffer[0..follow_len], received);

    const sync_event = slave.last_sync.?;
    const follow_event = slave.last_follow_up.?;
    const path_delay = clock.Duration.fromMilliseconds(1);
    const estimate = ptp.clock.OrdinaryClock.estimateSync(
        sync_event.timestamp,
        follow_event.timestamp,
        sync_event.receive_time,
        sync_event.header.correction,
        path_delay,
    );
    try std.testing.expectEqual(clock.Duration.fromNanoseconds(999 * std.time.ns_per_ms), estimate.offset);

    var local_clock = FakeClock{
        .utc = clock.Timestamp.fromSeconds(1_700_000_000),
        .mono = .zero,
    };
    var disciplined = clock.DisciplinedClock.init(
        clock.Monotonic.from(FakeClock, &local_clock),
        local_clock.utc,
        .{ .min_samples_for_step = 1 },
    );
    const result = disciplined.update(estimate.sample(local_clock.mono));
    try std.testing.expect(result.stepped);
}

const vail = @import("vail");

fn readAvailableIntegration(reader: *std.Io.Reader, buffer: []u8) !usize {
    var data = [1][]u8{buffer};
    return reader.readVec(&data) catch |err| switch (err) {
        error.EndOfStream => 0,
        else => return err,
    };
}

fn ed25519Spki(public_key: [32]u8) [44]u8 {
    return .{
        0x30, 0x2a, // SEQUENCE, length 42
        0x30, 0x05, // SEQUENCE, length 5
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x03, 0x21, 0x00, // BIT STRING, length 33, no unused bits
    } ++ public_key;
}

fn writeServerFlight(writer: *std.Io.Writer, flight: []const u8) !void {
    // vail emits a bare ServerHello handshake message followed by TLS records
    // for the encrypted part of the flight. Frame the ServerHello first.
    const hello_len = 4 + ((@as(usize, flight[1]) << 16) |
        (@as(usize, flight[2]) << 8) |
        flight[3]);
    var header: [5]u8 = .{ 22, 3, 3, 0, 0 };
    std.mem.writeInt(u16, header[3..5], @intCast(hello_len), .big);
    try writer.writeAll(&header);
    try writer.writeAll(flight[0..hello_len]);
    try writer.writeAll(flight[hello_len..]);
    try writer.flush();
}

const NtsKeTestServer = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    listener: *std.Io.net.Server,
    key_pair: std.crypto.sign.Ed25519.KeyPair,
    spki: [44]u8,
    result: anyerror!void = {},

    fn run(ctx: *NtsKeTestServer) void {
        ctx.result = ctx.runInner();
    }

    fn threadMain(ctx: *NtsKeTestServer) void {
        var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        ctx.io = threaded.io();
        ctx.run();
    }

    fn runInner(ctx: *NtsKeTestServer) !void {
        const ServerConn = vail.tls.server_connection.ServerConnection(4096, 4096);

        const peer = try ctx.listener.accept(ctx.io);
        defer peer.close(ctx.io);

        var read_buffer: [4096]u8 = undefined;
        var reader = peer.reader(ctx.io, &read_buffer);
        var write_buffer: [4096]u8 = undefined;
        var writer = peer.writer(ctx.io, &write_buffer);

        var server_random: [32]u8 = undefined;
        ctx.io.random(&server_random);
        var server_secret: [32]u8 = undefined;
        ctx.io.random(&server_secret);
        var key_material = vail.tls.key_exchange.ServerKeyMaterial{ .x25519 = server_secret };
        const chain = [1][]const u8{&ctx.spki};

        var tls = ServerConn.init(.{
            .allocator = ctx.allocator,
            .policy = .{
                .alpn_protocols = &.{"ntske/1"},
                .server_certificate_type = .raw_public_key,
            },
            .server_random = server_random,
            .key_material = &key_material,
            .certificate_chain = &chain,
            .signer = .{ .ed25519 = .{ .key_pair = ctx.key_pair } },
            .server_certificate_type = .raw_public_key,
        });
        defer tls.deinit();

        var tls_output: std.ArrayList(u8) = .empty;
        defer tls_output.deinit(ctx.allocator);
        var established: ServerConn.Established = undefined;
        var established_ready = false;

        var input: [4096]u8 = undefined;
        while (!established_ready) {
            const n = try readAvailableIntegration(&reader.interface, &input);
            if (n == 0) return error.ConnectionClosed;
            var remaining = input[0..n];
            while (remaining.len > 0) {
                tls_output.clearRetainingCapacity();
                const received = try tls.receiveInto(remaining, &tls_output, &established);
                remaining = remaining[received.consumed..];
                if (tls_output.items.len > 0) {
                    if (received.event) |event| {
                        switch (event) {
                            .server_flight => try writeServerFlight(&writer.interface, tls_output.items),
                            else => {
                                try writer.interface.writeAll(tls_output.items);
                                try writer.interface.flush();
                            },
                        }
                    } else {
                        try writer.interface.writeAll(tls_output.items);
                        try writer.interface.flush();
                    }
                }
                if (received.event) |event| switch (event) {
                    .established => {
                        established_ready = true;
                        break;
                    },
                    .peer_alert => return error.TlsAlert,
                    else => {},
                };
                if (received.consumed == 0 and received.event == null) break;
            }
        }

        var response: [256]u8 = undefined;
        var offset: usize = 0;
        offset = try ntp.nts.records.writeRecord(&response, offset, true, ntp.nts.records.record_next_protocol, &.{ 0, 0 });
        offset = try ntp.nts.records.writeRecord(&response, offset, false, ntp.nts.records.record_aead, &.{ 0, 15 });
        offset = try ntp.nts.records.writeRecord(&response, offset, false, ntp.nts.records.record_new_cookie, &([_]u8{0x77} ** 16));
        offset = try ntp.nts.records.writeRecord(&response, offset, true, ntp.nts.records.record_end, &.{});

        var application_input: [4096]u8 = undefined;
        while (true) {
            const n = try readAvailableIntegration(&reader.interface, &application_input);
            if (n == 0) return error.ConnectionClosed;
            var app_offset: usize = 0;
            while (app_offset < n) {
                const received = try established.application.receive(application_input[app_offset..n]);
                app_offset += received.consumed;
                if (received.event) |event| switch (event) {
                    .application_data => {
                        var record: [4096]u8 = undefined;
                        const len = try established.application.sealApplicationData(response[0..offset], &record);
                        try writer.interface.writeAll(record[0..len]);
                        try writer.interface.flush();

                        var alert: [64]u8 = undefined;
                        const alert_len = established.application.sealCloseNotify(&alert) catch 0;
                        if (alert_len > 0) {
                            try writer.interface.writeAll(alert[0..alert_len]);
                            try writer.interface.flush();
                        }
                        return;
                    },
                    .alert => return error.TlsAlert,
                    else => {},
                };
                if (received.consumed == 0 and received.event == null) break;
            }
        }
    }
};

test "NTS-KE completes over a vail TLS 1.3 channel" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const key_pair = std.crypto.sign.Ed25519.KeyPair.generate(io);
    const spki = ed25519Spki(key_pair.public_key.toBytes());

    const listen_address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var listener = try std.Io.net.IpAddress.listen(&listen_address, io, .{ .mode = .stream });
    defer listener.deinit(io);

    var server_context = NtsKeTestServer{
        .io = undefined,
        .allocator = std.heap.page_allocator,
        .listener = &listener,
        .key_pair = key_pair,
        .spki = spki,
    };
    const server_thread = try std.Thread.spawn(.{}, NtsKeTestServer.threadMain, .{&server_context});

    const channel = try ntp.nts.vail.VailChannel.init(.{
        .allocator = std.testing.allocator,
        .io = io,
        .address = listener.socket.address,
        .server_name = "ntske-test",
        .verifier = .{ .pinned_raw_public_key = &spki },
        .server_certificate_type = .raw_public_key,
    });
    defer channel.deinit();

    var negotiation = try ntp.nts.ke.negotiate(channel.channel(), .{});
    defer negotiation.deinit();
    try std.testing.expectEqual(@as(usize, 1), negotiation.cookies.len());
    try std.testing.expectEqual(@as(u16, 15), negotiation.aead_id);

    server_thread.join();
    try server_context.result;
}
