//! `vail` TLS 1.3 adapter for NTS-KE.
//!
//! `VailChannel` drives vail's incremental TLS 1.3 client state machine over a
//! TCP stream and exposes the `ke.Channel` interface: application-data send,
//! receive, close, and RFC 8446 exporter. The caller supplies the server
//! identity verifier (pinned key, trust callback, or a system-root-backed
//! verifier built outside this module).

const std = @import("std");
const vail = @import("vail");
const ke = @import("ke.zig");

pub const TlsClient = vail.tls.client_connection.ClientConnection(64 * 1024, 4096);
pub const ClientVerifier = vail.tls.auth.ClientVerifier;
pub const ClientKeyMaterial = vail.tls.key_exchange.ClientKeyMaterial;

pub const Error = error{
    ConnectionClosed,
    NotEstablished,
    BufferTooSmall,
    TlsAlert,
    TlsFailure,
    Timeout,
};

pub const Config = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    address: std.Io.net.IpAddress,
    server_name: []const u8,
    verifier: ClientVerifier,
    server_certificate_type: vail.tls.auth.CertificateType = .x509,
    connect_timeout: std.Io.Timeout = .none,
    /// Optional caller-supplied X25519 secret. If null, one is generated from
    /// `io.random`.
    secret: ?[32]u8 = null,
};

pub const VailChannel = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    reader_buffer: [4096]u8 = undefined,
    reader: std.Io.net.Stream.Reader = undefined,
    writer_buffer: [4096]u8 = undefined,
    writer: std.Io.net.Stream.Writer = undefined,
    tls: TlsClient = undefined,
    tls_output: std.ArrayList(u8) = .empty,
    established: TlsClient.Established = undefined,
    established_ready: bool = false,
    tls_initialized: bool = false,
    pending: [4096]u8 = undefined,
    pending_len: usize = 0,
    closed: bool = false,

    pub fn init(config: Config) !*VailChannel {
        const self = try config.allocator.create(VailChannel);
        errdefer config.allocator.destroy(self);
        self.* = .{
            .allocator = config.allocator,
            .io = config.io,
            .stream = undefined,
        };
        self.tls_output = .empty;

        self.stream = try std.Io.net.IpAddress.connect(&config.address, config.io, .{
            .mode = .stream,
            .timeout = config.connect_timeout,
        });
        errdefer {
            if (self.established_ready) self.established.deinit();
            if (self.tls_initialized) self.tls.deinit();
            self.tls_output.deinit(self.allocator);
            self.stream.close(self.io);
        }

        self.reader = self.stream.reader(config.io, &self.reader_buffer);
        self.writer = self.stream.writer(config.io, &self.writer_buffer);

        var secret: [32]u8 = undefined;
        if (config.secret) |provided| {
            secret = provided;
        } else {
            config.io.random(&secret);
        }
        var material = ClientKeyMaterial{ .x25519 = secret };
        var random: [32]u8 = undefined;
        config.io.random(&random);

        try self.tls.initInto(.{
            .allocator = config.allocator,
            .random = random,
            .server_name = config.server_name,
            .key_material = &material,
            .alpn_protocols = &.{"ntske/1"},
            .server_verifier = config.verifier,
            .server_certificate_type = config.server_certificate_type,
            .request_ocsp = false,
        }, &self.tls_output);
        self.tls_initialized = true;

        try self.sendRaw(self.tls_output.items);
        self.tls_output.clearRetainingCapacity();

        try self.handshake();
        return self;
    }

    fn handshake(self: *VailChannel) !void {
        var input: [4096]u8 = undefined;
        while (!self.established_ready) {
            const n = try readAvailable(&self.reader.interface, &input);
            if (n == 0) return error.ConnectionClosed;

            var remaining = input[0..n];
            while (remaining.len > 0) {
                self.tls_output.clearRetainingCapacity();
                const result = try self.tls.receiveInto(remaining, &self.tls_output, &self.established);
                remaining = remaining[result.consumed..];

                if (self.tls_output.items.len > 0) {
                    try self.sendRaw(self.tls_output.items);
                    self.tls_output.clearRetainingCapacity();
                }

                if (result.event) |event| switch (event) {
                    .established => {
                        self.established_ready = true;
                        return;
                    },
                    .peer_alert, .ech_rejected => return error.TlsAlert,
                    else => {},
                };

                if (result.consumed == 0 and result.event == null) break;
            }
        }
    }

    fn sendRaw(self: *VailChannel, bytes: []const u8) !void {
        try self.writer.interface.writeAll(bytes);
        try self.writer.interface.flush();
    }

    pub fn send(self: *VailChannel, bytes: []const u8) !void {
        if (!self.established_ready) return error.NotEstablished;
        var record: [8192]u8 = undefined;
        const len = try self.established.application.sealApplicationData(bytes, &record);
        try self.sendRaw(record[0..len]);
    }

    pub fn receive(self: *VailChannel, buffer: []u8) !usize {
        if (!self.established_ready) return error.NotEstablished;

        while (true) {
            var input: [4096]u8 = undefined;
            var input_len: usize = self.pending_len;
            if (input_len > 0) {
                @memcpy(input[0..input_len], self.pending[0..input_len]);
                self.pending_len = 0;
            } else {
                input_len = try readAvailable(&self.reader.interface, &input);
                if (input_len == 0) return error.ConnectionClosed;
            }

            var offset: usize = 0;
            while (offset < input_len) {
                const result = try self.established.application.receive(input[offset..input_len]);
                offset += result.consumed;

                if (result.event) |event| switch (event) {
                    .application_data => |data| {
                        if (data.len > buffer.len) return error.BufferTooSmall;
                        @memcpy(buffer[0..data.len], data);
                        if (offset < input_len) {
                            const remaining = input_len - offset;
                            @memcpy(self.pending[0..remaining], input[offset..input_len]);
                            self.pending_len = remaining;
                        }
                        return data.len;
                    },
                    .key_update => {
                        var response: [4096]u8 = undefined;
                        const len = self.established.application.sealKeyUpdateResponse(&response) catch |err| switch (err) {
                            error.NoKeyUpdateResponsePending => 0,
                            else => return err,
                        };
                        if (len > 0) try self.sendRaw(response[0..len]);
                    },
                    .post_handshake => {},
                    .alert => return error.TlsAlert,
                };

                if (result.consumed == 0 and result.event == null) break;
            }

            if (offset < input_len) {
                const remaining = input_len - offset;
                @memcpy(self.pending[0..remaining], input[offset..input_len]);
                self.pending_len = remaining;
            }
        }
    }

    pub fn exportKeyingMaterial(
        self: *VailChannel,
        label: []const u8,
        context: []const u8,
        output: []u8,
    ) !void {
        if (!self.established_ready) return error.NotEstablished;
        return self.established.exportKeyingMaterial(label, context, output);
    }

    pub fn close(self: *VailChannel) void {
        if (self.closed) return;
        self.closed = true;
        if (self.established_ready) {
            var alert: [4096]u8 = undefined;
            const len = self.established.application.sealCloseNotify(&alert) catch 0;
            if (len > 0) self.sendRaw(alert[0..len]) catch {};
        }
        self.stream.close(self.io);
    }

    pub fn deinit(self: *VailChannel) void {
        self.close();
        if (self.established_ready) self.established.deinit();
        self.tls.deinit();
        self.tls_output.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn channel(self: *VailChannel) ke.Channel {
        const Adapter = struct {
            fn send(ctx: *anyopaque, bytes: []const u8) anyerror!void {
                const ptr: *VailChannel = @ptrCast(@alignCast(ctx));
                return ptr.send(bytes);
            }
            fn receive(ctx: *anyopaque, buffer: []u8) anyerror!usize {
                const ptr: *VailChannel = @ptrCast(@alignCast(ctx));
                return ptr.receive(buffer);
            }
            fn exportKeyingMaterial(ctx: *anyopaque, label: []const u8, context: []const u8, output: []u8) anyerror!void {
                const ptr: *VailChannel = @ptrCast(@alignCast(ctx));
                return ptr.exportKeyingMaterial(label, context, output);
            }
            fn close(ctx: *anyopaque) void {
                const ptr: *VailChannel = @ptrCast(@alignCast(ctx));
                ptr.close();
            }
        };
        return .{
            .ctx = self,
            .vtable = &.{
                .send = Adapter.send,
                .receive = Adapter.receive,
                .export_keying_material = Adapter.exportKeyingMaterial,
                .close = Adapter.close,
            },
        };
    }
};

fn readAvailable(reader: *std.Io.Reader, buffer: []u8) !usize {
    var data = [1][]u8{buffer};
    return reader.readVec(&data) catch |err| switch (err) {
        error.EndOfStream => 0,
        else => return err,
    };
}

test "vail channel compiles against the NTS-KE interface" {
    // A full handshake needs a TLS server. The protocol layer is exercised by
    // the mock-channel NTS-KE tests; this test keeps the adapter type-checked.
    std.testing.refAllDecls(VailChannel);
}
