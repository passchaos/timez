//! NTS-protected NTP client and server sessions.
//!
//! A client session owns the negotiated AEAD keys and cookie jar. It wraps
//! outgoing NTP packets in Unique Identifier, Cookie, Cookie Placeholder, and
//! Authenticator extension fields, and verifies/decrypts responses. A server
//! session recovers keys from opaque cookies and emits encrypted replacement
//! cookies.

const std = @import("std");
const clock = @import("../../clock/mod.zig");
const packet = @import("../packet.zig");
const timestamp = @import("../timestamp.zig");
const aead = @import("aead.zig");
const cookie = @import("cookie.zig");
const keys = @import("keys.zig");

pub const max_plaintext_extensions = 2048;
pub const max_uid_len = 64;
pub const default_placeholder_count = 1;

pub const Error = packet.ParseError || aead.Error || cookie.Error || error{
    NoCookie,
    NotNtsProtected,
    MissingUniqueId,
    UniqueIdMismatch,
    NotServerResponse,
    NotClientRequest,
    InvalidExtension,
    BufferTooSmall,
    ExtensionTooLong,
    CookieTooLarge,
};

pub const ClientSession = struct {
    io: std.Io,
    key_material: keys.KeyMaterial,
    cookies: cookie.Jar,
    aead_id: u16 = aead.aead_aes_siv_cmac_256,
    placeholder_count: usize = default_placeholder_count,
    last_unique_id: ?[aead.unique_id_len]u8 = null,
    plaintext: [max_plaintext_extensions]u8 = undefined,

    pub fn init(
        io: std.Io,
        key_material: keys.KeyMaterial,
        cookies: cookie.Jar,
    ) ClientSession {
        return .{
            .io = io,
            .key_material = key_material,
            .cookies = cookies,
        };
    }

    pub fn deinit(self: *ClientSession) void {
        self.key_material.deinit();
        self.cookies.reset();
    }

    /// Protect an NTP client request. The packet header is written first, then
    /// the authenticated Unique Identifier, Cookie, Cookie Placeholder(s), and
    /// Authenticator extension fields.
    pub fn protectRequest(self: *ClientSession, request: *const packet.Packet, output: []u8) Error!usize {
        const cookie_value = self.cookies.take() orelse return error.NoCookie;

        var unique_id: [aead.unique_id_len]u8 = undefined;
        self.io.random(&unique_id);
        self.last_unique_id = unique_id;

        var offset = try request.write(output);
        offset = try packet.writeExtension(output, offset, aead.ext_unique_id, &unique_id);
        offset = try packet.writeExtension(output, offset, aead.ext_cookie, cookie_value);

        var zeros: [cookie.max_cookie_len]u8 = @splat(0);
        var i: usize = 0;
        while (i < self.placeholder_count) : (i += 1) {
            offset = try packet.writeExtension(
                output,
                offset,
                aead.ext_cookie_placeholder,
                zeros[0..cookie_value.len],
            );
        }

        const associated_data = output[0..offset];
        var nonce: [aead.nonce_len]u8 = undefined;
        self.io.random(&nonce);
        offset = try aead.sealAuthenticator(
            output,
            offset,
            &self.key_material.c2s,
            &.{},
            associated_data,
            &nonce,
        );
        return offset;
    }

    /// Verify and decrypt an NTS response. New cookies carried inside the
    /// authenticator are added to the jar. Returns the parsed protected packet
    /// so the caller can apply the ordinary NTP response checks.
    pub fn unprotectResponse(self: *ClientSession, bytes: []const u8) Error!packet.Parsed {
        const parsed = try packet.parse(bytes);
        if (parsed.packet.mode != .server) return error.NotServerResponse;

        const unique_id_entry = findExtension(parsed, aead.ext_unique_id) orelse
            return error.NotNtsProtected;
        const authenticator_entry = findExtension(parsed, aead.ext_authenticator) orelse
            return error.NotNtsProtected;

        const expected = self.last_unique_id orelse return error.UniqueIdMismatch;
        if (unique_id_entry.value.len != aead.unique_id_len or
            !std.mem.eql(u8, unique_id_entry.value, &expected))
        {
            return error.UniqueIdMismatch;
        }

        const associated_data = bytes[0..authenticator_entry.offset];
        const opened = try aead.openAuthenticator(
            authenticator_entry.value,
            &self.key_material.s2c,
            associated_data,
            &self.plaintext,
        );

        // Server cookies must be inside the authenticated ciphertext, but
        // accept authenticated plaintext cookies as well.
        for (parsed.extensions[0..parsed.extension_count]) |extension| {
            if (extension.offset >= authenticator_entry.offset) break;
            if (extension.kind == aead.ext_cookie) try self.cookies.add(extension.value);
        }
        try self.parseEncryptedExtensions(opened);

        self.last_unique_id = null;
        return parsed;
    }

    /// Detect an unprotected NTS NAK (KoD "NTSN") whose Unique Identifier
    /// matches the outstanding request.
    pub fn isNtsNak(self: *ClientSession, bytes: []const u8) bool {
        const parsed = packet.parse(bytes) catch return false;
        if (parsed.packet.mode != .server or parsed.packet.stratum != 0) return false;
        const code = parsed.packet.kissCode() orelse return false;
        if (!std.mem.eql(u8, &code, "NTSN")) return false;
        const unique_id_entry = findExtension(parsed, aead.ext_unique_id) orelse return false;
        const expected = self.last_unique_id orelse return false;
        return unique_id_entry.value.len == aead.unique_id_len and
            std.mem.eql(u8, unique_id_entry.value, &expected);
    }

    fn parseEncryptedExtensions(self: *ClientSession, bytes: []const u8) Error!void {
        if (bytes.len == 0) return;
        if (bytes.len % 4 != 0) return error.InvalidExtension;
        var offset: usize = 0;
        while (offset < bytes.len) {
            if (bytes.len - offset < 4) return error.InvalidExtension;
            const kind = readU16(bytes, offset);
            const length = readU16(bytes, offset + 2);
            if (length < 4 or length % 4 != 0 or length > bytes.len - offset) {
                return error.InvalidExtension;
            }
            if (kind == aead.ext_cookie) {
                try self.cookies.add(bytes[offset + 4 .. offset + length]);
            }
            offset += length;
        }
    }
};

pub const VerifiedRequest = struct {
    key_material: keys.KeyMaterial,
    unique_id: []const u8,
    placeholder_count: usize,
    parsed: packet.Parsed,

    pub fn deinit(self: *VerifiedRequest) void {
        self.key_material.deinit();
    }
};

pub const ServerSession = struct {
    io: std.Io,
    cookie_keys: cookie.KeyRing,
    plaintext: [max_plaintext_extensions]u8 = undefined,

    pub fn init(io: std.Io, cookie_keys: cookie.KeyRing) ServerSession {
        return .{ .io = io, .cookie_keys = cookie_keys };
    }

    /// Authenticate a client request and recover its keys from the cookie.
    pub fn verifyRequest(self: *ServerSession, bytes: []const u8) Error!VerifiedRequest {
        const parsed = try packet.parse(bytes);
        if (parsed.packet.mode != .client) return error.NotClientRequest;

        const unique_id_entry = findExtension(parsed, aead.ext_unique_id) orelse
            return error.MissingUniqueId;
        if (unique_id_entry.value.len < 32 or unique_id_entry.value.len > max_uid_len) {
            return error.InvalidExtension;
        }
        const cookie_entry = findExtension(parsed, aead.ext_cookie) orelse
            return error.NotNtsProtected;
        const authenticator_entry = findExtension(parsed, aead.ext_authenticator) orelse
            return error.NotNtsProtected;

        const key_material = try self.cookie_keys.decode(cookie_entry.value);

        const associated_data = bytes[0..authenticator_entry.offset];
        const authenticator = try aead.parseAuthenticator(authenticator_entry.value);
        try aead.checkClientPadding(authenticator);
        const opened = aead.openAuthenticator(
            authenticator_entry.value,
            &key_material.c2s,
            associated_data,
            &self.plaintext,
        ) catch |err| {
            var material = key_material;
            material.deinit();
            return err;
        };

        if (opened.len != 0) {
            if (opened.len % 4 != 0) {
                var material = key_material;
                material.deinit();
                return error.InvalidExtension;
            }
            // Encrypted extension fields are allowed; validate their framing.
            var offset: usize = 0;
            while (offset < opened.len) {
                if (opened.len - offset < 4) {
                    var material = key_material;
                    material.deinit();
                    return error.InvalidExtension;
                }
                const length = readU16(opened, offset + 2);
                if (length < 4 or length % 4 != 0 or length > opened.len - offset) {
                    var material = key_material;
                    material.deinit();
                    return error.InvalidExtension;
                }
                offset += length;
            }
        }

        var placeholders: usize = 0;
        for (parsed.extensions[0..parsed.extension_count]) |extension| {
            if (extension.kind == aead.ext_cookie_placeholder) placeholders += 1;
        }

        return .{
            .key_material = key_material,
            .unique_id = unique_id_entry.value,
            .placeholder_count = placeholders,
            .parsed = parsed,
        };
    }

    /// Build an NTS-protected response. `cookie_count` new cookies are created
    /// and encrypted under the S2C key. The response packet header is written
    /// first, followed by the echoed Unique Identifier.
    pub fn protectResponse(
        self: *ServerSession,
        response: *const packet.Packet,
        unique_id: []const u8,
        key_material: *const keys.KeyMaterial,
        cookie_count: usize,
        output: []u8,
    ) Error!usize {
        var offset = try response.write(output);
        offset = try packet.writeExtension(output, offset, aead.ext_unique_id, unique_id);

        var plaintext: [max_plaintext_extensions]u8 = undefined;
        var plaintext_len: usize = 0;
        var cookie_buffer: [cookie.max_cookie_len]u8 = undefined;
        var i: usize = 0;
        while (i < cookie_count) : (i += 1) {
            const value = try self.cookie_keys.encode(&cookie_buffer, key_material.*);
            plaintext_len = try packet.writeExtension(
                &plaintext,
                plaintext_len,
                aead.ext_cookie,
                value,
            );
        }

        const associated_data = output[0..offset];
        var nonce: [aead.nonce_len]u8 = undefined;
        self.io.random(&nonce);
        offset = try aead.sealAuthenticator(
            output,
            offset,
            &key_material.s2c,
            plaintext[0..plaintext_len],
            associated_data,
            &nonce,
        );
        return offset;
    }

    /// Append the echoed Unique Identifier to an unprotected NTS NAK packet.
    pub fn appendUniqueId(self: *ServerSession, request_bytes: []const u8, output: []u8, offset: usize) Error!usize {
        _ = self;
        const parsed = packet.parse(request_bytes) catch return offset;
        const unique_id_entry = findExtension(parsed, aead.ext_unique_id) orelse return offset;
        return packet.writeExtension(output, offset, aead.ext_unique_id, unique_id_entry.value);
    }
};

fn findExtension(parsed: packet.Parsed, kind: u16) ?packet.Extension {
    for (parsed.extensions[0..parsed.extension_count]) |extension| {
        if (extension.kind == kind) return extension;
    }
    return null;
}

fn readU16(bytes: []const u8, offset: usize) u16 {
    return (@as(u16, bytes[offset]) << 8) | bytes[offset + 1];
}

const TestClock = struct {
    utc: clock.Timestamp,
    mono: clock.Duration,

    pub fn nowSnapshot(self: *TestClock) clock.Error!clock.Snapshot {
        const leap: clock.LeapSeconds = .{};
        return .{
            .monotonic = self.mono,
            .utc = self.utc,
            .tai = leap.utcToTai(self.utc),
            .synchronized = true,
        };
    }
};

test "client and server sessions round-trip" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const key_material: keys.KeyMaterial = .{
        .c2s = [_]u8{0x01} ** 32,
        .s2c = [_]u8{0x02} ** 32,
    };
    const codec = cookie.Codec.init(io, 7, [_]u8{0x33} ** 32);
    const cookie_keys = cookie.KeyRing{ .current = codec };

    // Server issues one initial cookie through the cookie codec.
    var initial_cookie_buffer: [cookie.max_cookie_len]u8 = undefined;
    const initial_cookie = try codec.encode(&initial_cookie_buffer, key_material);

    var jar = cookie.Jar{};
    try jar.add(initial_cookie);
    var client = ClientSession.init(io, key_material, jar);
    defer client.deinit();

    const request: packet.Packet = .{
        .version = .v4,
        .mode = .client,
        .transmit_timestamp = timestamp.NtpTimestamp.fromTimestamp(clock.Timestamp.fromSeconds(1_700_000_000)),
    };
    var request_buffer: [1024]u8 = undefined;
    const request_len = try client.protectRequest(&request, &request_buffer);

    var server = ServerSession.init(io, cookie_keys);
    var verified = try server.verifyRequest(request_buffer[0..request_len]);
    defer verified.deinit();

    try std.testing.expectEqual(@as(usize, 1), verified.placeholder_count);
    try std.testing.expectEqual(aead.unique_id_len, verified.unique_id.len);

    const server_clock: TestClock = .{
        .utc = clock.Timestamp.fromSeconds(1_700_000_001),
        .mono = .zero,
    };
    const response_packet: packet.Packet = .{
        .leap = .no_warning,
        .version = .v4,
        .mode = .server,
        .stratum = 1,
        .origin_timestamp = request.transmit_timestamp,
        .receive_timestamp = timestamp.NtpTimestamp.fromTimestamp(server_clock.utc),
        .transmit_timestamp = timestamp.NtpTimestamp.fromTimestamp(server_clock.utc),
    };
    var response_buffer: [2048]u8 = undefined;
    const response_len = try server.protectResponse(
        &response_packet,
        verified.unique_id,
        &verified.key_material,
        1,
        &response_buffer,
    );

    const parsed = try client.unprotectResponse(response_buffer[0..response_len]);
    try std.testing.expectEqual(packet.Mode.server, parsed.packet.mode);
    try std.testing.expectEqual(@as(usize, 1), client.cookies.len());
}

test "client rejects replayed and tampered responses" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const key_material: keys.KeyMaterial = .{
        .c2s = [_]u8{0x01} ** 32,
        .s2c = [_]u8{0x02} ** 32,
    };
    const codec = cookie.Codec.init(io, 7, [_]u8{0x33} ** 32);
    var jar = cookie.Jar{};
    var initial_cookie_buffer: [cookie.max_cookie_len]u8 = undefined;
    const initial_cookie = try codec.encode(&initial_cookie_buffer, key_material);
    try jar.add(initial_cookie);
    var client = ClientSession.init(io, key_material, jar);
    defer client.deinit();

    const request: packet.Packet = .{ .version = .v4, .mode = .client };
    var request_buffer: [1024]u8 = undefined;
    _ = try client.protectRequest(&request, &request_buffer);

    var response_buffer: [2048]u8 = undefined;
    const response_packet: packet.Packet = .{
        .version = .v4,
        .mode = .server,
        .stratum = 1,
        .origin_timestamp = request.transmit_timestamp,
    };
    var server = ServerSession.init(io, .{ .current = codec });
    const response_len = try server.protectResponse(
        &response_packet,
        client.last_unique_id.?[0..],
        &key_material,
        1,
        &response_buffer,
    );

    const saved = response_buffer[108];
    response_buffer[108] ^= 1; // first byte of the authentication tag
    try std.testing.expectError(
        error.AuthenticationFailed,
        client.unprotectResponse(response_buffer[0..response_len]),
    );
    response_buffer[108] = saved;

    // A second use of the same response must fail the outstanding-ID check.
    const parsed = try client.unprotectResponse(response_buffer[0..response_len]);
    _ = parsed;
    try std.testing.expectError(error.UniqueIdMismatch, client.unprotectResponse(response_buffer[0..response_len]));
}

test "server rejects a client without an authenticator" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const codec = cookie.Codec.init(io, 7, [_]u8{0x33} ** 32);
    var server = ServerSession.init(io, .{ .current = codec });

    var buffer: [128]u8 = undefined;
    const request: packet.Packet = .{ .version = .v4, .mode = .client };
    var offset = try request.write(&buffer);
    offset = try packet.writeExtension(&buffer, offset, aead.ext_unique_id, &([_]u8{0x11} ** aead.unique_id_len));
    try std.testing.expectError(error.NotNtsProtected, server.verifyRequest(buffer[0..offset]));
}
