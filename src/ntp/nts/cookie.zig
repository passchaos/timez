//! NTS cookie storage and server cookie codec.
//!
//! The cookie format is implementation-defined by RFC 8915. `timez` uses the
//! suggested `(I, N, C)` construction: a 32-bit key identifier, a random
//! 128-bit nonce, and AES-SIV-CMAC-256 ciphertext containing the negotiated
//! AEAD identifier plus the C2S and S2C keys. Cookies are opaque to clients.

const std = @import("std");
const keys_mod = @import("keys.zig");
const records = @import("records.zig");

pub const Aes128Siv = std.crypto.aead.aes_siv.Aes128Siv;

pub const key_id_len = 4;
pub const nonce_len = 16;
pub const tag_len = 16;
pub const plaintext_len = 68;
pub const cookie_len = key_id_len + nonce_len + tag_len + plaintext_len; // 104

pub const max_cookie_len = 192;
pub const jar_capacity = 8;

pub const Error = error{
    CookieTooLarge,
    CookieTooShort,
    UnknownCookieKey,
    BadCookie,
    AuthenticationFailed,
    BufferTooSmall,
};

/// A single server cookie key. `key_id` must identify `key` so that rotated
/// keys can coexist during a transition.
pub const Codec = struct {
    io: std.Io,
    key_id: u32,
    key: [32]u8,

    pub fn init(io: std.Io, key_id: u32, key: [32]u8) Codec {
        return .{ .io = io, .key_id = key_id, .key = key };
    }

    pub fn encode(self: *const Codec, buffer: []u8, key_material: keys_mod.KeyMaterial) Error![]const u8 {
        if (buffer.len < cookie_len) return error.BufferTooSmall;

        var nonce: [nonce_len]u8 = undefined;
        self.io.random(&nonce);

        var plaintext: [plaintext_len]u8 = undefined;
        plaintext[0] = 1; // cookie format version
        plaintext[1] = 0; // AEAD identifier high byte
        plaintext[2] = records.aead_aes_siv_cmac_256;
        @memcpy(plaintext[3 .. 3 + keys_mod.key_len], &key_material.c2s);
        @memcpy(plaintext[3 + keys_mod.key_len .. 3 + 2 * keys_mod.key_len], &key_material.s2c);
        plaintext[3 + 2 * keys_mod.key_len] = 0; // padding

        writeU32(buffer, 0, self.key_id);
        @memcpy(buffer[key_id_len .. key_id_len + nonce_len], &nonce);

        const cipher_start = key_id_len + nonce_len;
        var tag: [tag_len]u8 = undefined;
        var encrypted: [plaintext_len]u8 = undefined;
        Aes128Siv.encrypt(&encrypted, &tag, &plaintext, null, &nonce, self.key);
        @memcpy(buffer[cipher_start .. cipher_start + tag_len], &tag);
        @memcpy(buffer[cipher_start + tag_len .. cookie_len], &encrypted);

        std.crypto.secureZero(u8, &plaintext);
        std.crypto.secureZero(u8, &encrypted);
        return buffer[0..cookie_len];
    }

    pub fn decode(self: *const Codec, cookie: []const u8) Error!keys_mod.KeyMaterial {
        if (cookie.len < cookie_len) return error.CookieTooShort;
        if (cookie.len > max_cookie_len) return error.CookieTooLarge;
        if (readU32(cookie, 0) != self.key_id) return error.UnknownCookieKey;
        if (cookie.len != cookie_len) return error.BadCookie;

        const nonce = cookie[key_id_len .. key_id_len + nonce_len];
        const cipher_start = key_id_len + nonce_len;
        const tag: [tag_len]u8 = cookie[cipher_start .. cipher_start + tag_len].*;
        const encrypted = cookie[cipher_start + tag_len .. cookie_len];

        var plaintext: [plaintext_len]u8 = undefined;
        Aes128Siv.decrypt(&plaintext, encrypted, tag, null, nonce, self.key) catch {
            return error.AuthenticationFailed;
        };
        defer std.crypto.secureZero(u8, &plaintext);

        if (plaintext[0] != 1) return error.BadCookie;
        const aead_id = (@as(u16, plaintext[1]) << 8) | plaintext[2];
        if (aead_id != records.aead_aes_siv_cmac_256) return error.BadCookie;

        return .{
            .c2s = plaintext[3 .. 3 + keys_mod.key_len].*,
            .s2c = plaintext[3 + keys_mod.key_len .. 3 + 2 * keys_mod.key_len].*,
        };
    }
};

/// Rotating cookie keys. New cookies use `current`; `previous` is accepted
/// during a rotation window.
pub const KeyRing = struct {
    current: Codec,
    previous: ?Codec = null,

    pub fn encode(self: *const KeyRing, buffer: []u8, key_material: keys_mod.KeyMaterial) Error![]const u8 {
        return self.current.encode(buffer, key_material);
    }

    pub fn decode(self: *const KeyRing, cookie: []const u8) Error!keys_mod.KeyMaterial {
        if (cookie.len < key_id_len) return error.CookieTooShort;
        const id = readU32(cookie, 0);
        if (id == self.current.key_id) return self.current.decode(cookie);
        if (self.previous) |previous| {
            if (id == previous.key_id) return previous.decode(cookie);
        }
        return error.UnknownCookieKey;
    }
};

/// Fixed-capacity FIFO of opaque client cookies.
pub const Jar = struct {
    storage: [jar_capacity][max_cookie_len]u8 = undefined,
    lengths: [jar_capacity]usize = @splat(0),
    head: usize = 0,
    count: usize = 0,

    pub fn reset(self: *Jar) void {
        self.head = 0;
        self.count = 0;
        for (&self.lengths) |*length| length.* = 0;
    }

    pub fn len(self: *const Jar) usize {
        return self.count;
    }

    pub fn add(self: *Jar, cookie: []const u8) Error!void {
        if (cookie.len > max_cookie_len) return error.CookieTooLarge;
        if (self.count == jar_capacity) {
            @memcpy(self.storage[self.head][0..cookie.len], cookie);
            self.lengths[self.head] = cookie.len;
            self.head = (self.head + 1) % jar_capacity;
            return;
        }
        const slot = (self.head + self.count) % jar_capacity;
        @memcpy(self.storage[slot][0..cookie.len], cookie);
        self.lengths[slot] = cookie.len;
        self.count += 1;
    }

    /// Remove and return the oldest cookie. The slice remains valid until the
    /// next mutation of the jar.
    pub fn take(self: *Jar) ?[]const u8 {
        if (self.count == 0) return null;
        const slot = self.head;
        const length = self.lengths[slot];
        self.head = (self.head + 1) % jar_capacity;
        self.count -= 1;
        return self.storage[slot][0..length];
    }

    pub fn peek(self: *const Jar) ?[]const u8 {
        if (self.count == 0) return null;
        return self.storage[self.head][0..self.lengths[self.head]];
    }
};

fn readU32(bytes: []const u8, offset: usize) u32 {
    return (@as(u32, bytes[offset]) << 24) |
        (@as(u32, bytes[offset + 1]) << 16) |
        (@as(u32, bytes[offset + 2]) << 8) |
        bytes[offset + 3];
}

fn writeU32(bytes: []u8, offset: usize, value: u32) void {
    bytes[offset] = @truncate(value >> 24);
    bytes[offset + 1] = @truncate(value >> 16);
    bytes[offset + 2] = @truncate(value >> 8);
    bytes[offset + 3] = @truncate(value);
}

test "cookie round-trip" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const codec = Codec.init(io, 0x11223344, [_]u8{0x5a} ** 32);
    const material: keys_mod.KeyMaterial = .{
        .c2s = [_]u8{0x01} ** 32,
        .s2c = [_]u8{0x02} ** 32,
    };

    var buffer: [max_cookie_len]u8 = undefined;
    const cookie = try codec.encode(&buffer, material);
    try std.testing.expectEqual(@as(usize, cookie_len), cookie.len);

    const recovered = try codec.decode(cookie);
    try std.testing.expect(material.eql(recovered));
}

test "cookie rejects unknown keys and tampering" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const codec = Codec.init(io, 7, [_]u8{0x5a} ** 32);
    const material: keys_mod.KeyMaterial = .{
        .c2s = [_]u8{0x01} ** 32,
        .s2c = [_]u8{0x02} ** 32,
    };
    var buffer: [max_cookie_len]u8 = undefined;
    const cookie = try codec.encode(&buffer, material);

    const other = Codec.init(io, 8, [_]u8{0x5a} ** 32);
    try std.testing.expectError(error.UnknownCookieKey, other.decode(cookie));

    buffer[key_id_len + nonce_len + 4] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, codec.decode(buffer[0..cookie_len]));
}

test "cookie jar is FIFO and bounded" {
    var jar = Jar{};
    var i: u8 = 0;
    while (i < jar_capacity + 2) : (i += 1) {
        try jar.add(&[_]u8{i} ** 4);
    }
    try std.testing.expectEqual(@as(usize, jar_capacity), jar.len());
    try std.testing.expectEqualSlices(u8, &[_]u8{2} ** 4, jar.take().?);
    try std.testing.expectEqual(@as(usize, jar_capacity - 1), jar.len());
}

test "key ring accepts the previous key" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const old = Codec.init(io, 1, [_]u8{0x11} ** 32);
    const new = Codec.init(io, 2, [_]u8{0x22} ** 32);
    const ring = KeyRing{ .current = new, .previous = old };

    const material: keys_mod.KeyMaterial = .{
        .c2s = [_]u8{0x03} ** 32,
        .s2c = [_]u8{0x04} ** 32,
    };
    var old_buffer: [max_cookie_len]u8 = undefined;
    const old_cookie = try old.encode(&old_buffer, material);
    const recovered = try ring.decode(old_cookie);
    try std.testing.expect(material.eql(recovered));
}
