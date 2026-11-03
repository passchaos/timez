//! NTS authenticator and encrypted-extension protection (RFC 8915 section 5.6).
//!
//! Only AEAD_AES_SIV_CMAC_256 (numeric identifier 15) is mandatory and
//! implemented here. AES-SIV is nonce-misuse resistant, which matches NTS's
//! cookie/ticket model.

const std = @import("std");
const packet = @import("../packet.zig");

pub const Aes128Siv = std.crypto.aead.aes_siv.Aes128Siv;

pub const ext_unique_id: u16 = 0x0104;
pub const ext_cookie: u16 = 0x0204;
pub const ext_cookie_placeholder: u16 = 0x0304;
pub const ext_authenticator: u16 = 0x0404;

pub const aead_aes_siv_cmac_256: u16 = 15;

pub const key_len = 32;
pub const nonce_len = 16;
pub const tag_len = 16;
pub const unique_id_len = 32;
pub const max_nonce_len = 16;

pub const Error = error{
    BadAuthenticator,
    AuthenticationFailed,
    NonceTooLong,
    BufferTooSmall,
    ExtensionTooLong,
    MissingPadding,
};

pub const Authenticator = struct {
    nonce: []const u8,
    ciphertext: []const u8,
    additional_padding_len: usize,
};

/// Seal `plaintext_extensions` under `key`, authenticating `associated_data`.
/// The authenticator extension is appended at `offset`; the new offset is
/// returned.
pub fn sealAuthenticator(
    buffer: []u8,
    offset: usize,
    key: *const [key_len]u8,
    plaintext_extensions: []const u8,
    associated_data: []const u8,
    nonce: *const [nonce_len]u8,
) Error!usize {
    const ciphertext_len = plaintext_extensions.len + tag_len;
    const padded_ciphertext_len = align4(ciphertext_len);
    const total_len = 4 + 4 + nonce_len + padded_ciphertext_len;
    if (total_len > std.math.maxInt(u16)) return error.ExtensionTooLong;
    if (buffer.len < offset + total_len) return error.BufferTooSmall;

    packet_put_u16(buffer, offset, ext_authenticator);
    packet_put_u16(buffer, offset + 2, @intCast(total_len));
    packet_put_u16(buffer, offset + 4, nonce_len);
    packet_put_u16(buffer, offset + 6, @intCast(ciphertext_len));

    const nonce_start = offset + 8;
    @memcpy(buffer[nonce_start .. nonce_start + nonce_len], nonce);

    const cipher_start = nonce_start + nonce_len;
    var tag: [tag_len]u8 = undefined;
    const encrypted = buffer[cipher_start + tag_len .. cipher_start + tag_len + plaintext_extensions.len];
    Aes128Siv.encrypt(
        encrypted,
        &tag,
        plaintext_extensions,
        associated_data,
        nonce,
        key.*,
    );
    @memcpy(buffer[cipher_start .. cipher_start + tag_len], &tag);
    @memset(buffer[cipher_start + ciphertext_len .. offset + total_len], 0);
    return offset + total_len;
}

/// Verify and decrypt an authenticator extension body. `value` excludes the
/// four-byte extension header. Plaintext extension fields are written to
/// `plaintext_out`, whose length must be at least `ciphertext_len - tag_len`.
pub fn openAuthenticator(
    value: []const u8,
    key: *const [key_len]u8,
    associated_data: []const u8,
    plaintext_out: []u8,
) Error![]const u8 {
    const parts = try parseAuthenticator(value);
    if (parts.ciphertext.len < tag_len) return error.BadAuthenticator;

    const encrypted_len = parts.ciphertext.len - tag_len;
    if (plaintext_out.len < encrypted_len) return error.BufferTooSmall;

    const tag: [tag_len]u8 = parts.ciphertext[0..tag_len].*;
    const encrypted = parts.ciphertext[tag_len..];
    Aes128Siv.decrypt(
        plaintext_out[0..encrypted_len],
        encrypted,
        tag,
        associated_data,
        parts.nonce,
        key.*,
    ) catch return error.AuthenticationFailed;

    return plaintext_out[0..encrypted_len];
}

pub fn parseAuthenticator(value: []const u8) Error!Authenticator {
    if (value.len < 4) return error.BadAuthenticator;
    const nonce_length = packet_get_u16(value, 0);
    const ciphertext_length = packet_get_u16(value, 2);
    if (nonce_length > max_nonce_len) return error.NonceTooLong;

    const padded_nonce_len = align4(nonce_length);
    const padded_ciphertext_len = align4(ciphertext_length);
    const required = 4 + padded_nonce_len + padded_ciphertext_len;
    if (value.len < required) return error.BadAuthenticator;

    const nonce_start: usize = 4;
    const cipher_start = nonce_start + padded_nonce_len;
    const nonce = value[nonce_start .. nonce_start + nonce_length];
    const ciphertext = value[cipher_start .. cipher_start + ciphertext_length];

    // Padding octets are required to be zero by RFC 7822's extension-field
    // conventions and RFC 8915's figure 4.
    for (value[nonce_start + nonce_length .. cipher_start]) |byte| {
        if (byte != 0) return error.BadAuthenticator;
    }
    for (value[cipher_start + ciphertext_length .. cipher_start + padded_ciphertext_len]) |byte| {
        if (byte != 0) return error.BadAuthenticator;
    }

    return .{
        .nonce = nonce,
        .ciphertext = ciphertext,
        .additional_padding_len = value.len - required,
    };
}

/// Enforce the RFC 8915 client additional-padding rule: a client nonce shorter
/// than 16 octets must be accompanied by enough zero padding that servers can
/// substitute a longer nonce without growing the packet.
pub fn checkClientPadding(auth: Authenticator) Error!void {
    const padded_nonce_len = align4(auth.nonce.len);
    const required_nonce_padding = 16 - padded_nonce_len;
    if (auth.additional_padding_len < required_nonce_padding) return error.MissingPadding;
}

fn align4(value: usize) usize {
    return (value + 3) & ~@as(usize, 3);
}

fn packet_get_u16(bytes: []const u8, offset: usize) u16 {
    return (@as(u16, bytes[offset]) << 8) | bytes[offset + 1];
}

fn packet_put_u16(bytes: []u8, offset: usize, value: u16) void {
    bytes[offset] = @truncate(value >> 8);
    bytes[offset + 1] = @truncate(value);
}

test "seal and open round-trip" {
    const key = [_]u8{0x42} ** key_len;
    const nonce = [_]u8{0x11} ** nonce_len;
    const plaintext = "cookie-extension-data";
    const ad = "ntp header and preceding extensions";

    var buffer: [256]u8 = undefined;
    const offset = try sealAuthenticator(&buffer, 0, &key, plaintext, ad, &nonce);
    try std.testing.expect(offset >= 40);

    const value = buffer[4..offset];
    var output: [128]u8 = undefined;
    const opened = try openAuthenticator(value, &key, ad, &output);
    try std.testing.expectEqualSlices(u8, plaintext, opened);
}

test "tampering fails authentication" {
    const key = [_]u8{0x42} ** key_len;
    const nonce = [_]u8{0x11} ** nonce_len;
    const ad = "associated";
    var buffer: [128]u8 = undefined;
    const offset = try sealAuthenticator(&buffer, 0, &key, "hello", ad, &nonce);

    // Flip one ciphertext byte.
    buffer[4 + 4 + nonce_len + 4] ^= 0x01;
    var output: [64]u8 = undefined;
    try std.testing.expectError(
        error.AuthenticationFailed,
        openAuthenticator(buffer[4..offset], &key, ad, &output),
    );
}

test "wrong associated data fails authentication" {
    const key = [_]u8{0x42} ** key_len;
    const nonce = [_]u8{0x11} ** nonce_len;
    var buffer: [128]u8 = undefined;
    const offset = try sealAuthenticator(&buffer, 0, &key, "", "ad-one", &nonce);
    var output: [64]u8 = undefined;
    try std.testing.expectError(
        error.AuthenticationFailed,
        openAuthenticator(buffer[4..offset], &key, "ad-two", &output),
    );
}

test "malformed authenticator is rejected" {
    var value = [_]u8{0} ** 8;
    packet_put_u16(&value, 0, 32);
    packet_put_u16(&value, 2, 16);
    try std.testing.expectError(error.NonceTooLong, parseAuthenticator(&value));

    packet_put_u16(&value, 0, 16);
    packet_put_u16(&value, 2, 20);
    try std.testing.expectError(error.BadAuthenticator, parseAuthenticator(&value));
}

test "client padding rule" {
    const auth: Authenticator = .{
        .nonce = &[_]u8{0} ** 8,
        .ciphertext = &[_]u8{0} ** 16,
        .additional_padding_len = 0,
    };
    try std.testing.expectError(error.MissingPadding, checkClientPadding(auth));
    var padded = auth;
    padded.additional_padding_len = 8;
    try checkClientPadding(padded);
}
