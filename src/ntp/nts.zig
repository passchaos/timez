//! RFC 8915 Network Time Security.
//!
//! - `records`: NTS-KE record codec.
//! - `keys`: TLS exporter key derivation.
//! - `ke`: TLS-agnostic NTS-KE client negotiation.
//! - `aead`: AES-SIV-CMAC-256 authenticator extension protection.
//! - `cookie`: opaque cookie jar and server cookie codec.
//! - `session`: NTS-protected NTP client and server sessions.
//!
//! NTPv4 autokey is intentionally not implemented.

const std = @import("std");

pub const records = @import("nts/records.zig");
pub const keys = @import("nts/keys.zig");
pub const ke = @import("nts/ke.zig");
pub const aead = @import("nts/aead.zig");
pub const cookie = @import("nts/cookie.zig");
pub const session = @import("nts/session.zig");

pub const Channel = ke.Channel;
pub const Negotiation = ke.Negotiation;
pub const KeyMaterial = keys.KeyMaterial;
pub const CookieJar = cookie.Jar;
pub const CookieCodec = cookie.Codec;
pub const CookieKeyRing = cookie.KeyRing;
pub const ClientSession = session.ClientSession;
pub const ServerSession = session.ServerSession;
pub const VerifiedRequest = session.VerifiedRequest;
pub const ext_unique_id = aead.ext_unique_id;
pub const ext_cookie = aead.ext_cookie;
pub const ext_cookie_placeholder = aead.ext_cookie_placeholder;
pub const ext_authenticator = aead.ext_authenticator;

test {
    std.testing.refAllDecls(@This());
    _ = records;
    _ = keys;
    _ = ke;
    _ = aead;
    _ = cookie;
    _ = session;
}
