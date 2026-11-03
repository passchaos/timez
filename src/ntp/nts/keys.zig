//! NTS key extraction (RFC 8915 sections 4.3 and 5.1).
//!
//! The TLS exporter provides the input keying material. NTPv4 requires two
//! separate 256-bit keys with a five-octet context: two zero octets for the
//! protocol ID, the negotiated AEAD identifier, and a direction octet.

const std = @import("std");
const records = @import("records.zig");

pub const exporter_label = "EXPORTER-network-time-security";
pub const key_len = 32;

pub const KeyMaterial = struct {
    c2s: [key_len]u8,
    s2c: [key_len]u8,

    pub fn deinit(self: *KeyMaterial) void {
        std.crypto.secureZero(u8, &self.c2s);
        std.crypto.secureZero(u8, &self.s2c);
    }

    pub fn eql(a: KeyMaterial, b: KeyMaterial) bool {
        return std.crypto.timing_safe.eql([key_len]u8, a.c2s, b.c2s) and
            std.crypto.timing_safe.eql([key_len]u8, a.s2c, b.s2c);
    }
};

/// Type-erased TLS exporter. The adapter must implement RFC 8446 section 7.5
/// `exportKeyingMaterial`.
pub const Exporter = struct {
    ctx: *anyopaque,
    export_fn: *const fn (
        ctx: *anyopaque,
        label: []const u8,
        context: []const u8,
        output: []u8,
    ) anyerror!void,

    pub fn exportKeyingMaterial(
        self: Exporter,
        label: []const u8,
        context: []const u8,
        output: []u8,
    ) anyerror!void {
        return self.export_fn(self.ctx, label, context, output);
    }

    pub fn from(comptime T: type, ptr: *T) Exporter {
        const Adapter = struct {
            fn exportKeyingMaterial(
                ctx: *anyopaque,
                label: []const u8,
                context: []const u8,
                output: []u8,
            ) anyerror!void {
                const self: *T = @ptrCast(@alignCast(ctx));
                return self.exportKeyingMaterial(label, context, output);
            }
        };
        return .{
            .ctx = ptr,
            .export_fn = Adapter.exportKeyingMaterial,
        };
    }
};

pub const DeriveError = anyerror || error{
    UnsupportedAead,
};

/// Derive the C2S and S2C keys for NTPv4.
pub fn derive(exporter: Exporter, aead_id: u16) DeriveError!KeyMaterial {
    if (aead_id != records.aead_aes_siv_cmac_256) return error.UnsupportedAead;

    var keys = KeyMaterial{
        .c2s = undefined,
        .s2c = undefined,
    };

    const c2s_context = [5]u8{ 0, 0, @truncate(aead_id >> 8), @truncate(aead_id), 0 };
    const s2c_context = [5]u8{ 0, 0, @truncate(aead_id >> 8), @truncate(aead_id), 1 };

    try exporter.exportKeyingMaterial(exporter_label, &c2s_context, &keys.c2s);
    try exporter.exportKeyingMaterial(exporter_label, &s2c_context, &keys.s2c);
    return keys;
}

test "exporter contexts and key split" {
    const Mock = struct {
        calls: usize = 0,
        last_context: [5]u8 = undefined,

        pub fn exportKeyingMaterial(
            self: *@This(),
            label: []const u8,
            context: []const u8,
            output: []u8,
        ) !void {
            try std.testing.expectEqualStrings(exporter_label, label);
            try std.testing.expectEqual(@as(usize, 5), context.len);
            self.last_context = context[0..5].*;
            self.calls += 1;
            @memset(output, @truncate(self.calls));
        }
    };
    var mock = Mock{};
    const keys = try derive(Exporter.from(Mock, &mock), records.aead_aes_siv_cmac_256);
    try std.testing.expectEqual(@as(usize, 2), mock.calls);
    try std.testing.expectEqual(@as(u8, 1), keys.c2s[0]);
    try std.testing.expectEqual(@as(u8, 2), keys.s2c[0]);
    try std.testing.expectEqual([5]u8{ 0, 0, 0, 15, 1 }, mock.last_context);
}

test "unsupported aead is rejected" {
    const Mock = struct {
        pub fn exportKeyingMaterial(_: *@This(), _: []const u8, _: []const u8, _: []u8) !void {}
    };
    var mock = Mock{};
    try std.testing.expectError(
        error.UnsupportedAead,
        derive(Exporter.from(Mock, &mock), 1),
    );
}
