const std = @import("std");
const timez = @import("timez");

test "fuzz NTP packet parser" {
    try std.testing.fuzz({}, fuzzPacket, .{});
}

fn fuzzPacket(_: void, smith: *std.testing.Smith) !void {
    var buffer: [timez.ntp.packet.max_packet_len]u8 = undefined;
    const len = smith.slice(&buffer);
    const parsed = timez.ntp.packet.parse(buffer[0..len]) catch return;

    var output: [timez.ntp.packet.header_len]u8 = undefined;
    _ = try parsed.packet.write(&output);
    const round = try timez.ntp.packet.parse(&output);
    try std.testing.expectEqual(parsed.packet.mode, round.packet.mode);
    try std.testing.expectEqual(parsed.packet.version, round.packet.version);
}
