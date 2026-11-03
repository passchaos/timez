const std = @import("std");
const timez = @import("timez");

test "fuzz PTP message parser" {
    try std.testing.fuzz({}, fuzzMessage, .{});
}

fn fuzzMessage(_: void, smith: *std.testing.Smith) !void {
    var buffer: [timez.ptp.message.max_message_len]u8 = undefined;
    const len = smith.slice(&buffer);
    const parsed = timez.ptp.message.parse(buffer[0..len]) catch return;

    var output: [timez.ptp.message.max_message_len]u8 = undefined;
    _ = try timez.ptp.message.write(parsed.header, parsed.body, &output);
    const round = try timez.ptp.message.parse(&output);
    try std.testing.expectEqual(parsed.header.message_type, round.header.message_type);
}
