const std = @import("std");

pub const timez = @import("timez");

test {
    std.testing.refAllDecls(timez);
}
