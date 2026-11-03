const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const vail_dependency = b.dependency("vail", .{
        .target = target,
        .optimize = optimize,
    });
    const vail = vail_dependency.module("vail");

    const timez = b.addModule("timez", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{.{ .name = "vail", .module = vail }},
    });

    const lib = b.addLibrary(.{
        .name = "timez",
        .root_module = timez,
        .linkage = .static,
    });
    b.installArtifact(lib);

    const install_docs = b.addInstallDirectory(.{
        .source_dir = lib.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    const docs_step = b.step("docs", "Install docs into zig-out/docs");
    docs_step.dependOn(&install_docs.step);

    const test_filter = b.option([]const u8, "test-filter", "Filter for test names");

    const unit_tests = b.addTest(.{
        .root_module = timez,
        .filters = if (test_filter) |f| &.{f} else &.{},
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    run_unit_tests.has_side_effects = true;

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    const integration_module = b.createModule(.{
        .root_source_file = b.path("test/integration.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    integration_module.addImport("timez", timez);
    integration_module.addImport("vail", vail);
    const integration_tests = b.addTest(.{
        .root_module = integration_module,
        .filters = if (test_filter) |f| &.{f} else &.{},
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    run_integration_tests.has_side_effects = true;

    const integration_step = b.step("test-integration", "Run integration tests");
    integration_step.dependOn(&run_integration_tests.step);

    test_step.dependOn(&run_integration_tests.step);
}
