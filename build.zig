const std = @import("std");

const warn_flags = [_][]const u8{
    "-std=c23",
    "-Wall",
    "-Wextra",
    "-Wpedantic",
    "-Wshadow",
    "-Wcast-qual",
    "-Wcast-align",
    "-Wpointer-arith",
    "-Wstrict-prototypes",
    "-Wmissing-prototypes",
    "-Wold-style-definition",
    "-Wwrite-strings",
    "-Wvla",
    "-Wfloat-equal",
    "-Wundef",
    "-Wformat=2",
    "-Wnull-dereference",
    "-Wdouble-promotion",
    "-Wimplicit-fallthrough",
    "-Wconversion",
    "-fno-strict-aliasing",
};

const release_flags = [_][]const u8{
    "-D_FORTIFY_SOURCE=3",
    "-fstack-protector-strong",
    "-ftrivial-auto-var-init=zero",
    "-fno-delete-null-pointer-checks",
};

const debug_flags = [_][]const u8{
    "-fno-omit-frame-pointer",
    "-fsanitize=address,undefined",
    "-fno-sanitize-recover=all",
    "-U_FORTIFY_SOURCE",
};

const linux_flags = [_][]const u8{
    "-D_GNU_SOURCE",
};

const linux_x86_64_flags = [_][]const u8{
    "-fstack-clash-protection",
};

const shared_sources = [_][]const u8{
    // "shared/frame.c",
    // "shared/transport.c",
    // "shared/protocol.c",
};

const Binary = struct {
    step_name: []const u8,
    exe_name: []const u8,
    sources: []const []const u8,
};

const binaries = [_]Binary{
    .{
        .step_name = "server",
        .exe_name = "pac-server",
        .sources = &.{
            "server/src/main.c",
        },
    },
    .{
        .step_name = "cli",
        .exe_name = "pac-cli",
        .sources = &.{
            // "cli/src/main.c",
        },
    },
};

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const version = b.option([]const u8, "version", "Version string from git tag") orelse "dev";

    var cflags: std.ArrayList([]const u8) = .empty;
    try cflags.appendSlice(b.allocator, &warn_flags);
    if (optimize == .Debug) {
        try cflags.appendSlice(b.allocator, &debug_flags);
    } else {
        try cflags.appendSlice(b.allocator, &release_flags);
    }
    if (target.result.os.tag == .linux) {
        try cflags.appendSlice(b.allocator, &linux_flags);
        if (target.result.cpu.arch == .x86_64) {
            try cflags.appendSlice(b.allocator, &linux_x86_64_flags);
        }
    }
    const flags = cflags.items;

    inline for (binaries) |bin| {
        if (bin.sources.len == 0) continue;

        const exe = b.addExecutable(.{
            .name = bin.exe_name,
            .root_module = b.createModule(.{
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });

        exe.root_module.addCMacro("PAC_VERSION", b.fmt("\"{s}\"", .{version}));
        exe.root_module.addIncludePath(b.path("shared"));
        exe.root_module.addIncludePath(b.path("shared/vendor"));

        if (shared_sources.len > 0) {
            exe.root_module.addCSourceFiles(.{
                .root = b.path(""),
                .files = &shared_sources,
                .flags = flags,
            });
        }
        exe.root_module.addCSourceFiles(.{
            .root = b.path(""),
            .files = bin.sources,
            .flags = flags,
        });

        exe.root_module.linkSystemLibrary("sodium", .{});

        const install = b.addInstallArtifact(exe, .{});
        const step = b.step(bin.step_name, "Build " ++ bin.exe_name);
        step.dependOn(&install.step);
        b.getInstallStep().dependOn(&install.step);

        const run = b.addRunArtifact(exe);
        run.step.dependOn(&install.step);
        if (b.args) |args| run.addArgs(args);
        const run_step = b.step("run-" ++ bin.step_name, "Run " ++ bin.exe_name);
        run_step.dependOn(&run.step);
    }
}
