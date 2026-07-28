const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try printUsage();
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "hexdump")) {
        if (args.len < 3) {
            std.debug.print("Usage: ucop-utils hexdump <file>\n", .{});
            return;
        }
        try hexdump(args[2]);
    } else if (std.mem.eql(u8, command, "hash")) {
        if (args.len < 3) {
            std.debug.print("Usage: ucop-utils hash <string>\n", .{});
            return;
        }
        try hashString(args[2]);
    } else if (std.mem.eql(u8, command, "banner")) {
        try printBanner();
    } else {
        std.debug.print("Unknown command: {s}\n", .{command});
        try printUsage();
    }
}

fn printUsage() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.writeAll(
        \\UCOP-X Zig Utilities
        \\
        \\Usage: ucop-utils <command> [args]
        \\
        \\Commands:
        \\  hexdump <file>    Display hex dump of a file
        \\  hash <string>     Compute SHA-256 hash (placeholder)
        \\  banner            Display UCOP-X banner
        \\
    );
}

fn hexdump(path: []const u8) !void {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var buffer: [16]u8 = undefined;
    var offset: usize = 0;
    const stdout = std.io.getStdOut().writer();

    while (true) {
        const bytes_read = try file.read(&buffer);
        if (bytes_read == 0) break;

        try stdout.print("{:0>8x}  ", .{offset});

        for (0..16) |i| {
            if (i < bytes_read) {
                try stdout.print("{:0>2x} ", .{buffer[i]});
            } else {
                try stdout.writeAll("   ");
            }
            if (i == 7) try stdout.writeAll(" ");
        }

        try stdout.writeAll(" |");
        for (0..bytes_read) |i| {
            const c = buffer[i];
            if (c >= 32 and c < 127) {
                try stdout.writeByte(c);
            } else {
                try stdout.writeByte('.');
            }
        }
        try stdout.writeAll("|\n");

        offset += bytes_read;
    }
}

fn hashString(s: []const u8) !void {
    const stdout = std.io.getStdOut().writer();
    // Placeholder - would use a real hash implementation
    _ = s;
    try stdout.writeAll("SHA-256: <hash computation placeholder>\n");
}

fn printBanner() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.writeAll(
        \\  _    _ _____ _____ _____   _____   __
        \\ | |  | |  ___|  ___|  ___| |  ___| / _|
        \\ | |  | | |__ | |_  | |_    | |__  | |_
        \\ | |/\\| |  __||  _| |  _|   |  __| |  _|
        \\ \\  /\\  / |___| |   | |     | |___ | |
        \\  \\/  \\/\\____/|_|   |_|     \\____/ |_|
        \\
        \\  Enterprise Cybersecurity Platform
        \\  Zig Utilities Module
        \\
    );
}
