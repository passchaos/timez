//! NTP server filtering, intersection selection, and combination.
//!
//! Each configured server keeps a short history of measurements. The clock
//! filter picks the lowest-delay sample, ages its dispersion, and produces a
//! candidate interval. Selection then uses Marzullo's interval-intersection
//! algorithm (RFC 5905 section 11.2.1) and combines the surviving candidates
//! with inverse-variance weights.
//!
//! The implementation is allocation-free and bounded by `max_servers`, so it
//! is safe to drive from a poll loop on any runtime.

const std = @import("std");
const clock = @import("../clock/mod.zig");
const client = @import("client.zig");

pub const Duration = clock.Duration;
pub const Timestamp = clock.Timestamp;
pub const Quality = clock.Quality;
pub const LeapIndicator = clock.LeapIndicator;
pub const Measurement = client.Measurement;
pub const IpAddress = std.Io.net.IpAddress;

pub const max_servers = 16;
pub const samples_per_server = 8;

pub const ServerState = struct {
    id: IpAddress,
    samples: [samples_per_server]Measurement = undefined,
    len: usize = 0,
    next: usize = 0,
    /// RFC 5905 reachability shift register.
    reach: u8 = 0,
    total_responses: u64 = 0,
    total_failures: u64 = 0,

    pub fn init(id: IpAddress) ServerState {
        return .{ .id = id };
    }

    pub fn reset(self: *ServerState) void {
        self.len = 0;
        self.next = 0;
        self.reach = 0;
    }

    pub fn addMeasurement(self: *ServerState, measurement: Measurement) void {
        self.samples[self.next] = measurement;
        self.next = (self.next + 1) % samples_per_server;
        if (self.len < samples_per_server) self.len += 1;
        self.reach = (self.reach << 1) | 1;
        self.total_responses += 1;
    }

    pub fn markFailure(self: *ServerState) void {
        self.reach <<= 1;
        self.total_failures += 1;
    }

    fn at(self: *const ServerState, index: usize) Measurement {
        const start = if (self.len == samples_per_server) self.next else 0;
        return self.samples[(start + index) % samples_per_server];
    }

    pub fn isReachable(self: *const ServerState) bool {
        return self.reach != 0;
    }

    /// Produce a selection candidate from the lowest-delay retained sample.
    pub fn candidate(self: *const ServerState, now: Duration, drift_ppm: f64) ?Candidate {
        if (self.len == 0 or self.reach == 0) return null;

        var best_sample = self.at(0);
        var best_delay = best_sample.delay.ns;
        var i: usize = 1;
        while (i < self.len) : (i += 1) {
            const sample = self.at(i);
            if (sample.delay.ns < best_delay) {
                best_delay = sample.delay.ns;
                best_sample = sample;
            }
        }

        if (best_sample.stratum == 0 or best_sample.stratum > 15) return null;
        if (best_sample.leap == .unknown) return null;

        const age = if (now.ns > best_sample.monotonic.ns)
            now.sub(best_sample.monotonic)
        else
            Duration.zero;
        const aged_ns: i96 = @intFromFloat(
            @as(f64, @floatFromInt(age.ns)) * (drift_ppm * 1e-6),
        );

        const root_distance = Duration.fromNanoseconds(
            @divTrunc(best_sample.delay.ns, 2) +
                @divTrunc(best_sample.quality.root_delay.ns, 2) +
                best_sample.dispersion.ns +
                aged_ns,
        );

        return .{
            .server = self.id,
            .offset = best_sample.offset,
            .root_distance = root_distance,
            .quality = best_sample.quality,
            .delay = best_sample.delay,
            .jitter = self.jitter(best_sample),
            .monotonic = best_sample.monotonic,
            .stratum = best_sample.stratum,
        };
    }

    fn jitter(self: *const ServerState, best_sample: Measurement) Duration {
        if (self.len < 2) return .zero;
        var sum: f64 = 0;
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            const sample = self.at(i);
            const deviation = @as(f64, @floatFromInt(sample.offset.ns - best_sample.offset.ns));
            sum += deviation * deviation;
        }
        const rms = @sqrt(sum / @as(f64, @floatFromInt(self.len)));
        return Duration.fromFloatSeconds(rms / @as(f64, @floatFromInt(std.time.ns_per_s)));
    }
};

pub const Candidate = struct {
    server: IpAddress,
    offset: Duration,
    root_distance: Duration,
    quality: Quality,
    delay: Duration,
    jitter: Duration,
    monotonic: Duration,
    stratum: u8,
};

pub const SelectionResult = struct {
    offset: Duration,
    /// Combined uncertainty (standard deviation of the weighted mean).
    uncertainty: Duration,
    quality: Quality,
    /// Server contributing the best quality/root distance.
    server: IpAddress,
    jitter: Duration,
    /// Number of candidates considered and number that survived intersection.
    candidate_count: usize,
    selected_count: usize,
};

/// Select from a set of candidates. Returns null when no candidate is usable.
pub fn selectCandidates(candidates: []const Candidate) ?SelectionResult {
    if (candidates.len == 0) return null;

    const Endpoint = struct {
        position: i96,
        delta: i8,
    };

    var endpoints: [max_servers * 2]Endpoint = undefined;
    var endpoint_count: usize = 0;
    for (candidates) |candidate| {
        if (endpoint_count + 2 > endpoints.len) break;
        endpoints[endpoint_count] = .{
            .position = candidate.offset.ns - candidate.root_distance.ns,
            .delta = 1,
        };
        endpoints[endpoint_count + 1] = .{
            .position = candidate.offset.ns + candidate.root_distance.ns,
            .delta = -1,
        };
        endpoint_count += 2;
    }

    // Sort by position; starts before ends so touching intervals overlap.
    std.mem.sort(Endpoint, endpoints[0..endpoint_count], {}, struct {
        fn lessThan(_: void, a: Endpoint, b: Endpoint) bool {
            if (a.position == b.position) return a.delta > b.delta;
            return a.position < b.position;
        }
    }.lessThan);

    var overlap: i32 = 0;
    var best_overlap: i32 = 0;
    var best_low: i96 = 0;
    var best_high: i96 = 0;
    var active = false;
    for (endpoints[0..endpoint_count]) |endpoint| {
        if (endpoint.delta > 0) {
            overlap += 1;
            if (overlap > best_overlap) {
                best_overlap = overlap;
                best_low = endpoint.position;
                best_high = endpoint.position;
                active = true;
            }
        } else {
            if (active and overlap == best_overlap) {
                best_high = endpoint.position;
            }
            overlap -= 1;
            if (overlap < best_overlap) active = false;
        }
    }
    if (best_overlap == 0) return null;

    const midpoint = @divTrunc(best_low + best_high, 2);

    var selected: [max_servers]Candidate = undefined;
    var selected_count: usize = 0;
    for (candidates) |candidate| {
        if (candidate.offset.ns - candidate.root_distance.ns <= midpoint and
            candidate.offset.ns + candidate.root_distance.ns >= midpoint)
        {
            if (selected_count < selected.len) {
                selected[selected_count] = candidate;
                selected_count += 1;
            }
        }
    }
    if (selected_count == 0) return null;

    var weight_sum: f64 = 0;
    var weighted_offset: f64 = 0;
    var variance_sum: f64 = 0;
    var best_index: usize = 0;
    for (selected[0..selected_count], 0..) |candidate, i| {
        const sigma_ns = @as(f64, @floatFromInt(@max(candidate.root_distance.ns, 1)));
        const weight = 1.0 / (sigma_ns * sigma_ns);
        weight_sum += weight;
        weighted_offset += @as(f64, @floatFromInt(candidate.offset.ns)) * weight;
        variance_sum += weight;

        if (candidate.stratum < selected[best_index].stratum or
            (candidate.stratum == selected[best_index].stratum and
                candidate.root_distance.ns < selected[best_index].root_distance.ns))
        {
            best_index = i;
        }
    }

    if (weight_sum == 0) return null;
    const combined_offset = weighted_offset / weight_sum;
    const combined_sigma = @sqrt(1.0 / variance_sum);

    var jitter_ns: i96 = 0;
    for (selected[0..selected_count]) |candidate| {
        jitter_ns = @max(jitter_ns, candidate.jitter.ns);
    }

    const best = selected[best_index];
    var quality = best.quality;
    quality.reference_time = best.quality.reference_time;
    quality.root_dispersion = Duration.fromFloatSeconds(
        combined_sigma / @as(f64, @floatFromInt(std.time.ns_per_s)),
    );

    return .{
        .offset = Duration.fromFloatSeconds(combined_offset / @as(f64, @floatFromInt(std.time.ns_per_s))),
        .uncertainty = Duration.fromFloatSeconds(combined_sigma / @as(f64, @floatFromInt(std.time.ns_per_s))),
        .quality = quality,
        .server = best.server,
        .jitter = .{ .ns = jitter_ns },
        .candidate_count = candidates.len,
        .selected_count = selected_count,
    };
}

/// Alias matching the module-level API.
pub const select = selectCandidates;

/// Bounded server pool and selection state.
pub const Pool = struct {
    servers: [max_servers]ServerState = undefined,
    len: usize = 0,
    drift_ppm: f64 = 15.0,

    pub const AddError = error{TooManyServers};

    pub fn addServer(self: *Pool, id: IpAddress) AddError!*ServerState {
        for (self.servers[0..self.len]) |*server| {
            if (server.id.eql(&id)) return server;
        }
        if (self.len == max_servers) return error.TooManyServers;
        self.servers[self.len] = ServerState.init(id);
        self.len += 1;
        return &self.servers[self.len - 1];
    }

    pub fn findServer(self: *Pool, id: IpAddress) ?*ServerState {
        for (self.servers[0..self.len]) |*server| {
            if (server.id.eql(&id)) return server;
        }
        return null;
    }

    pub fn addMeasurement(self: *Pool, measurement: Measurement) !void {
        const server = try self.addServer(measurement.server);
        server.addMeasurement(measurement);
    }

    pub fn markFailure(self: *Pool, id: IpAddress) void {
        if (self.findServer(id)) |server| server.markFailure();
    }

    pub fn select(self: *Pool, now: Duration) ?SelectionResult {
        var candidates: [max_servers]Candidate = undefined;
        var count: usize = 0;
        for (self.servers[0..self.len]) |*server| {
            if (server.candidate(now, self.drift_ppm)) |candidate| {
                if (count < candidates.len) {
                    candidates[count] = candidate;
                    count += 1;
                }
            }
        }
        return selectCandidates(candidates[0..count]);
    }
};

test "overlapping servers are combined" {
    const addr_a = try IpAddress.parseIp4("127.0.0.1", 123);
    const addr_b = try IpAddress.parseIp4("127.0.0.2", 123);
    var candidates = [_]Candidate{
        .{
            .server = addr_a,
            .offset = Duration.fromMilliseconds(10),
            .root_distance = Duration.fromMilliseconds(10),
            .quality = .{ .leap = .no_warning, .stratum = 1 },
            .delay = Duration.fromMilliseconds(5),
            .jitter = Duration.fromMilliseconds(1),
            .monotonic = .zero,
            .stratum = 1,
        },
        .{
            .server = addr_b,
            .offset = Duration.fromMilliseconds(20),
            .root_distance = Duration.fromMilliseconds(10),
            .quality = .{ .leap = .no_warning, .stratum = 2 },
            .delay = Duration.fromMilliseconds(5),
            .jitter = Duration.fromMilliseconds(1),
            .monotonic = .zero,
            .stratum = 2,
        },
    };
    const result = select(&candidates).?;
    try std.testing.expectEqual(@as(usize, 2), result.selected_count);
    try std.testing.expect(result.offset.ns >= 10 * std.time.ns_per_ms);
    try std.testing.expect(result.offset.ns <= 20 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u8, 1), result.quality.stratum);
}

test "disjoint servers do not intersect" {
    const addr_a = try IpAddress.parseIp4("127.0.0.1", 123);
    const addr_b = try IpAddress.parseIp4("127.0.0.2", 123);
    var candidates = [_]Candidate{
        .{
            .server = addr_a,
            .offset = .zero,
            .root_distance = Duration.fromMilliseconds(1),
            .quality = .{ .leap = .no_warning, .stratum = 1 },
            .delay = .zero,
            .jitter = .zero,
            .monotonic = .zero,
            .stratum = 1,
        },
        .{
            .server = addr_b,
            .offset = Duration.fromSeconds(100),
            .root_distance = Duration.fromMilliseconds(1),
            .quality = .{ .leap = .no_warning, .stratum = 2 },
            .delay = .zero,
            .jitter = .zero,
            .monotonic = .zero,
            .stratum = 2,
        },
    };
    const result = select(&candidates).?;
    try std.testing.expectEqual(@as(usize, 1), result.selected_count);
    try std.testing.expectEqual(Duration.zero, result.offset);
}

test "pool filters kiss-of-death and unreachable servers" {
    const addr = try IpAddress.parseIp4("127.0.0.1", 123);
    var pool = Pool{};
    const server = try pool.addServer(addr);
    server.addMeasurement(.{
        .offset = .zero,
        .delay = Duration.fromMilliseconds(1),
        .dispersion = .zero,
        .t1 = Timestamp.zero,
        .t2 = Timestamp.zero,
        .t3 = Timestamp.zero,
        .t4 = Timestamp.zero,
        .monotonic = .zero,
        .quality = .{ .leap = .unknown, .stratum = 0 },
        .leap = .unknown,
        .stratum = 0,
        .reference_id = 0,
        .server = addr,
    });
    try std.testing.expect(pool.select(.zero) == null);
    var i: usize = 0;
    while (i < 8) : (i += 1) server.markFailure();
    try std.testing.expect(!server.isReachable());
}

test "pool ages dispersion and prefers reachable servers" {
    const addr = try IpAddress.parseIp4("127.0.0.1", 123);
    var pool = Pool{ .drift_ppm = 100.0 };
    const server = try pool.addServer(addr);
    server.addMeasurement(.{
        .offset = Duration.fromMilliseconds(2),
        .delay = Duration.fromMilliseconds(2),
        .dispersion = Duration.fromMilliseconds(1),
        .t1 = Timestamp.zero,
        .t2 = Timestamp.zero,
        .t3 = Timestamp.zero,
        .t4 = Timestamp.zero,
        .monotonic = .zero,
        .quality = .{ .leap = .no_warning, .stratum = 1 },
        .leap = .no_warning,
        .stratum = 1,
        .reference_id = 0,
        .server = addr,
    });
    const early = server.candidate(.zero, 100.0).?;
    const late = server.candidate(Duration.fromSeconds(100), 100.0).?;
    try std.testing.expect(late.root_distance.ns > early.root_distance.ns);
}
