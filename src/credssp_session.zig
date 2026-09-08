const std = @import("std");
const r4os = @import("r4os");
const records = @import("ntlm_session.zig");
const Hmac = std.crypto.auth.hmac.HmacMd5;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Error = error{ BadConfig, BadState, BadToken, BadPassword, BadBinding, Unsupported, EntropyUnavailable, BufferSmall };
pub const Phase = enum(u8) { negotiate = 1, authenticate = 2, credentials = 3, complete = 4, failed = 5 };
pub const stream_size: usize = 140;
pub const max_token: usize = 4096;
const signature = "NTLMSSP\x00";
const unicode: u32 = 0x00000001;
const sign: u32 = 0x00000010;
const seal: u32 = 0x00000020;
const ntlm: u32 = 0x00000200;
const always_sign: u32 = 0x00008000;
const extended: u32 = 0x00080000;
const target_info: u32 = 0x00800000;
const version_flag: u32 = 0x02000000;
const bits128: u32 = 0x20000000;
const key_exchange: u32 = 0x40000000;
const bits56: u32 = 0x80000000;
const required_flags = unicode | sign | seal | ntlm | extended | bits128;

fn read32(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .little);
}
fn read16(bytes: []const u8) u16 {
    return std.mem.readInt(u16, bytes[0..2], .little);
}
fn write32(bytes: []u8, value: u32) void {
    std.mem.writeInt(u32, bytes[0..4], value, .little);
}
fn write16(bytes: []u8, value: u16) void {
    std.mem.writeInt(u16, bytes[0..2], value, .little);
}
fn sameSecret(comptime n: usize, a: []const u8, b: []const u8) bool {
    return a.len == n and b.len == n and std.crypto.timing_safe.eql([n]u8, a[0..n].*, b[0..n].*);
}
fn userMatches(wide: []const u8, ascii: []const u8) bool {
    if (wide.len != ascii.len * 2) return false;
    for (ascii, 0..) |byte, index| {
        if (wide[index * 2 + 1] != 0 or std.ascii.toLower(wide[index * 2]) != std.ascii.toLower(byte)) return false;
    }
    return true;
}
fn localDomain(wide: []const u8) bool {
    return wide.len == 0 or userMatches(wide, "R4OS");
}
fn securityBuffer(message: []const u8, offset: usize, minimum: usize) Error![]const u8 {
    if (offset > message.len or message.len - offset < 8) return error.BadToken;
    const len: usize = read16(message[offset..]);
    const maximum: usize = read16(message[offset + 2 ..]);
    const start: usize = read32(message[offset + 4 ..]);
    if (maximum < len or start > message.len or len > message.len - start or (len != 0 and start < minimum)) return error.BadToken;
    return message[start..][0..len];
}
fn putSecurityBuffer(bytes: []u8, length: usize, offset: usize) void {
    write16(bytes[0..2], @intCast(length));
    write16(bytes[2..4], @intCast(length));
    write32(bytes[4..8], @intCast(offset));
}
fn tlsFingerprint(stream: []const u8) Error![32]u8 {
    if (stream.len != stream_size or !std.mem.startsWith(u8, stream, "R4LK") or
        std.mem.allEqual(u8, stream[60..108], 0) or std.mem.allEqual(u8, stream[108..140], 0)) return error.BadBinding;
    var digest: [32]u8 = undefined;
    // The two record sequence numbers change during this same handshake.
    Sha256.hash(stream[20..], &digest, .{});
    return digest;
}

// The adapter supplies the existing bounded DER/TSRequest helpers and MD4
// primitive. The session engine has no configured default user/password.
pub fn Engine(comptime wire: type) type {
    return struct {
        pub const Session = extern struct {
            magic: [4]u8 = "R4A3".*,
            phase: u8 = @intFromEnum(Phase.negotiate),
            credssp_version: u8 = 0,
            reserved: [2]u8 = .{ 0, 0 },
            flags: u32 = 0,
            user_len: u16 = 0,
            public_key_len: u16 = 0,
            type1_len: u16 = 0,
            type2_len: u16 = 0,
            domain_len: u16 = 0,
            reserved2: [2]u8 = .{ 0, 0 },
            challenge: [8]u8 = .{0} ** 8,
            tls_binding: [32]u8 = .{0} ** 32,
            nt_hash: [16]u8 = .{0} ** 16,
            user: [32]u8 = .{0} ** 32,
            domain: [64]u8 = .{0} ** 64,
            public_key: [1024]u8 = .{0} ** 1024,
            type1: [512]u8 = .{0} ** 512,
            type2: [256]u8 = .{0} ** 256,
            client: records.Direction = std.mem.zeroes(records.Direction),
            server: records.Direction = std.mem.zeroes(records.Direction),

            pub fn init(user: []const u8, password: []const u8, stream: []const u8, public_key: []const u8) Error!Session {
                try validateConfig(user, password);
                if (public_key.len == 0 or public_key.len > 1024) return error.BadBinding;
                var self = Session{};
                errdefer self.clear();
                self.tls_binding = try tlsFingerprint(stream);
                self.user_len = @intCast(user.len);
                @memcpy(self.user[0..user.len], user);
                self.public_key_len = @intCast(public_key.len);
                @memcpy(self.public_key[0..public_key.len], public_key);
                var wide: [64]u16 = undefined;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&wide));
                const count = std.unicode.utf8ToUtf16Le(&wide, password) catch return error.BadConfig;
                wire.md4(std.mem.sliceAsBytes(wide[0..count]), &self.nt_hash);
                if (!r4os.secure_random.fill(&self.challenge)) return error.EntropyUnavailable;
                return self;
            }

            pub fn clear(self: *Session) void {
                std.crypto.secureZero(u8, std.mem.asBytes(self));
                self.phase = @intFromEnum(Phase.failed);
            }

            pub fn process(self: *Session, stream: []const u8, tsrequest: []const u8, out: []u8) Error!usize {
                errdefer self.clear();
                if (!std.mem.eql(u8, &self.magic, "R4A3") or self.user_len == 0 or self.user_len >= self.user.len or
                    self.public_key_len == 0 or self.public_key_len > self.public_key.len or
                    self.type1_len > self.type1.len or self.type2_len > self.type2.len or self.domain_len > self.domain.len) return error.BadState;
                const binding = try tlsFingerprint(stream);
                if (!sameSecret(32, &binding, &self.tls_binding)) return error.BadBinding;
                if (tsrequest.len > max_token) return error.BadToken;
                const request = wire.parseRequest(tsrequest) orelse return error.BadToken;
                if (!request.has_version or request.version < 2 or request.version > 6 or request.has_error_code or request.unknown_fields != 0 or request.nego_tokens > 1) return error.BadToken;
                switch (self.phase) {
                    @intFromEnum(Phase.negotiate) => {
                        if (request.has_auth_info or request.has_pub_key_auth or request.nego_tokens != 1) return error.BadState;
                        const token = wire.ntlmMessage(request.nego_token) orelse return error.Unsupported;
                        if (token.len < 32 or token.len > self.type1.len or read32(token[8..]) != 1) return error.BadToken;
                        const offered = read32(token[12..]);
                        if ((offered & required_flags) != required_flags) return error.Unsupported;
                        const header: usize = if ((offered & version_flag) != 0) 40 else 32;
                        if (token.len < header) return error.BadToken;
                        _ = try securityBuffer(token, 16, header);
                        _ = try securityBuffer(token, 24, header);
                        self.flags = (offered & (required_flags | always_sign | version_flag | key_exchange | bits56)) | target_info | 4;
                        self.credssp_version = @intCast(request.version);
                        self.type1_len = @intCast(token.len);
                        @memcpy(self.type1[0..token.len], token);
                        self.type2_len = @intCast(self.buildChallenge());
                        var spnego: [320]u8 = undefined;
                        const sn = wire.spnego(&spnego, self.type2[0..self.type2_len], 1) orelse return error.BufferSmall;
                        const n = wire.tokenRequest(out, spnego[0..sn], self.credssp_version) orelse return error.BufferSmall;
                        self.phase = @intFromEnum(Phase.authenticate);
                        return n;
                    },
                    @intFromEnum(Phase.authenticate) => {
                        if (request.version != self.credssp_version or request.has_auth_info or request.nego_tokens != 1 or !request.has_pub_key_auth) return error.BadState;
                        const token = wire.ntlmMessage(request.nego_token) orelse return error.BadToken;
                        try self.authenticate(token);
                        const n = try self.verifyBinding(request.pub_key_auth, request.client_nonce, out);
                        self.phase = @intFromEnum(Phase.credentials);
                        return n;
                    },
                    @intFromEnum(Phase.credentials) => {
                        if (request.version != self.credssp_version or !request.has_auth_info or request.nego_tokens != 0 or request.has_pub_key_auth or request.has_client_nonce) return error.BadState;
                        try self.verifyCredentials(request.auth_info);
                        self.clear();
                        self.phase = @intFromEnum(Phase.complete);
                        return 0;
                    },
                    else => return error.BadState,
                }
            }

            fn buildChallenge(self: *Session) usize {
                const start: usize = if ((self.flags & version_flag) != 0) 56 else 48;
                const out = &self.type2;
                @memset(out, 0);
                @memcpy(out[0..8], signature);
                write32(out[8..12], 2);
                write32(out[20..24], self.flags);
                @memcpy(out[24..32], &self.challenge);
                if (start == 56) @memcpy(out[48..56], &[_]u8{ 10, 0, 0, 0, 0, 0, 0, 15 });
                const name = "R\x004\x00O\x00S\x00";
                putSecurityBuffer(out[12..20], name.len, start);
                @memcpy(out[start..][0..name.len], name);
                const av_start = start + name.len;
                var pos = av_start;
                for ([_]u16{ 1, 2 }) |id| {
                    write16(out[pos..], id);
                    write16(out[pos + 2 ..], name.len);
                    @memcpy(out[pos + 4 ..][0..name.len], name);
                    pos += 4 + name.len;
                }
                pos += 4; // Zero AV terminator.
                putSecurityBuffer(out[40..48], pos - av_start, av_start);
                return pos;
            }

            fn authenticate(self: *Session, token: []const u8) Error!void {
                if (token.len < 64 or token.len > max_token or !std.mem.startsWith(u8, token, signature) or read32(token[8..]) != 3) return error.BadToken;
                const flags = read32(token[60..]);
                if ((flags & required_flags) != required_flags or ((flags ^ self.flags) & (key_exchange | version_flag)) != 0) return error.Unsupported;
                const header: usize = if ((flags & version_flag) != 0) 72 else 64;
                if (token.len < header) return error.BadToken;
                const response = try securityBuffer(token, 20, header);
                const domain = try securityBuffer(token, 28, header);
                const user = try securityBuffer(token, 36, header);
                const encrypted_key = try securityBuffer(token, 52, header);
                if (!userMatches(user, self.user[0..self.user_len])) return error.BadPassword;
                if (!localDomain(domain) or domain.len > self.domain.len) return error.Unsupported;
                if (response.len < 16 + 36) return error.BadPassword;
                const proof = response[0..16];
                const blob = response[16..];
                const mic_required = try validateBlob(blob);
                var identity: [128]u8 = undefined;
                defer std.crypto.secureZero(u8, &identity);
                for (self.user[0..self.user_len], 0..) |byte, i| {
                    identity[i * 2] = std.ascii.toUpper(byte);
                    identity[i * 2 + 1] = 0;
                }
                const identity_len = @as(usize, self.user_len) * 2;
                @memcpy(identity[identity_len..][0..domain.len], domain);
                var response_key: [16]u8 = undefined;
                defer std.crypto.secureZero(u8, &response_key);
                Hmac.create(&response_key, identity[0 .. identity_len + domain.len], &self.nt_hash);
                var check = Hmac.init(&response_key);
                check.update(&self.challenge);
                check.update(blob);
                var expected: [16]u8 = undefined;
                defer std.crypto.secureZero(u8, &expected);
                check.final(&expected);
                if (!sameSecret(16, proof, &expected)) return error.BadPassword;
                var exported: [16]u8 = undefined;
                defer std.crypto.secureZero(u8, &exported);
                Hmac.create(&exported, proof, &response_key);
                if ((self.flags & key_exchange) != 0) {
                    if (encrypted_key.len != 16) return error.BadToken;
                    var cipher = records.Rc4.init(exported);
                    defer std.crypto.secureZero(u8, std.mem.asBytes(&cipher));
                    @memcpy(&exported, encrypted_key);
                    cipher.xor(&exported);
                } else if (encrypted_key.len != 0) return error.BadToken;
                var first_payload: usize = token.len;
                for ([_]usize{ 12, 20, 28, 36, 44, 52 }) |offset| {
                    const value = try securityBuffer(token, offset, header);
                    if (value.len != 0) first_payload = @min(first_payload, read32(token[offset + 4 ..]));
                }
                const mic_present = first_payload >= header + 16;
                if (mic_required and !mic_present) return error.BadToken;
                if (mic_present) {
                    var transcript = Hmac.init(&exported);
                    transcript.update(self.type1[0..self.type1_len]);
                    transcript.update(self.type2[0..self.type2_len]);
                    transcript.update(token[0..header]);
                    transcript.update(&([_]u8{0} ** 16));
                    transcript.update(token[header + 16 ..]);
                    transcript.final(&expected);
                    if (!sameSecret(16, token[header..][0..16], &expected)) return error.BadPassword;
                }
                self.domain_len = @intCast(domain.len);
                @memcpy(self.domain[0..domain.len], domain);
                self.client = records.clientDirection(exported);
                self.server = records.serverDirection(exported);
            }

            fn verifyBinding(self: *Session, sealed: []const u8, nonce: []const u8, out: []u8) Error!usize {
                var plain: [1024]u8 = undefined;
                defer std.crypto.secureZero(u8, &plain);
                const n = self.client.open(sealed, &plain, (self.flags & key_exchange) != 0) catch return error.BadBinding;
                const public_key = self.public_key[0..self.public_key_len];
                var answer: [1024]u8 = undefined;
                var answer_len: usize = 0;
                if (self.credssp_version >= 5) {
                    if (nonce.len != 32 or n != 32) return error.BadBinding;
                    var hash = Sha256.init(.{});
                    hash.update("CredSSP Client-To-Server Binding Hash\x00");
                    hash.update(nonce);
                    hash.update(public_key);
                    var expected: [32]u8 = undefined;
                    hash.final(&expected);
                    if (!sameSecret(32, plain[0..n], &expected)) return error.BadBinding;
                    hash = Sha256.init(.{});
                    hash.update("CredSSP Server-To-Client Binding Hash\x00");
                    hash.update(nonce);
                    hash.update(public_key);
                    hash.final(answer[0..32]);
                    answer_len = 32;
                } else {
                    if (!std.mem.eql(u8, plain[0..n], public_key)) return error.BadBinding;
                    @memcpy(answer[0..n], plain[0..n]);
                    answer[0] +%= 1;
                    answer_len = n;
                }
                var encrypted: [1040]u8 = undefined;
                const sealed_len = self.server.seal(answer[0..answer_len], &encrypted, (self.flags & key_exchange) != 0) catch return error.BadBinding;
                return wire.bindingRequest(out, encrypted[0..sealed_len], self.credssp_version) orelse error.BufferSmall;
            }

            fn verifyCredentials(self: *Session, sealed: []const u8) Error!void {
                var plain: [1024]u8 = undefined;
                defer std.crypto.secureZero(u8, &plain);
                const n = self.client.open(sealed, &plain, (self.flags & key_exchange) != 0) catch return error.BadPassword;
                const creds = wire.passwordCredentials(plain[0..n]) orelse return error.BadToken;
                if (!userMatches(creds.user, self.user[0..self.user_len]) or !std.mem.eql(u8, creds.domain, self.domain[0..self.domain_len])) return error.BadPassword;
                if (creds.password.len == 0 or creds.password.len % 2 != 0 or creds.password.len > 128) return error.BadPassword;
                var digest: [16]u8 = undefined;
                defer std.crypto.secureZero(u8, &digest);
                wire.md4(creds.password, &digest);
                if (!sameSecret(16, &digest, &self.nt_hash)) return error.BadPassword;
            }
        };

        pub fn validateConfig(user: []const u8, password: []const u8) Error!void {
            if (user.len == 0 or user.len >= 32 or password.len == 0 or password.len >= 32) return error.BadConfig;
            for (user) |byte| if (byte < 0x20 or byte > 0x7e or byte == '\\' or byte == '/') return error.BadConfig;
            if (!std.unicode.utf8ValidateSlice(password) or std.mem.indexOfScalar(u8, password, 0) != null) return error.BadConfig;
        }

        fn validateBlob(blob: []const u8) Error!bool {
            if (blob.len < 36 or blob.len > max_token - 16 or blob[0] != 1 or blob[1] != 1 or
                !std.mem.allEqual(u8, blob[2..8], 0) or !std.mem.allEqual(u8, blob[24..28], 0)) return error.BadToken;
            var pos: usize = 28;
            var mic = false;
            var seen_flags = false;
            while (pos <= blob.len and blob.len - pos >= 4) {
                const id = read16(blob[pos..]);
                const len: usize = read16(blob[pos + 2 ..]);
                pos += 4;
                if (len > blob.len - pos) return error.BadToken;
                if (id == 0) {
                    if (len != 0 or blob.len - pos != 4 or !std.mem.allEqual(u8, blob[pos..], 0)) return error.BadToken;
                    return mic;
                }
                if (id == 6) {
                    if (len != 4 or seen_flags) return error.BadToken;
                    seen_flags = true;
                    mic = (read32(blob[pos..]) & 2) != 0;
                }
                pos += len;
            }
            return error.BadToken;
        }
    };
}
