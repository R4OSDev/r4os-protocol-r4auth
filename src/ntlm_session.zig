const std = @import("std");
const HmacMd5 = std.crypto.auth.hmac.HmacMd5;

// NTLM's connection-oriented, extended-session-security record protection.
// This legacy cipher is confined to the NTLM wire contract; TLS protects the
// surrounding transport. State belongs to one direction of one connection.
pub const Rc4 = extern struct {
    s: [256]u8,
    i: u8 = 0,
    j: u8 = 0,

    pub fn init(key: [16]u8) Rc4 {
        var result: Rc4 = .{ .s = undefined };
        for (&result.s, 0..) |*byte, index| byte.* = @intCast(index);
        var j: u8 = 0;
        for (0..256) |index| {
            j +%= result.s[index] +% key[index % key.len];
            std.mem.swap(u8, &result.s[index], &result.s[j]);
        }
        return result;
    }

    pub fn xor(self: *Rc4, bytes: []u8) void {
        for (bytes) |*byte| {
            self.i +%= 1;
            self.j +%= self.s[self.i];
            std.mem.swap(u8, &self.s[self.i], &self.s[self.j]);
            byte.* ^= self.s[self.s[self.i] +% self.s[self.j]];
        }
    }
};

pub const Error = error{ BadBuffer, BadSignature, SequenceExhausted };

pub const Direction = extern struct {
    cipher: Rc4,
    reserved: [2]u8 = .{ 0, 0 },
    signing_key: [16]u8,
    sequence: u32 = 0,

    pub fn init(signing_key: [16]u8, sealing_key: [16]u8) Direction {
        return .{ .cipher = Rc4.init(sealing_key), .signing_key = signing_key };
    }

    fn checksum(self: *const Direction, message: []const u8) [8]u8 {
        var sequence: [4]u8 = undefined;
        std.mem.writeInt(u32, &sequence, self.sequence, .little);
        var hmac = HmacMd5.init(&self.signing_key);
        hmac.update(&sequence);
        hmac.update(message);
        var digest: [16]u8 = undefined;
        defer std.crypto.secureZero(u8, &digest);
        hmac.final(&digest);
        return digest[0..8].*;
    }

    pub fn seal(self: *Direction, message: []const u8, out: []u8, key_exchange: bool) Error!usize {
        if (out.len < 16 or message.len > out.len - 16) return error.BadBuffer;
        if (self.sequence == std.math.maxInt(u32)) return error.SequenceExhausted;
        var next = self.*;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&next));
        var mac = self.checksum(message);
        @memcpy(out[16..][0..message.len], message);
        next.cipher.xor(out[16..][0..message.len]);
        if (key_exchange) next.cipher.xor(&mac);
        std.mem.writeInt(u32, out[0..4], 1, .little);
        @memcpy(out[4..12], &mac);
        std.mem.writeInt(u32, out[12..16], self.sequence, .little);
        next.sequence += 1;
        self.* = next;
        return 16 + message.len;
    }

    pub fn open(self: *Direction, record: []const u8, out: []u8, key_exchange: bool) Error!usize {
        if (record.len < 16 or record.len - 16 > out.len) return error.BadBuffer;
        if (self.sequence == std.math.maxInt(u32)) return error.SequenceExhausted;
        if (std.mem.readInt(u32, record[0..4], .little) != 1 or
            std.mem.readInt(u32, record[12..16], .little) != self.sequence) return error.BadSignature;
        const count = record.len - 16;
        var next = self.*;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&next));
        @memcpy(out[0..count], record[16..]);
        next.cipher.xor(out[0..count]);
        var mac = self.checksum(out[0..count]);
        if (key_exchange) next.cipher.xor(&mac);
        if (!std.crypto.timing_safe.eql([8]u8, mac, record[4..12].*)) {
            std.crypto.secureZero(u8, out[0..count]);
            return error.BadSignature;
        }
        next.sequence += 1;
        self.* = next;
        return count;
    }
};

pub fn deriveKey(exported_key: [16]u8, label: []const u8) [16]u8 {
    var hash = std.crypto.hash.Md5.init(.{});
    hash.update(&exported_key);
    hash.update(label);
    var out: [16]u8 = undefined;
    hash.final(&out);
    return out;
}

pub fn clientDirection(exported_key: [16]u8) Direction {
    return Direction.init(
        deriveKey(exported_key, "session key to client-to-server signing key magic constant\x00"),
        deriveKey(exported_key, "session key to client-to-server sealing key magic constant\x00"),
    );
}

pub fn serverDirection(exported_key: [16]u8) Direction {
    return Direction.init(
        deriveKey(exported_key, "session key to server-to-client signing key magic constant\x00"),
        deriveKey(exported_key, "session key to server-to-client sealing key magic constant\x00"),
    );
}
