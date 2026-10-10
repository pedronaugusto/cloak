//! Private P-256/P-384 arithmetic. Complete a=-3 formulas from Zig 0.17.0.
//! Montgomery limbs stay canonical. Only the public affine result leaves.
const std = @import("std");
const Montgomery = @import("Montgomery.zig");
pub fn Point(comptime Public: type) type {
    const fiat = Montgomery.Field(Public.Fe);
    const Field = struct {
        pub const Self = @This();
        limbs: fiat.MontgomeryDomainFieldElement,
        fn fromPublic(p: Public.Fe) Self {
            @setRuntimeSafety(true);
            return .{ .limbs = p.limbs };
        }
        fn add(a: Self, b: Self) Self {
            @setRuntimeSafety(true);
            var r: Self = undefined;
            fiat.add(&r.limbs, a.limbs, b.limbs);
            defer if (!@inComptime()) std.crypto.secureZero(u8, std.mem.asBytes(&r));
            return r;
        }
        fn sub(a: Self, b: Self) Self {
            @setRuntimeSafety(true);
            var r: Self = undefined;
            fiat.sub(&r.limbs, a.limbs, b.limbs);
            defer if (!@inComptime()) std.crypto.secureZero(u8, std.mem.asBytes(&r));
            return r;
        }
        fn mul(a: Self, b: Self) Self {
            @setRuntimeSafety(true);
            var r: Self = undefined;
            fiat.mul(&r.limbs, a.limbs, b.limbs);
            defer if (!@inComptime()) std.crypto.secureZero(u8, std.mem.asBytes(&r));
            return r;
        }
        fn sq(a: Self) Self {
            @setRuntimeSafety(true);
            var r: Self = undefined;
            fiat.square(&r.limbs, a.limbs);
            defer if (!@inComptime()) std.crypto.secureZero(u8, std.mem.asBytes(&r));
            return r;
        }
        fn dbl(a: Self) Self {
            @setRuntimeSafety(true);
            return a.add(a);
        }
        pub fn cMov(a: *Self, b: Self, choice: u1) void {
            @setRuntimeSafety(true);
            fiat.selectznz(&a.limbs, choice, a.limbs, b.limbs);
        }
        fn isZero(a: Self) bool {
            @setRuntimeSafety(true);
            var bits: u64 = 0;
            defer if (!@inComptime()) std.crypto.secureZero(u8, std.mem.asBytes(&bits));
            inline for (a.limbs) |limb| bits |= limb;
            return bits == 0;
        }
        fn invert(a: Self) Self {
            @setRuntimeSafety(true); // Fermat exponent is public, fixed at compile time for each prime.
            var scratch: struct { value: Self } = .{ .value = fromPublic(Public.Fe.one) };
            defer if (!@inComptime()) std.crypto.secureZero(u8, std.mem.asBytes(&scratch));
            const exponent = comptime blk: {
                var bytes: [Public.Fe.encoded_length]u8 = undefined;
                std.mem.writeInt(@Int(.unsigned, bytes.len * 8), &bytes, Public.Fe.field_order - 2, .big);
                break :blk bytes;
            };
            for (0..Public.Fe.field_bits) |i| {
                scratch.value = scratch.value.sq();
                if ((exponent[i / 8] >> @as(u3, @intCast(7 - i % 8))) & 1 != 0) // safe: public bit offset is 0..7
                    scratch.value = scratch.value.mul(a);
            }
            return scratch.value;
        }
    };
    return struct {
        const Self = @This();
        pub const scalar = Public.scalar;
        x: Field,
        y: Field,
        z: Field,
        pub const identityElement: Self = .{ .x = Field.fromPublic(Public.Fe.zero), .y = Field.fromPublic(Public.Fe.one), .z = Field.fromPublic(Public.Fe.zero) };
        pub const basePoint: Self = .{ .x = Field.fromPublic(Public.basePoint.x), .y = Field.fromPublic(Public.basePoint.y), .z = Field.fromPublic(Public.basePoint.z) };
        const B = Field.fromPublic(Public.B);
        /// Imports a public point; its coordinates carry no secret.
        pub fn fromPublic(p: Public) Self {
            @setRuntimeSafety(true);
            return .{ .x = Field.fromPublic(p.x), .y = Field.fromPublic(p.y), .z = Field.fromPublic(p.z) };
        }
        pub fn rejectIdentity(p: Self) error{IdentityElement}!void {
            @setRuntimeSafety(true);
            // Complete formulas have homogeneous identity z=0. Release only invalid-key status.
            if (p.z.isZero()) return error.IdentityElement;
        }
        pub fn publicPoint(p: Self) Public {
            @setRuntimeSafety(true);
            var scratch: struct { inverse: Field, x: Field, y: Field } = .{
                .inverse = p.z.invert(),
                .x = p.x,
                .y = p.y,
            };
            defer if (!@inComptime()) std.crypto.secureZero(u8, std.mem.asBytes(&scratch));
            scratch.x = scratch.x.mul(scratch.inverse);
            scratch.y = scratch.y.mul(scratch.inverse);
            // Affine coordinates are the disclosed public key. No private projective z escapes.
            return .{ .x = .{ .limbs = scratch.x.limbs }, .y = .{ .limbs = scratch.y.limbs }, .z = Public.Fe.one };
        }
        pub fn dbl(p: Self) Self {
            @setRuntimeSafety(true);
            var scratch: struct { t0: Field, t1: Field, t2: Field, t3: Field, X3: Field, Y3: Field, Z3: Field } = undefined;
            defer if (!@inComptime()) std.crypto.secureZero(u8, std.mem.asBytes(&scratch));
            scratch.t0 = p.x.sq();
            scratch.t1 = p.y.sq();
            scratch.t2 = p.z.sq();
            scratch.t3 = p.x.mul(p.y);
            scratch.t3 = scratch.t3.dbl();
            scratch.Z3 = p.x.mul(p.z);
            scratch.Z3 = scratch.Z3.add(scratch.Z3);
            scratch.Y3 = B.mul(scratch.t2);
            scratch.Y3 = scratch.Y3.sub(scratch.Z3);
            scratch.X3 = scratch.Y3.dbl();
            scratch.Y3 = scratch.X3.add(scratch.Y3);
            scratch.X3 = scratch.t1.sub(scratch.Y3);
            scratch.Y3 = scratch.t1.add(scratch.Y3);
            scratch.Y3 = scratch.X3.mul(scratch.Y3);
            scratch.X3 = scratch.X3.mul(scratch.t3);
            scratch.t3 = scratch.t2.dbl();
            scratch.t2 = scratch.t2.add(scratch.t3);
            scratch.Z3 = B.mul(scratch.Z3);
            scratch.Z3 = scratch.Z3.sub(scratch.t2);
            scratch.Z3 = scratch.Z3.sub(scratch.t0);
            scratch.t3 = scratch.Z3.dbl();
            scratch.Z3 = scratch.Z3.add(scratch.t3);
            scratch.t3 = scratch.t0.dbl();
            scratch.t0 = scratch.t3.add(scratch.t0);
            scratch.t0 = scratch.t0.sub(scratch.t2);
            scratch.t0 = scratch.t0.mul(scratch.Z3);
            scratch.Y3 = scratch.Y3.add(scratch.t0);
            scratch.t0 = p.y.mul(p.z);
            scratch.t0 = scratch.t0.dbl();
            scratch.Z3 = scratch.t0.mul(scratch.Z3);
            scratch.X3 = scratch.X3.sub(scratch.Z3);
            scratch.Z3 = scratch.t0.mul(scratch.t1);
            scratch.Z3 = scratch.Z3.dbl().dbl();
            return .{
                .x = scratch.X3,
                .y = scratch.Y3,
                .z = scratch.Z3,
            };
        }

        pub fn add(p: Self, q: Self) Self {
            @setRuntimeSafety(true);
            var scratch: struct { t0: Field, t1: Field, t2: Field, t3: Field, t4: Field, X3: Field, Y3: Field, Z3: Field } = undefined;
            defer if (!@inComptime()) std.crypto.secureZero(u8, std.mem.asBytes(&scratch));
            scratch.t0 = p.x.mul(q.x);
            scratch.t1 = p.y.mul(q.y);
            scratch.t2 = p.z.mul(q.z);
            scratch.t3 = p.x.add(p.y);
            scratch.t4 = q.x.add(q.y);
            scratch.t3 = scratch.t3.mul(scratch.t4);
            scratch.t4 = scratch.t0.add(scratch.t1);
            scratch.t3 = scratch.t3.sub(scratch.t4);
            scratch.t4 = p.y.add(p.z);
            scratch.X3 = q.y.add(q.z);
            scratch.t4 = scratch.t4.mul(scratch.X3);
            scratch.X3 = scratch.t1.add(scratch.t2);
            scratch.t4 = scratch.t4.sub(scratch.X3);
            scratch.X3 = p.x.add(p.z);
            scratch.Y3 = q.x.add(q.z);
            scratch.X3 = scratch.X3.mul(scratch.Y3);
            scratch.Y3 = scratch.t0.add(scratch.t2);
            scratch.Y3 = scratch.X3.sub(scratch.Y3);
            scratch.Z3 = B.mul(scratch.t2);
            scratch.X3 = scratch.Y3.sub(scratch.Z3);
            scratch.Z3 = scratch.X3.dbl();
            scratch.X3 = scratch.X3.add(scratch.Z3);
            scratch.Z3 = scratch.t1.sub(scratch.X3);
            scratch.X3 = scratch.t1.add(scratch.X3);
            scratch.Y3 = B.mul(scratch.Y3);
            scratch.t1 = scratch.t2.dbl();
            scratch.t2 = scratch.t1.add(scratch.t2);
            scratch.Y3 = scratch.Y3.sub(scratch.t2);
            scratch.Y3 = scratch.Y3.sub(scratch.t0);
            scratch.t1 = scratch.Y3.dbl();
            scratch.Y3 = scratch.t1.add(scratch.Y3);
            scratch.t1 = scratch.t0.dbl();
            scratch.t0 = scratch.t1.add(scratch.t0);
            scratch.t0 = scratch.t0.sub(scratch.t2);
            scratch.t1 = scratch.t4.mul(scratch.Y3);
            scratch.t2 = scratch.t0.mul(scratch.Y3);
            scratch.Y3 = scratch.X3.mul(scratch.Z3);
            scratch.Y3 = scratch.Y3.add(scratch.t2);
            scratch.X3 = scratch.t3.mul(scratch.X3);
            scratch.X3 = scratch.X3.sub(scratch.t1);
            scratch.Z3 = scratch.t4.mul(scratch.Z3);
            scratch.t1 = scratch.t3.mul(scratch.t0);
            scratch.Z3 = scratch.Z3.add(scratch.t1);
            return .{
                .x = scratch.X3,
                .y = scratch.Y3,
                .z = scratch.Z3,
            };
        }
    };
}
