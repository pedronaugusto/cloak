//! The ROCA fingerprint against the published detector's masks and test keys (crocs-muni/roca,
//! MIT; testdata/roca, see provenance.md).
const std = @import("std");
const roca = @import("roca.zig");

test "C1 ROCA masks: derived from 65537's powers, equal to the published detector's" {
    const published = [_]u256{ 6, 30, 126, 1026, 5658, 107286, 199410, 8388606, 536870910, 2147483646, 67109890, 2199023255550, 8796093022206, 140737488355326, 5310023542746834, 576460752303423486, 1455791217086302986, 147573952589676412926, 20052041432995567486, 6041388139249378920330, 207530445072488465666, 9671406556917033397649406, 618970019642690137449562110, 79228162521181866724264247298, 2535301200456458802993406410750, 1760368345969468176824550810518, 50079290986288516948354744811034, 473022961816146413042658758988474, 10384593717069655257060992658440190, 144390480366845522447407333004847678774, 2722258935367507707706996859454145691646, 174224571863520493293247799005065324265470, 696898287454081973172991196020261297061886, 713623846352979940529142984724747568191373310, 1800793591454480341970779146165214289059119882, 126304807362733370595828809000324029340048915994, 11692013098647223345629478661730264157247460343806, 187072209578355573530071658587684226515959365500926 };
    try std.testing.expectEqualSlices(u256, &published, &roca.masks);
}

fn hexModulus(comptime text: []const u8) []const u8 {
    const trimmed = comptime std.mem.trim(u8, text, " \n\r");
    const digits = comptime trimmed[2..];
    const bytes = comptime blk: {
        @setEvalBranchQuota(100_000);
        var out: [digits.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, digits) catch unreachable;
        break :blk out;
    };
    return &bytes;
}

test "C1 ROCA moduli: the published positive moduli have it, its negatives do not" {
    try std.testing.expect(roca.fingerprinted(hexModulus(@embedFile("testdata/roca/mod03.txt"))));
    try std.testing.expect(roca.fingerprinted(hexModulus(@embedFile("testdata/roca/mod09.txt"))));
    try std.testing.expect(!roca.fingerprinted(hexModulus(@embedFile("testdata/roca/mod04.txt"))));
}
