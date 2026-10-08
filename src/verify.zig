//! Portable verification with explicit inputs and owned request-bound evidence.
const Verifier = @import("verify/Verifier.zig");
pub const verify = Verifier.verify;
pub const indexed = Verifier.indexed;
pub const nativePath = Verifier.nativePath;
pub const VerifyError = Verifier.VerifyError;
pub const Request = @import("types.zig").Request;
pub const Verification = @import("types.zig").Verification;
test {
    _ = @import("verify/Verifier.zig");
    _ = @import("verify/signature.zig");
    _ = @import("verify/constraints.zig");
    _ = @import("verify/revocation.zig");
    _ = @import("verify/identity.zig");
    _ = @import("verify/policy.zig");
    _ = @import("verify/Verifier_test.zig");
    _ = @import("verify/revocation_test.zig");
    _ = @import("verify/Verification_test.zig");
    _ = @import("verify/types_test.zig");
    _ = @import("verify/signature_test.zig");
    _ = @import("verify/constraints_test.zig");
    _ = @import("verify/limbo_test.zig");
    _ = @import("verify/parser_property_test.zig");
    _ = @import("verify/fuzz_parser_test.zig");
    _ = @import("verify/policy_test.zig");
    _ = @import("verify/wycheproof_test.zig");
    _ = @import("verify/credential_review_test.zig");
}
