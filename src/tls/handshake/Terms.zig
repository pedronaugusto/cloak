//! What both roles of the handshake share with their drivers and with post-handshake
//! authentication: the bounds on what a peer sends, how a peer is verified, and the services the
//! handshake asks for.
const certificates = @import("../../certificates.zig");
const types = certificates.types;
const Hello = @import("Hello.zig");
const Messages = @import("Messages.zig");
const Delegation = @import("Delegation.zig");

pub const Limits = struct {
    /// One handshake message, header included.
    message: usize = 128 * 1024,
    /// All handshake messages of one connection before it is established.
    handshake: usize = 256 * 1024,
    /// Total DER bytes of a peer chain.
    chain_bytes: usize = 64 * 1024,
    /// Entries of a peer chain.
    certificates: usize = Messages.max_certificates,
};

/// Peer verification. `none` is an explicit choice and yields an unauthenticated connection.
/// `raw_key` trusts a raw public key (RFC 7250, TLS 1.3 and 1.2) by its pin and nothing else: no
/// certificate, name or trust store is involved, and a peer presenting certificates is refused.
pub const Verify = union(enum) {
    none,
    full: Full,
    /// A raw public key (RFC 7250) trusted by its pin; no certificate is taken.
    raw_key: Pins,
    /// A certificate taken for its leaf's key alone, trusted by its pin: no path, name, validity,
    /// usage or revocation is checked (designs/cloak.md §5.2, a pin with no authorities).
    leaf_key: Pins,
    pub const Pins = struct {
        /// The SHA-256 of each SubjectPublicKeyInfo the peer may hold, at least one and at most
        /// `max_pins`; `Info.pin` names the one it proved.
        pins: []const [32]u8,
        pub const max_pins = 1024;
    };
    pub const Full = struct {
        trust_generation: types.TrustGeneration,
        policy_generation: types.PolicyGeneration = .fromRaw(1),
        policy: types.Policy = .{},
        pins: []const [32]u8 = &.{},
        evidence: types.Evidence = .{},
        limits: types.Limits = .{},
        anchor_policies: []const types.AnchorPolicy = &.{},
    };
};

pub const Need = union(enum) {
    none,
    /// Exactly `len` fresh CSPRNG bytes.
    entropy: struct { len: usize },
    /// Real (calendar) time in seconds.
    time,
    /// Peer chain verification.
    verify,
    /// A CertificateVerify signature for the client certificate.
    sign,
    /// Peer QUIC transport parameters need an accept or reject.
    parameters,
};

/// What a key held elsewhere must sign. `prehashed` content is already the digest of the
/// scheme's hash (a TLS 1.2 CertificateVerify signs the transcript hash); sign it as is.
pub const SignRequest = struct {
    scheme: Hello.SignatureScheme,
    content: []const u8,
    prehashed: bool = false,
    /// The credential that signs: its index in the server's or the client's credentials.
    credential: u8 = 0,

    /// Signs this request with `key`, as cloak signs with a key it holds: for a driver that signs
    /// away from the handshake (a worker thread, a process holding the key). The scheme binds to
    /// the key as a TLS 1.2 signature's does, the loosest binding cloak chooses schemes within;
    /// `noise` is `key.noiseLength()` fresh bytes. The connection checks the signature against
    /// the credential before it is sent.
    pub fn signWith(request: SignRequest, key: certificates.PrivateKey, noise: []const u8, out: *[certificates.PrivateKey.max_signature]u8) error{SigningFailed}![]const u8 {
        @setRuntimeSafety(true);
        var info: [certificates.PrivateKey.max_public_key_info]u8 = undefined;
        const public_key = certificates.certificate.parsePublicKey(key.publicKeyInfo(&info)) catch return error.SigningFailed;
        const algorithm = @import("Possession.zig").bind12(request.scheme, public_key) catch return error.SigningFailed;
        if (request.prehashed) return key.signDigest(algorithm, request.content, noise, out) catch error.SigningFailed;
        return key.sign(algorithm, request.content, noise, out) catch error.SigningFailed;
    }
};

/// A certificate chain or raw public key a client can present, with its delegated credential.
pub const ClientCredential = struct {
    auth: certificates.ClientAuth,
    /// A delegated credential of `auth`'s certificate (RFC 9345, role `client`), presented with
    /// it when the server's CertificateRequest takes one; its key signs then. Needs full
    /// verification of the server, whose clock decides whether it is still valid.
    delegated: ?Delegation.Credential = null,
    /// The signature schemes `auth`'s key signs under, in this client's order, borrowed; empty for
    /// every scheme the key can make, in cloak's order. As a server credential's `schemes`.
    schemes: []const Hello.SignatureScheme = &.{},
    /// Presented only when the CertificateRequest names an issuer in the chain (BoringSSL's
    /// must-match-issuer); otherwise passed over, as one the request does not take.
    must_match_issuer: bool = false,

    /// The most a client holds, as a server.
    pub const max = 32;
};
