//! The handshake's error sets, shared by both roles and both versions without importing a role.
const std = @import("std");
const Hello = @import("Hello.zig");
const ClientHello = @import("ClientHello.zig");
const Messages = @import("Messages.zig");
const State = @import("State.zig");
const Transcripts = @import("Transcripts.zig");
const Possession = @import("Possession.zig");
const Schedule = @import("Schedule.zig");
const Labels = @import("../crypto/Labels.zig");
const Exchange = @import("../crypto/Exchange.zig");
const Prf = @import("../crypto/Prf.zig");

pub const Error = State.AdvanceError || Hello.ParseError || Hello.EncodeError || Messages.ParseError ||
    Transcripts.CommitError || Labels.CheckError || Possession.Error || Exchange.AgreeError ||
    Schedule.InitError || Schedule.AdvanceError ||
    std.mem.Allocator.Error || error{
    Pending,
    InvalidEntropy,
    EntropyUnavailable,
    BadSignature,
    SigningFailed,
    VerificationFailed,
    VerificationRejected,
    ParametersRejected,
    UnexpectedService,
    QueueFull,
    NoSharedGroup,
    NoSharedSuite,
    NoSignatureScheme,
    UnrecognizedName,
    CertificateRequired,
    UnexpectedCookie,
    InappropriateFallback,
    NoClientCertificate,
    BadBinder,
    /// The peer's authentication is not post-quantum where the policy requires it
    /// (`require_pq_auth`): a classical signature on its path.
    PqAuthenticationRequired,
    /// A certificate of a type the policy does not take (RFC 7250): an X.509 chain where only a
    /// pinned raw public key is, or a raw key where certificates are.
    UnsupportedCertificate,
    /// A raw public key that no pin names.
    PinMismatch,
    /// The server did not accept Encrypted Client Hello: the connection ends with ech_required.
    EchRejected,
    /// A second ClientHelloOuter's payload does not open under the first one's HPKE context.
    EchDecryptFailed,
} || ClientHello.ParseError;

pub const ExportError = Schedule.ExportError || Prf.ExportError;
