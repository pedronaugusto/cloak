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
    Renegotiation,
    InappropriateFallback,
} || ClientHello.ParseError;

pub const ExportError = Schedule.ExportError || Prf.ExportError;
