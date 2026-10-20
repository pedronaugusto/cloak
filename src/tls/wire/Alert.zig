//! TLS alert descriptions (RFC 8446 section 6) that this engine sends or names.
pub const Alert = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    record_overflow = 22,
    /// TLS 1.2 (RFC 5246 section 7.2.2); cloak compresses no records, so it only receives it.
    decompression_failure = 30,
    handshake_failure = 40,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    /// DTLS 1.3: a peer asked for more connection IDs than it may (RFC 9147 section 9).
    too_many_cids_requested = 52,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    inappropriate_fallback = 86,
    user_canceled = 90,
    no_renegotiation = 100,
    missing_extension = 109,
    unsupported_extension = 110,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,
    /// The client offered ECH and the server did not accept it (RFC 9849 section 11.2).
    ech_required = 121,
    _,

    /// QUIC reports a TLS alert as the crypto error 0x100 plus its description (RFC 9001).
    pub fn quicError(alert: Alert) u16 {
        return 0x100 + @as(u16, @backingInt(alert));
    }
};
