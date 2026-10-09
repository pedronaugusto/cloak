# cloak

Work in progress: credentials, certificate verification and TLS 1.3 foundations for Zig consumers. The TLS engine is under construction; this package does not yet provide an encrypted stream.

## Install

Requires Zig 0.17.0. Pin a reviewed commit:

```sh
zig fetch --save git+https://github.com/pedronaugusto/cloak#<commit>
```

## Usage

Load trust before traffic and retain a snapshot while using its issuer index. The verifier takes explicit time, name, policy generations and a completion token:

<!-- BEGIN GENERATED zig build docs -- usage -->
```zig
const std = @import("std");
const cloak = @import("cloak");

pub fn authenticate(
    gpa: std.mem.Allocator,
    roots: []const []const u8,
    chain: []const []const u8,
    name: []const u8,
    time: i64,
    token: cloak.types.Token,
) !cloak.types.Verification {
    @setRuntimeSafety(true);
    var trust = cloak.Trust.init(gpa);
    defer trust.deinit();
    for (roots) |der| try trust.addDer(der, .{});
    const snapshot = try trust.freeze();
    defer snapshot.deinit();
    return cloak.verify.indexed(gpa, .{
        .chain = chain,
        .identity = .{ .dns = name },
        .time = time,
        .trust_generation = snapshot.generation(),
        .policy_generation = .fromRaw(1),
        .token = token,
    }, snapshot.issuers());
}
```
<!-- END GENERATED zig build docs -- usage -->

The returned receipt owns the selected DER path; its caller calls `deinit()`. Check it against the unchanged request before accepting a service completion. Snapshot generations are scoped to their builder; reload across owners also changes the caller's policy generation and completion token.

`PrivateKey.parse` owns its material and wipes it on final release. RSA parsing requires fresh caller CSPRNG witnesses through `PrivateKey.Entropy.fromIo(&io)`. Passphrases and Io are borrowed only for the parse call. `Identity.init` copies the chain, checks the leaf key and retains the key; `ClientAuth` shares that immutable identity.

Native system trust uses `NativeVerification` with an empty explicit-anchor list. A finite timeout requires a bounded caller executor before inputs are copied. The executor owns the completion until it runs and releases it, including after abandonment and during shutdown. The driver applies portable floors to the exact OS-selected chain before returning a receipt. See [ownership and integration](docs/design.md).

## Design

One owner per state. Runtime code uses [aegis](https://github.com/pedronaugusto/aegis), Zig's standard library and native platform trust APIs. Credentials, verification and native services import only lower certificate, wire and value layers. The portable core takes explicit time and trust; it performs no network discovery.

## Scope

Cloak implements credentials and certificate verification, plus private TLS 1.3 record protection, HKDF/Finished, bounded transcript and checked transition foundations. A usable TLS client, stream adapter and record-free QUIC client are still under construction. Resumption, datagrams and offload follow their own phases. No application protocol, dialer or resolver lives here.

The build exposes `cloak.certificates` for certificates, keys and trust, and
`cloak.tls` for TLS. `cloak` retains the existing credential names and exposes
`certificates` and `tls` namespaces. TLS currently exposes only suite vocabulary;
record seal/open and transcript mutation stay private. DTLS will be a separate
module when its datagram implementation is built.

## Platforms

Portable verification uses explicit trust. Linux and BSD system policy loads bounded root files. macOS and Windows system policy requires native verification with network retrieval disabled.

## Built with

[preflight](https://github.com/pedronaugusto/preflight) supplies the build and CI gate. [shakedown](https://github.com/pedronaugusto/shakedown) is a lazy test-only dependency. Neither belongs to the runtime closure.

## Testing

```sh
zig build test -Dtest-filter=trust
zig build lint
zig build check
zig build bench
```

CI plans come from `zig build plan`. Benchmarks compile in CI; measurements run by hand in ReleaseFast. `zig build check-wasm` executes portable vectors without hosted Io. `zig build fuzz -Dtest-filter="credential key parser fuzz" --fuzz=100K` uses the compiler fuzz runner. Source functions explicitly retain runtime safety in ReleaseFast; optimized parser, credential and service checks are part of lint.

## Licence

MIT; see [LICENSE](LICENSE).

## Security

Report vulnerabilities privately through GitHub private vulnerability reporting,
never in public issues. See [SECURITY.md](SECURITY.md) for supported versions and
the reporting policy.
