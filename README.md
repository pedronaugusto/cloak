# cloak

A std-only TLS package for Zig 0.17.0, under construction.

This initial commit establishes build and CI infrastructure only. Credentials,
verification and the TLS engine are not supported by this floor. C1 security
review and evidence remain gates on the separate development branch.

## Install

Requires Zig 0.17.0. No release is available yet.

## Testing

`zig build check` compiles the floor. CI uses pinned preflight.

## Licence

MIT; see LICENSE.
