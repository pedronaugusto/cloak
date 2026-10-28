// cloak's view of s2n-bignum's arm header, found before it on the include path: the header as it
// is, then every routine named cloak_<routine> and private to the image (so a program that also
// links AWS-LC's copy links), and on Windows COFF's function directive in place of ELF's. The
// routines themselves are s2n-bignum's files unchanged.
#include "s2n-bignum/include/_internal_s2n_bignum_arm.h"
#undef S2N_BN_SYMBOL
#undef S2N_BN_FUNCTION_TYPE_DIRECTIVE
#undef S2N_BN_SYM_PRIVACY_DIRECTIVE
#undef S2N_BN_SIZE_DIRECTIVE
#if defined(__APPLE__)
#   define S2N_BN_SYMBOL(name) _cloak_##name
#   define S2N_BN_FUNCTION_TYPE_DIRECTIVE(name)
#   define S2N_BN_SYM_PRIVACY_DIRECTIVE(name) .private_extern S2N_BN_SYMBOL(name)
#   define S2N_BN_SIZE_DIRECTIVE(name)
#elif defined(_WIN32)
#   define S2N_BN_SYMBOL(name) cloak_##name
#   define S2N_BN_FUNCTION_TYPE_DIRECTIVE(name) .def S2N_BN_SYMBOL(name) ; .scl 2 ; .type 32 ; .endef
#   define S2N_BN_SYM_PRIVACY_DIRECTIVE(name)
#   define S2N_BN_SIZE_DIRECTIVE(name)
#else
// A routine's own local functions (`Ledwards25519_decode_standard`) take these directives too, and
// keep upstream's names. Both go at the function's end, where `.ifdef` tells a renamed routine
// from a local label: ELF's `.type` may follow the definition.
#   define S2N_BN_SYMBOL(name) cloak_##name
#   define S2N_BN_FUNCTION_TYPE_DIRECTIVE(name)
#   define S2N_BN_SYM_PRIVACY_DIRECTIVE(name) .hidden S2N_BN_SYMBOL(name)
#   define S2N_BN_SIZE_DIRECTIVE(name) .ifdef S2N_BN_SYMBOL(name) ; .type S2N_BN_SYMBOL(name), %function ; .size S2N_BN_SYMBOL(name), .-S2N_BN_SYMBOL(name) ; .else ; .type name, %function ; .size name, .-name ; .endif
#endif
