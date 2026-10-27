// cloak's view of s2n-bignum's x86 header, found before it on the include path: the header as it
// is, then every routine named cloak_<routine> and private to the image (so a program that also
// links AWS-LC's copy links), and on Windows COFF's function directive in place of ELF's. The
// routines themselves are s2n-bignum's files unchanged.
#include "s2n-bignum/include/_internal_s2n_bignum_x86.h"
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
#   define S2N_BN_SYMBOL(name) cloak_##name
#   define S2N_BN_FUNCTION_TYPE_DIRECTIVE(name) .type S2N_BN_SYMBOL(name), %function
#   define S2N_BN_SYM_PRIVACY_DIRECTIVE(name) .hidden S2N_BN_SYMBOL(name)
#   define S2N_BN_SIZE_DIRECTIVE(name) .size S2N_BN_SYMBOL(name), .-S2N_BN_SYMBOL(name)
#endif
