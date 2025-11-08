// include/math/fp_arithmetic.h
#ifndef FP_ARITHMETIC_H
#define FP_ARITHMETIC_H

#include "torus_common.h"
#include "fp_types.h"
#include "math/montgomery.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file fp_arithmetic.h
 * @brief Finite field arithmetic operations for Fp
 * @ingroup math
 * 
 * This module provides optimized arithmetic operations in the finite field Fp
 * used by the TorusCSIDH cryptographic system. All operations are implemented
 * in constant-time to prevent timing attacks.
 */

/**
 * @brief Finite field context structure
 */
typedef struct {
    fp modulus;                    ///< Prime modulus
    montgomery_ctx_t montgomery_ctx; ///< Montgomery multiplication context
    fp p_minus_2;                 ///< Precomputed p - 2 for exponentiation
    fp p_plus_1_div_4;            ///< Precomputed (p + 1) / 4 for square roots
    fp temp;                      ///< Temporary storage for computations
    uint32_t security_level;      ///< Security level parameter
} fp_ctx_t;

/**
 * @brief Initialize finite field context
 * 
 * @param ctx Field context to initialize
 * @param modulus Prime modulus
 * @param security_level Security level parameter
 * @return TORUS_SUCCESS on success, error code on failure
 * 
 * @security This function does not handle secret data
 */
TORUS_API int fp_ctx_init(fp_ctx_t* ctx, const fp* modulus, uint32_t security_level);

/**
 * @brief Cleanup finite field context
 * 
 * @param ctx Field context to cleanup
 * 
 * @security Zeroizes sensitive data in context
 */
TORUS_API void fp_ctx_cleanup(fp_ctx_t* ctx);

/**
 * @brief Set finite field element to zero
 * 
 * @param a Element to set to zero
 * 
 * @security Constant-time execution
 */
TORUS_API void fp_set_zero(fp* a);

/**
 * @brief Set finite field element to one
 * 
 * @param a Element to set to one
 * @param ctx Field context
 * 
 * @security Constant-time execution
 */
TORUS_API void fp_set_one(fp* a, const fp_ctx_t* ctx);

/**
 * @brief Set finite field element from 64-bit unsigned integer
 * 
 * @param a Element to set
 * @param value 64-bit unsigned integer value
 * @param ctx Field context
 * 
 * @security Constant-time execution
 */
TORUS_API void fp_set_u64(fp* a, uint64_t value, const fp_ctx_t* ctx);

/**
 * @brief Set finite field element from bytes (big-endian)
 * 
 * @param a Element to set
 * @param bytes Input byte array (big-endian)
 * @param ctx Field context
 * 
 * @security Constant-time execution
 */
TORUS_API void fp_set_bytes(fp* a, const uint8_t* bytes, const fp_ctx_t* ctx);

/**
 * @brief Check if finite field element is zero
 * 
 * @param a Element to check
 * @return 1 if zero, 0 otherwise
 * 
 * @security Constant-time execution
 */
TORUS_API int fp_is_zero(const fp* a);

/**
 * @brief Check if finite field element is one
 * 
 * @param a Element to check
 * @param ctx Field context
 * @return 1 if one, 0 otherwise
 * 
 * @security Constant-time execution
 */
TORUS_API int fp_is_one(const fp* a, const fp_ctx_t* ctx);

/**
 * @brief Compare two finite field elements
 * 
 * @param a First element
 * @param b Second element
 * @return 1 if equal, 0 otherwise
 * 
 * @security Constant-time execution
 */
TORUS_API int fp_equal(const fp* a, const fp* b);

/**
 * @brief Copy finite field element
 * 
 * @param dst Destination element
 * @param src Source element
 * 
 * @security Constant-time execution
 */
TORUS_API void fp_copy(fp* dst, const fp* src);

/**
 * @brief Generate random finite field element
 * 
 * @param a Element to generate
 * @param ctx Field context
 * @return TORUS_SUCCESS on success, error code on failure
 * 
 * @security Uses cryptographically secure RNG
 */
TORUS_API int fp_random(fp* a, const fp_ctx_t* ctx);

/**
 * @brief Generate random non-zero finite field element
 * 
 * @param a Element to generate
 * @param ctx Field context
 * @return TORUS_SUCCESS on success, error code on failure
 * 
 * @security Uses cryptographically secure RNG
 */
TORUS_API int fp_random_nonzero(fp* a, const fp_ctx_t* ctx);

/**
 * @brief Modular addition: c = a + b mod p
 * 
 * @param c Result element
 * @param a First operand
 * @param b Second operand
 * @param ctx Field context
 * 
 * @security Constant-time execution
 */
TORUS_API void fp_add(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx);

/**
 * @brief Modular subtraction: c = a - b mod p
 * 
 * @param c Result element
 * @param a First operand
 * @param b Second operand
 * @param ctx Field context
 * 
 * @security Constant-time execution
 */
TORUS_API void fp_sub(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx);

/**
 * @brief Modular multiplication: c = a * b mod p
 * 
 * @param c Result element
 * @param a First operand
 * @param b Second operand
 * @param ctx Field context
 * 
 * @security Constant-time execution
 */
TORUS_API void fp_mul(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx);

/**
 * @brief Modular squaring: c = a^2 mod p
 * 
 * @param c Result element
 * @param a Element to square
 * @param ctx Field context
 * 
 * @security Constant-time execution
 */
TORUS_API void fp_sqr(fp* c, const fp* a, const fp_ctx_t* ctx);

/**
 * @brief Modular inversion: c = a^{-1} mod p
 * 
 * @param c Result element
 * @param a Element to invert
 * @param ctx Field context
 * @return TORUS_SUCCESS on success, error code if a is zero
 * 
 * @security Constant-time execution
 */
TORUS_API int fp_inv(fp* c, const fp* a, const fp_ctx_t* ctx);

/**
 * @brief Modular negation: c = -a mod p
 * 
 * @param c Result element
 * @param a Element to negate
 * @param ctx Field context
 * 
 * @security Constant-time execution
 */
TORUS_API void fp_neg(fp* c, const fp* a, const fp_ctx_t* ctx);

/**
 * @brief Modular exponentiation: c = a^e mod p
 * 
 * @param c Result element
 * @param a Base element
 * @param e Exponent
 * @param ctx Field context
 * 
 * @security Constant-time execution
 */
TORUS_API void fp_pow(fp* c, const fp* a, const fp* e, const fp_ctx_t* ctx);

/**
 * @brief Modular exponentiation with unsigned integer exponent
 * 
 * @param c Result element
 * @param a Base element
 * @param exponent Unsigned integer exponent
 * @param ctx Field context
 * 
 * @security Constant-time execution
 */
TORUS_API void fp_pow_u64(fp* c, const fp* a, uint64_t exponent, const fp_ctx_t* ctx);

/**
 * @brief Modular reduction: a = a mod p
 * 
 * @param a Element to reduce
 * @param ctx Field context
 * 
 * @security Constant-time execution
 */
TORUS_API void fp_reduce(fp* a, const fp_ctx_t* ctx);

/**
 * @brief Check if element is quadratic residue
 * 
 * @param a Element to check
 * @param ctx Field context
 * @return 1 if quadratic residue, 0 otherwise
 * 
 * @security Constant-time execution
 */
TORUS_API int fp_is_square(const fp* a, const fp_ctx_t* ctx);

/**
 * @brief Compute square root modulo p
 * 
 * @param c Square root result
 * @param a Element to take square root of
 * @param ctx Field context
 * @return TORUS_SUCCESS on success, error code if no square root exists
 * 
 * @security Constant-time execution
 */
TORUS_API int fp_sqrt(fp* c, const fp* a, const fp_ctx_t* ctx);

/**
 * @brief Convert to Montgomery representation
 * 
 * @param c Result in Montgomery form
 * @param a Element to convert
 * @param ctx Field context
 * 
 * @security Constant-time execution
 */
TORUS_API void fp_to_montgomery(fp* c, const fp* a, const fp_ctx_t* ctx);

/**
 * @brief Convert from Montgomery representation
 * 
 * @param c Result in normal form
 * @param a Element in Montgomery form
 * @param ctx Field context
 * 
 * @security Constant-time execution
 */
TORUS_API void fp_from_montgomery(fp* c, const fp* a, const fp_ctx_t* ctx);

/**
 * @brief Serialize finite field element to bytes (big-endian)
 * 
 * @param bytes Output byte array (must be at least FP_BYTES)
 * @param a Element to serialize
 * @param ctx Field context
 * 
 * @security Constant-time execution
 */
TORUS_API void fp_to_bytes(uint8_t* bytes, const fp* a, const fp_ctx_t* ctx);

/**
 * @brief Deserialize finite field element from bytes (big-endian)
 * 
 * @param a Element to store result
 * @param bytes Input byte array (big-endian)
 * @param ctx Field context
 * @return TORUS_SUCCESS on success, error code on failure
 * 
 * @security Constant-time execution
 */
TORUS_API int fp_from_bytes(fp* a, const uint8_t* bytes, const fp_ctx_t* ctx);

/**
 * @brief Check if element is in canonical form (reduced modulo p)
 * 
 * @param a Element to check
 * @param ctx Field context
 * @return 1 if canonical, 0 otherwise
 * 
 * @security Constant-time execution
 */
TORUS_API int fp_is_canonical(const fp* a, const fp_ctx_t* ctx);

/**
 * @brief Conditional move: dst = src if condition is true
 * 
 * @param dst Destination element
 * @param src Source element
 * @param condition Selection condition (0 or 1)
 * 
 * @security Constant-time execution, branch-free
 */
TORUS_API void fp_cmov(fp* dst, const fp* src, uint8_t condition);

/**
 * @brief Conditional swap: swap a and b if condition is true
 * 
 * @param a First element
 * @param b Second element
 * @param condition Swap condition (0 or 1)
 * 
 * @security Constant-time execution, branch-free
 */
TORUS_API void fp_cswap(fp* a, fp* b, uint8_t condition);

/**
 * @brief Get bit at specified position (constant-time)
 * 
 * @param a Element to get bit from
 * @param bit_index Bit index (0 = least significant bit)
 * @param ctx Field context
 * @return 0 or 1 (the bit value)
 * 
 * @security Constant-time execution
 */
TORUS_API uint8_t fp_get_bit(const fp* a, uint32_t bit_index, const fp_ctx_t* ctx);

/**
 * @brief Get number of bits in the modulus
 * 
 * @param ctx Field context
 * @return Number of bits in modulus
 */
TORUS_API uint32_t fp_get_bits(const fp_ctx_t* ctx);

/**
 * @brief Get number of bytes needed to represent modulus
 * 
 * @param ctx Field context
 * @return Number of bytes
 */
TORUS_API uint32_t fp_get_bytes(const fp_ctx_t* ctx);

// Optimized versions for specific architectures
#ifdef __AVX2__
TORUS_API void fp_add_avx2(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx);
TORUS_API void fp_sub_avx2(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx);
TORUS_API void fp_mul_avx2(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx);
TORUS_API void fp_sqr_avx2(fp* c, const fp* a, const fp_ctx_t* ctx);
#endif

#ifdef __ARM_NEON
TORUS_API void fp_add_neon(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx);
TORUS_API void fp_sub_neon(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx);
TORUS_API void fp_mul_neon(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx);
TORUS_API void fp_sqr_neon(fp* c, const fp* a, const fp_ctx_t* ctx);
#endif

#ifdef __cplusplus
}
#endif

#endif /* FP_ARITHMETIC_H */
