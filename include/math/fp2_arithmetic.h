// include/math/fp2_arithmetic.h
#ifndef FP2_ARITHMETIC_H
#define FP2_ARITHMETIC_H

#include "math/fp_arithmetic.h"
#include "math/fp_types.h"
#include "torus_errors.h"
#include "torus_common.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Constants and Configuration
// ============================================================================

/**
 * @file fp2_arithmetic.h
 * @brief Arithmetic operations in quadratic extension field Fp2
 * 
 * This module implements arithmetic operations in the quadratic extension field Fp2,
 * where Fp2 = Fp[i]/(i^2 + 1). Elements are represented as a + bi where a, b ∈ Fp.
 * All operations are implemented in constant-time to prevent timing attacks.
 */

/**
 * @brief Maximum number of attempts for random number generation
 */
#define FP2_MAX_RANDOM_ATTEMPTS 256

/**
 * @brief Maximum number of iterations for Tonelli-Shanks algorithm
 */
#define FP2_MAX_TS_ITERATIONS 100

/**
 * @brief Element of Fp2 field
 * 
 * Represents an element a + bi in Fp2, where i^2 = -1.
 */
typedef struct {
    fp x;  /**< Real part (a) */
    fp y;  /**< Imaginary part (b) */
} fp2;

/**
 * @brief Fp2 context structure
 */
typedef struct {
    fp_ctx_t fp_ctx;           ///< Base field context
    fp2 non_residue;          ///< Non-residue for Fp2 construction
    uint32_t security_level;  ///< Security level parameter
    uint8_t p_mod_4_is_3;    ///< Flag indicating if p ≡ 3 mod 4
    uint8_t p_mod_8_is_5;    ///< Flag indicating if p ≡ 5 mod 8
} fp2_ctx_t;

// ============================================================================
// Context Management
// ============================================================================

/**
 * @brief Initialize Fp2 context
 * 
 * @param ctx Fp2 context to initialize
 * @param fp_ctx Base field context
 * @param security_level Security level parameter
 * @return int TORUS_SUCCESS on success, error code on failure
 */
TORUS_API int fp2_ctx_init(fp2_ctx_t* ctx, const fp_ctx_t* fp_ctx, uint32_t security_level);

/**
 * @brief Cleanup Fp2 context
 * 
 * @param ctx Fp2 context to cleanup
 */
TORUS_API void fp2_ctx_cleanup(fp2_ctx_t* ctx);

// ============================================================================
// Basic Operations
// ============================================================================

/**
 * @brief Set Fp2 element to zero
 * 
 * @param a Fp2 element to set to zero
 * @param ctx Fp2 context
 */
TORUS_API void fp2_set_zero(fp2* a, const fp2_ctx_t* ctx);

/**
 * @brief Set Fp2 element to one
 * 
 * @param a Fp2 element to set to one
 * @param ctx Fp2 context
 */
TORUS_API void fp2_set_one(fp2* a, const fp2_ctx_t* ctx);

/**
 * @brief Set Fp2 element from unsigned 64-bit integer
 * 
 * @param a Fp2 element to set
 * @param value Integer value to set
 * @param ctx Fp2 context
 */
TORUS_API void fp2_set_u64(fp2* a, uint64_t value, const fp2_ctx_t* ctx);

/**
 * @brief Set Fp2 element from two Fp elements
 * 
 * @param a Fp2 element to set
 * @param real Real part
 * @param imag Imaginary part
 * @param ctx Fp2 context
 */
TORUS_API void fp2_set_fp(fp2* a, const fp* real, const fp* imag, const fp2_ctx_t* ctx);

/**
 * @brief Set Fp2 element from bytes (big-endian)
 * 
 * @param a Fp2 element to set
 * @param bytes Input byte array (big-endian, real followed by imaginary)
 * @param ctx Fp2 context
 */
TORUS_API void fp2_set_bytes(fp2* a, const uint8_t* bytes, const fp2_ctx_t* ctx);

/**
 * @brief Check if Fp2 element is zero
 * 
 * @param a Fp2 element to check
 * @param ctx Fp2 context
 * @return int 1 if zero, 0 otherwise
 */
TORUS_API int fp2_is_zero(const fp2* a, const fp2_ctx_t* ctx);

/**
 * @brief Check if Fp2 element is one
 * 
 * @param a Fp2 element to check
 * @param ctx Fp2 context
 * @return int 1 if one, 0 otherwise
 */
TORUS_API int fp2_is_one(const fp2* a, const fp2_ctx_t* ctx);

/**
 * @brief Compare two Fp2 elements for equality
 * 
 * @param a First Fp2 element
 * @param b Second Fp2 element
 * @param ctx Fp2 context
 * @return int 1 if equal, 0 otherwise
 */
TORUS_API int fp2_equal(const fp2* a, const fp2* b, const fp2_ctx_t* ctx);

/**
 * @brief Generate random Fp2 element
 * 
 * @param a Fp2 element to store result
 * @param ctx Fp2 context
 * @return int TORUS_SUCCESS on success, error code on failure
 */
TORUS_API int fp2_random(fp2* a, const fp2_ctx_t* ctx);

/**
 * @brief Generate random non-zero Fp2 element
 * 
 * @param a Fp2 element to store result
 * @param ctx Fp2 context
 * @return int TORUS_SUCCESS on success, error code on failure
 */
TORUS_API int fp2_random_nonzero(fp2* a, const fp2_ctx_t* ctx);

/**
 * @brief Copy Fp2 element
 * 
 * @param dst Destination Fp2 element
 * @param src Source Fp2 element
 * @param ctx Fp2 context
 */
TORUS_API void fp2_copy(fp2* dst, const fp2* src, const fp2_ctx_t* ctx);

// ============================================================================
// Arithmetic Operations
// ============================================================================

/**
 * @brief Fp2 addition: c = a + b
 * 
 * @param c Result Fp2 element
 * @param a First Fp2 element
 * @param b Second Fp2 element
 * @param ctx Fp2 context
 */
TORUS_API void fp2_add(fp2* c, const fp2* a, const fp2* b, const fp2_ctx_t* ctx);

/**
 * @brief Fp2 subtraction: c = a - b
 * 
 * @param c Result Fp2 element
 * @param a First Fp2 element
 * @param b Second Fp2 element
 * @param ctx Fp2 context
 */
TORUS_API void fp2_sub(fp2* c, const fp2* a, const fp2* b, const fp2_ctx_t* ctx);

/**
 * @brief Fp2 negation: c = -a
 * 
 * @param c Result Fp2 element
 * @param a Fp2 element to negate
 * @param ctx Fp2 context
 */
TORUS_API void fp2_neg(fp2* c, const fp2* a, const fp2_ctx_t* ctx);

/**
 * @brief Fp2 multiplication: c = a * b
 * 
 * @param c Result Fp2 element
 * @param a First Fp2 element
 * @param b Second Fp2 element
 * @param ctx Fp2 context
 */
TORUS_API void fp2_mul(fp2* c, const fp2* a, const fp2* b, const fp2_ctx_t* ctx);

/**
 * @brief Fp2 squaring: c = a^2
 * 
 * @param c Result Fp2 element
 * @param a Fp2 element to square
 * @param ctx Fp2 context
 */
TORUS_API void fp2_sqr(fp2* c, const fp2* a, const fp2_ctx_t* ctx);

/**
 * @brief Fp2 inversion: c = a^(-1)
 * 
 * @param c Result Fp2 element
 * @param a Fp2 element to invert
 * @param ctx Fp2 context
 * @return int TORUS_SUCCESS on success, TORUS_ERROR_DIVISION_BY_ZERO if a is zero
 */
TORUS_API int fp2_inv(fp2* c, const fp2* a, const fp2_ctx_t* ctx);

/**
 * @brief Fp2 division: c = a / b
 * 
 * @param c Result Fp2 element
 * @param a Numerator Fp2 element
 * @param b Denominator Fp2 element
 * @param ctx Fp2 context
 * @return int TORUS_SUCCESS on success, TORUS_ERROR_DIVISION_BY_ZERO if b is zero
 */
TORUS_API int fp2_div(fp2* c, const fp2* a, const fp2* b, const fp2_ctx_t* ctx);

/**
 * @brief Fp2 scalar multiplication: c = a * k, where k ∈ Fp
 * 
 * @param c Result Fp2 element
 * @param a Fp2 element
 * @param k Scalar in Fp
 * @param ctx Fp2 context
 */
TORUS_API void fp2_mul_scalar(fp2* c, const fp2* a, const fp* k, const fp2_ctx_t* ctx);

/**
 * @brief Fp2 scalar multiplication with unsigned integer: c = a * k
 * 
 * @param c Result Fp2 element
 * @param a Fp2 element
 * @param k Unsigned integer scalar
 * @param ctx Fp2 context
 */
TORUS_API void fp2_mul_u64(fp2* c, const fp2* a, uint64_t k, const fp2_ctx_t* ctx);

// ============================================================================
// Advanced Operations
// ============================================================================

/**
 * @brief Fp2 complex conjugation: c = conjugate(a)
 * 
 * @param c Result Fp2 element
 * @param a Fp2 element to conjugate
 * @param ctx Fp2 context
 */
TORUS_API void fp2_conj(fp2* c, const fp2* a, const fp2_ctx_t* ctx);

/**
 * @brief Fp2 norm: n = a * conjugate(a) = a.x^2 + a.y^2
 * 
 * @param n Result Fp element (norm)
 * @param a Fp2 element
 * @param ctx Fp2 context
 */
TORUS_API void fp2_norm(fp* n, const fp2* a, const fp2_ctx_t* ctx);

/**
 * @brief Check if Fp2 element is a square
 * 
 * @param a Fp2 element to check
 * @param ctx Fp2 context
 * @return int 1 if square, 0 otherwise
 */
TORUS_API int fp2_is_square(const fp2* a, const fp2_ctx_t* ctx);

/**
 * @brief Compute square root in Fp2
 * 
 * @param c Result Fp2 element (square root)
 * @param a Fp2 element to take square root of
 * @param ctx Fp2 context
 * @return int TORUS_SUCCESS on success, TORUS_ERROR_NOT_QUADRATIC_RESIDUE if no square root exists
 */
TORUS_API int fp2_sqrt(fp2* c, const fp2* a, const fp2_ctx_t* ctx);

/**
 * @brief Fp2 exponentiation: c = a^e
 * 
 * @param c Result Fp2 element
 * @param a Base Fp2 element
 * @param e Exponent (Fp element)
 * @param ctx Fp2 context
 */
TORUS_API void fp2_pow(fp2* c, const fp2* a, const fp* e, const fp2_ctx_t* ctx);

/**
 * @brief Fp2 exponentiation with unsigned integer exponent
 * 
 * @param c Result Fp2 element
 * @param a Base Fp2 element
 * @param exponent Unsigned integer exponent
 * @param ctx Fp2 context
 */
TORUS_API void fp2_pow_u64(fp2* c, const fp2* a, uint64_t exponent, const fp2_ctx_t* ctx);

/**
 * @brief Fp2 Frobenius endomorphism: c = a^p
 * 
 * @param c Result Fp2 element
 * @param a Fp2 element
 * @param ctx Fp2 context
 */
TORUS_API void fp2_frobenius(fp2* c, const fp2* a, const fp2_ctx_t* ctx);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Modular reduction of Fp2 element
 * 
 * Ensures both components are in range [0, p-1]
 * 
 * @param a Fp2 element to reduce
 * @param ctx Fp2 context
 */
TORUS_API void fp2_reduce(fp2* a, const fp2_ctx_t* ctx);

/**
 * @brief Check if Fp2 element is in canonical form
 * 
 * @param a Fp2 element to check
 * @param ctx Fp2 context
 * @return int 1 if canonical, 0 otherwise
 */
TORUS_API int fp2_is_canonical(const fp2* a, const fp2_ctx_t* ctx);

/**
 * @brief Serialize Fp2 element to byte array
 * 
 * @param bytes Output byte array (must have at least 2*FP_BYTES bytes)
 * @param a Fp2 element to serialize
 * @param ctx Fp2 context
 */
TORUS_API void fp2_to_bytes(uint8_t* bytes, const fp2* a, const fp2_ctx_t* ctx);

/**
 * @brief Deserialize Fp2 element from byte array
 * 
 * @param a Fp2 element to store result
 * @param bytes Input byte array (big-endian, real followed by imaginary)
 * @param ctx Fp2 context
 * @return int TORUS_SUCCESS on success, error code on failure
 */
TORUS_API int fp2_from_bytes(fp2* a, const uint8_t* bytes, const fp2_ctx_t* ctx);

/**
 * @brief Constant-time conditional copy of Fp2 element
 * 
 * @param dst Destination Fp2 element
 * @param src Source Fp2 element
 * @param condition Copy if condition != 0
 * @param ctx Fp2 context
 */
TORUS_API void fp2_conditional_copy(fp2* dst, const fp2* src, uint8_t condition, const fp2_ctx_t* ctx);

/**
 * @brief Constant-time conditional swap of Fp2 elements
 * 
 * @param a First Fp2 element
 * @param b Second Fp2 element
 * @param condition Swap if condition != 0
 * @param ctx Fp2 context
 */
TORUS_API void fp2_conditional_swap(fp2* a, fp2* b, uint8_t condition, const fp2_ctx_t* ctx);

/**
 * @brief Get the real part of Fp2 element
 * 
 * @param real Real part result
 * @param a Fp2 element
 * @param ctx Fp2 context
 */
TORUS_API void fp2_real_part(fp* real, const fp2* a, const fp2_ctx_t* ctx);

/**
 * @brief Get the imaginary part of Fp2 element
 * 
 * @param imag Imaginary part result
 * @param a Fp2 element
 * @param ctx Fp2 context
 */
TORUS_API void fp2_imag_part(fp* imag, const fp2* a, const fp2_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif /* FP2_ARITHMETIC_H */
