// include/math/fp2_arithmetic.h
#ifndef FP2_ARITHMETIC_H
#define FP2_ARITHMETIC_H

#include "fp_arithmetic.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file fp2_arithmetic.h
 * @brief Arithmetic operations in quadratic extension field Fp2
 * 
 * This module implements arithmetic operations in the quadratic extension field Fp2,
 * where Fp2 = Fp[i]/(i^2 + 1). Elements are represented as a + bi where a, b ∈ Fp.
 */

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
 * @brief Initialize Fp2 context
 * 
 * @param ctx Fp2 context (currently unused, for future extensions)
 * @return int 1 on success, 0 on failure
 */
int fp2_ctx_init(void* ctx);

/**
 * @brief Set Fp2 element to zero
 * 
 * @param a Fp2 element to set to zero
 * @param ctx Fp context
 */
void fp2_set_zero(fp2* a, const fp_ctx* ctx);

/**
 * @brief Set Fp2 element to one
 * 
 * @param a Fp2 element to set to one
 * @param ctx Fp context
 */
void fp2_set_one(fp2* a, const fp_ctx* ctx);

/**
 * @brief Set Fp2 element from unsigned 64-bit integer
 * 
 * @param a Fp2 element to set
 * @param value Integer value to set
 * @param ctx Fp context
 */
void fp2_set_u64(fp2* a, uint64_t value, const fp_ctx* ctx);

/**
 * @brief Check if Fp2 element is zero
 * 
 * @param a Fp2 element to check
 * @param ctx Fp context
 * @return int 1 if zero, 0 otherwise
 */
int fp2_is_zero(const fp2* a, const fp_ctx* ctx);

/**
 * @brief Check if Fp2 element is one
 * 
 * @param a Fp2 element to check
 * @param ctx Fp context
 * @return int 1 if one, 0 otherwise
 */
int fp2_is_one(const fp2* a, const fp_ctx* ctx);

/**
 * @brief Compare two Fp2 elements for equality
 * 
 * @param a First Fp2 element
 * @param b Second Fp2 element
 * @param ctx Fp context
 * @return int 1 if equal, 0 otherwise
 */
int fp2_equal(const fp2* a, const fp2* b, const fp_ctx* ctx);

/**
 * @brief Generate random Fp2 element
 * 
 * @param a Fp2 element to store result
 * @param ctx Fp context
 */
void fp2_random(fp2* a, const fp_ctx* ctx);

/**
 * @brief Copy Fp2 element
 * 
 * @param dst Destination Fp2 element
 * @param src Source Fp2 element
 * @param ctx Fp context
 */
void fp2_copy(fp2* dst, const fp2* src, const fp_ctx* ctx);

/**
 * @brief Fp2 addition: c = a + b
 * 
 * @param c Result Fp2 element
 * @param a First Fp2 element
 * @param b Second Fp2 element
 * @param ctx Fp context
 */
void fp2_add(fp2* c, const fp2* a, const fp2* b, const fp_ctx* ctx);

/**
 * @brief Fp2 subtraction: c = a - b
 * 
 * @param c Result Fp2 element
 * @param a First Fp2 element
 * @param b Second Fp2 element
 * @param ctx Fp context
 */
void fp2_sub(fp2* c, const fp2* a, const fp2* b, const fp_ctx* ctx);

/**
 * @brief Fp2 negation: c = -a
 * 
 * @param c Result Fp2 element
 * @param a Fp2 element to negate
 * @param ctx Fp context
 */
void fp2_neg(fp2* c, const fp2* a, const fp_ctx* ctx);

/**
 * @brief Fp2 multiplication: c = a * b
 * 
 * @param c Result Fp2 element
 * @param a First Fp2 element
 * @param b Second Fp2 element
 * @param ctx Fp context
 */
void fp2_mul(fp2* c, const fp2* a, const fp2* b, const fp_ctx* ctx);

/**
 * @brief Fp2 squaring: c = a^2
 * 
 * @param c Result Fp2 element
 * @param a Fp2 element to square
 * @param ctx Fp context
 */
void fp2_sqr(fp2* c, const fp2* a, const fp_ctx* ctx);

/**
 * @brief Fp2 inversion: c = a^(-1)
 * 
 * @param c Result Fp2 element
 * @param a Fp2 element to invert
 * @param ctx Fp context
 * @return int 1 on success, 0 if a is zero
 */
int fp2_inv(fp2* c, const fp2* a, const fp_ctx* ctx);

/**
 * @brief Fp2 division: c = a / b
 * 
 * @param c Result Fp2 element
 * @param a Numerator Fp2 element
 * @param b Denominator Fp2 element
 * @param ctx Fp context
 * @return int 1 on success, 0 if b is zero
 */
int fp2_div(fp2* c, const fp2* a, const fp2* b, const fp_ctx* ctx);

/**
 * @brief Fp2 scalar multiplication: c = a * k, where k ∈ Fp
 * 
 * @param c Result Fp2 element
 * @param a Fp2 element
 * @param k Scalar in Fp
 * @param ctx Fp context
 */
void fp2_mul_scalar(fp2* c, const fp2* a, const fp* k, const fp_ctx* ctx);

/**
 * @brief Fp2 complex conjugation: c = conjugate(a)
 * 
 * @param c Result Fp2 element
 * @param a Fp2 element to conjugate
 * @param ctx Fp context
 */
void fp2_conj(fp2* c, const fp2* a, const fp_ctx* ctx);

/**
 * @brief Fp2 norm: n = a * conjugate(a) = a.x^2 + a.y^2
 * 
 * @param n Result Fp element (norm)
 * @param a Fp2 element
 * @param ctx Fp context
 */
void fp2_norm(fp* n, const fp2* a, const fp_ctx* ctx);

/**
 * @brief Check if Fp2 element is a square
 * 
 * @param a Fp2 element to check
 * @param ctx Fp context
 * @return int 1 if square, 0 otherwise
 */
int fp2_is_square(const fp2* a, const fp_ctx* ctx);

/**
 * @brief Compute square root in Fp2
 * 
 * @param c Result Fp2 element (square root)
 * @param a Fp2 element to take square root of
 * @param ctx Fp context
 * @return int 1 on success, 0 if square root doesn't exist
 */
int fp2_sqrt(fp2* c, const fp2* a, const fp_ctx* ctx);

/**
 * @brief Fp2 exponentiation: c = a^e
 * 
 * @param c Result Fp2 element
 * @param a Base Fp2 element
 * @param e Exponent (Fp element)
 * @param ctx Fp context
 */
void fp2_pow(fp2* c, const fp2* a, const fp* e, const fp_ctx* ctx);

/**
 * @brief Fp2 exponentiation with unsigned integer exponent
 * 
 * @param c Result Fp2 element
 * @param a Base Fp2 element
 * @param exponent Unsigned integer exponent
 * @param ctx Fp context
 */
void fp2_pow_u64(fp2* c, const fp2* a, uint64_t exponent, const fp_ctx* ctx);

/**
 * @brief Modular reduction of Fp2 element
 * 
 * Ensures both components are in range [0, p-1]
 * 
 * @param a Fp2 element to reduce
 * @param ctx Fp context
 */
void fp2_reduce(fp2* a, const fp_ctx* ctx);

/**
 * @brief Check if Fp2 element is in canonical form
 * 
 * @param a Fp2 element to check
 * @param ctx Fp context
 * @return int 1 if canonical, 0 otherwise
 */
int fp2_is_canonical(const fp2* a, const fp_ctx* ctx);

/**
 * @brief Constant-time conditional copy of Fp2 element
 * 
 * @param dst Destination Fp2 element
 * @param src Source Fp2 element
 * @param condition Copy if condition != 0
 * @param ctx Fp context
 */
void fp2_conditional_copy(fp2* dst, const fp2* src, int condition, const fp_ctx* ctx);

/**
 * @brief Constant-time conditional swap of Fp2 elements
 * 
 * @param a First Fp2 element
 * @param b Second Fp2 element
 * @param condition Swap if condition != 0
 * @param ctx Fp context
 */
void fp2_conditional_swap(fp2* a, fp2* b, int condition, const fp_ctx* ctx);

/**
 * @brief Serialize Fp2 element to byte array
 * 
 * @param output Output byte array (must have at least 2*NLIMBS*8 bytes)
 * @param a Fp2 element to serialize
 * @param ctx Fp context
 */
void fp2_serialize(uint8_t* output, const fp2* a, const fp_ctx* ctx);

/**
 * @brief Deserialize Fp2 element from byte array
 * 
 * @param a Fp2 element to store result
 * @param input Input byte array
 * @param ctx Fp context
 * @return int 1 on success, 0 on failure
 */
int fp2_deserialize(fp2* a, const uint8_t* input, const fp_ctx* ctx);

#ifdef __cplusplus
}
#endif

#endif /* FP2_ARITHMETIC_H */
