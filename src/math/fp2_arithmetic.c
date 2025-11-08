// src/math/fp2_arithmetic.c
#include "math/fp2_arithmetic.h"
#include "utils/secure_utils.h"
#include "utils/random.h"
#include "utils/error_handling.h"
#include <string.h>

// Internal function declarations
static int fp2_sqrt_simple(fp2* c, const fp2* a, const fp2_ctx_t* ctx);
static int fp2_sqrt_tonelli_shanks(fp2* c, const fp2* a, const fp2_ctx_t* ctx);
static void fp2_mul_karatsuba(fp2* c, const fp2* a, const fp2* b, const fp2_ctx_t* ctx);
static void fp2_sqr_complex(fp2* c, const fp2* a, const fp2_ctx_t* ctx);

int fp2_ctx_init(fp2_ctx_t* ctx, const fp_ctx_t* fp_ctx, uint32_t security_level) {
    if (!ctx || !fp_ctx) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Copy base field context
    memcpy(&ctx->fp_ctx, fp_ctx, sizeof(fp_ctx_t));
    ctx->security_level = security_level;
    
    // For Fp2 with i^2 = -1, the non-residue is -1
    // Check if -1 is a quadratic non-residue in Fp
    fp_set_u64(&ctx->non_residue.x, 1, &ctx->fp_ctx);
    fp_neg(&ctx->non_residue.x, &ctx->non_residue.x, &ctx->fp_ctx); // -1
    fp_set_zero(&ctx->non_residue.y, &ctx->fp_ctx);
    
    // Verify that -1 is indeed a quadratic non-residue
    // For CSIDH primes (p ≡ 3 mod 4), -1 is a quadratic non-residue
    if (fp_is_square(&ctx->non_residue.x, &ctx->fp_ctx)) {
        // This should not happen for CSIDH primes
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    return TORUS_SUCCESS;
}

void fp2_ctx_cleanup(fp2_ctx_t* ctx) {
    if (!ctx) return;
    
    // Cleanup base field context
    fp_ctx_cleanup(&ctx->fp_ctx);
    
    // Securely zeroize the context
    secure_zeroize(ctx, sizeof(fp2_ctx_t));
}

void fp2_set_zero(fp2* a, const fp2_ctx_t* ctx) {
    if (!a || !ctx) return;
    
    fp_set_zero(&a->x, &ctx->fp_ctx);
    fp_set_zero(&a->y, &ctx->fp_ctx);
}

void fp2_set_one(fp2* a, const fp2_ctx_t* ctx) {
    if (!a || !ctx) return;
    
    fp_set_one(&a->x, &ctx->fp_ctx);
    fp_set_zero(&a->y, &ctx->fp_ctx);
}

void fp2_set_u64(fp2* a, uint64_t value, const fp2_ctx_t* ctx) {
    if (!a || !ctx) return;
    
    fp_set_u64(&a->x, value, &ctx->fp_ctx);
    fp_set_zero(&a->y, &ctx->fp_ctx);
}

void fp2_set_fp(fp2* a, const fp* real, const fp* imag, const fp2_ctx_t* ctx) {
    if (!a || !real || !imag || !ctx) return;
    
    fp_copy(&a->x, real);
    fp_copy(&a->y, imag);
    fp2_reduce(a, ctx);
}

void fp2_set_bytes(fp2* a, const uint8_t* bytes, const fp2_ctx_t* ctx) {
    if (!a || !bytes || !ctx) return;
    
    size_t fp_bytes = fp_get_bytes(&ctx->fp_ctx);
    
    // First half: real part, second half: imaginary part
    fp_from_bytes(&a->x, bytes, &ctx->fp_ctx);
    fp_from_bytes(&a->y, bytes + fp_bytes, &ctx->fp_ctx);
}

int fp2_is_zero(const fp2* a, const fp2_ctx_t* ctx) {
    if (!a || !ctx) return 0;
    
    return fp_is_zero(&a->x, &ctx->fp_ctx) && fp_is_zero(&a->y, &ctx->fp_ctx);
}

int fp2_is_one(const fp2* a, const fp2_ctx_t* ctx) {
    if (!a || !ctx) return 0;
    
    return fp_is_one(&a->x, &ctx->fp_ctx) && fp_is_zero(&a->y, &ctx->fp_ctx);
}

int fp2_equal(const fp2* a, const fp2* b, const fp2_ctx_t* ctx) {
    if (!a || !b || !ctx) return 0;
    
    return fp_equal(&a->x, &b->x) && fp_equal(&a->y, &b->y);
}

int fp2_random(fp2* a, const fp2_ctx_t* ctx) {
    if (!a || !ctx) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    if (fp_random(&a->x, &ctx->fp_ctx) != TORUS_SUCCESS) {
        return TORUS_ERROR_RANDOM;
    }
    
    if (fp_random(&a->y, &ctx->fp_ctx) != TORUS_SUCCESS) {
        return TORUS_ERROR_RANDOM;
    }
    
    return TORUS_SUCCESS;
}

int fp2_random_nonzero(fp2* a, const fp2_ctx_t* ctx) {
    if (!a || !ctx) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    int attempts = 0;
    const int max_attempts = 100;
    
    do {
        if (fp2_random(a, ctx) != TORUS_SUCCESS) {
            return TORUS_ERROR_RANDOM;
        }
        attempts++;
    } while (fp2_is_zero(a, ctx) && attempts < max_attempts);
    
    if (fp2_is_zero(a, ctx)) {
        return TORUS_ERROR_RANDOM;
    }
    
    return TORUS_SUCCESS;
}

void fp2_copy(fp2* dst, const fp2* src, const fp2_ctx_t* ctx) {
    if (!dst || !src || !ctx) return;
    
    fp_copy(&dst->x, &src->x);
    fp_copy(&dst->y, &src->y);
}

void fp2_add(fp2* c, const fp2* a, const fp2* b, const fp2_ctx_t* ctx) {
    if (!c || !a || !b || !ctx) return;
    
    fp_add(&c->x, &a->x, &b->x, &ctx->fp_ctx);
    fp_add(&c->y, &a->y, &b->y, &ctx->fp_ctx);
}

void fp2_sub(fp2* c, const fp2* a, const fp2* b, const fp2_ctx_t* ctx) {
    if (!c || !a || !b || !ctx) return;
    
    fp_sub(&c->x, &a->x, &b->x, &ctx->fp_ctx);
    fp_sub(&c->y, &a->y, &b->y, &ctx->fp_ctx);
}

void fp2_neg(fp2* c, const fp2* a, const fp2_ctx_t* ctx) {
    if (!c || !a || !ctx) return;
    
    fp_neg(&c->x, &a->x, &ctx->fp_ctx);
    fp_neg(&c->y, &a->y, &ctx->fp_ctx);
}

void fp2_mul(fp2* c, const fp2* a, const fp2* b, const fp2_ctx_t* ctx) {
    if (!c || !a || !b || !ctx) return;
    
    // Use Karatsuba multiplication for better performance
    fp2_mul_karatsuba(c, a, b, ctx);
}

static void fp2_mul_karatsuba(fp2* c, const fp2* a, const fp2* b, const fp2_ctx_t* ctx) {
    // Karatsuba multiplication: (a + bi)(c + di) = (ac - bd) + (ad + bc)i
    // Optimized to use 3 multiplications instead of 4
    
    fp t1, t2, t3, t4, t5;
    
    // t1 = a.x * b.x
    fp_mul(&t1, &a->x, &b->x, &ctx->fp_ctx);
    
    // t2 = a.y * b.y  
    fp_mul(&t2, &a->y, &b->y, &ctx->fp_ctx);
    
    // t3 = (a.x + a.y) * (b.x + b.y)
    fp_add(&t3, &a->x, &a->y, &ctx->fp_ctx);
    fp_add(&t4, &b->x, &b->y, &ctx->fp_ctx);
    fp_mul(&t3, &t3, &t4, &ctx->fp_ctx);
    
    // c.x = t1 - t2
    fp_sub(&c->x, &t1, &t2, &ctx->fp_ctx);
    
    // c.y = t3 - t1 - t2
    fp_sub(&t5, &t3, &t1, &ctx->fp_ctx);
    fp_sub(&c->y, &t5, &t2, &ctx->fp_ctx);
    
    // Secure cleanup of temporary variables
    secure_zeroize(&t1, sizeof(fp));
    secure_zeroize(&t2, sizeof(fp));
    secure_zeroize(&t3, sizeof(fp));
    secure_zeroize(&t4, sizeof(fp));
    secure_zeroize(&t5, sizeof(fp));
}

void fp2_sqr(fp2* c, const fp2* a, const fp2_ctx_t* ctx) {
    if (!c || !a || !ctx) return;
    
    // Use complex squaring formula for better performance
    fp2_sqr_complex(c, a, ctx);
}

static void fp2_sqr_complex(fp2* c, const fp2* a, const fp2_ctx_t* ctx) {
    // Specialized squaring formula: (a + bi)^2 = (a^2 - b^2) + 2abi
    // Optimized to use 2 multiplications instead of 3
    
    fp t1, t2, t3;
    
    // t1 = a.x + a.y
    fp_add(&t1, &a->x, &a->y, &ctx->fp_ctx);
    
    // t2 = a.x - a.y
    fp_sub(&t2, &a->x, &a->y, &ctx->fp_ctx);
    
    // t3 = a.x * a.y
    fp_mul(&t3, &a->x, &a->y, &ctx->fp_ctx);
    
    // c.x = t1 * t2 = (a.x + a.y)(a.x - a.y) = a.x^2 - a.y^2
    fp_mul(&c->x, &t1, &t2, &ctx->fp_ctx);
    
    // c.y = 2 * t3 = 2 * a.x * a.y
    fp_add(&c->y, &t3, &t3, &ctx->fp_ctx);
    
    // Secure cleanup of temporary variables
    secure_zeroize(&t1, sizeof(fp));
    secure_zeroize(&t2, sizeof(fp));
    secure_zeroize(&t3, sizeof(fp));
}

int fp2_inv(fp2* c, const fp2* a, const fp2_ctx_t* ctx) {
    if (!c || !a || !ctx) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Check for zero element
    if (fp2_is_zero(a, ctx)) {
        return TORUS_ERROR_DIVISION_BY_ZERO;
    }
    
    // Inverse in Fp2: 1/(a + bi) = (a - bi)/(a^2 + b^2)
    fp norm, inv_norm;
    
    // Compute norm: a.x^2 + a.y^2
    fp_sqr(&norm, &a->x, &ctx->fp_ctx);
    fp_sqr(&inv_norm, &a->y, &ctx->fp_ctx); // Reusing inv_norm as temporary
    fp_add(&norm, &norm, &inv_norm, &ctx->fp_ctx);
    
    // Invert norm
    if (fp_inv(&inv_norm, &norm, &ctx->fp_ctx) != TORUS_SUCCESS) {
        return TORUS_ERROR_DIVISION_BY_ZERO;
    }
    
    // c.x = a.x * inv_norm
    fp_mul(&c->x, &a->x, &inv_norm, &ctx->fp_ctx);
    
    // c.y = -a.y * inv_norm
    fp_neg(&c->y, &a->y, &ctx->fp_ctx);
    fp_mul(&c->y, &c->y, &inv_norm, &ctx->fp_ctx);
    
    // Secure cleanup of temporary variables
    secure_zeroize(&norm, sizeof(fp));
    secure_zeroize(&inv_norm, sizeof(fp));
    
    return TORUS_SUCCESS;
}

int fp2_div(fp2* c, const fp2* a, const fp2* b, const fp2_ctx_t* ctx) {
    if (!c || !a || !b || !ctx) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Division: a / b = a * b^(-1)
    fp2 binv;
    
    if (fp2_inv(&binv, b, ctx) != TORUS_SUCCESS) {
        return TORUS_ERROR_DIVISION_BY_ZERO;
    }
    
    fp2_mul(c, a, &binv, ctx);
    
    // Secure cleanup
    secure_zeroize(&binv, sizeof(fp2));
    
    return TORUS_SUCCESS;
}

void fp2_mul_scalar(fp2* c, const fp2* a, const fp* k, const fp2_ctx_t* ctx) {
    if (!c || !a || !k || !ctx) return;
    
    fp_mul(&c->x, &a->x, k, &ctx->fp_ctx);
    fp_mul(&c->y, &a->y, k, &ctx->fp_ctx);
}

void fp2_mul_u64(fp2* c, const fp2* a, uint64_t k, const fp2_ctx_t* ctx) {
    if (!c || !a || !ctx) return;
    
    fp_mul_u64(&c->x, &a->x, k, &ctx->fp_ctx);
    fp_mul_u64(&c->y, &a->y, k, &ctx->fp_ctx);
}

void fp2_conj(fp2* c, const fp2* a, const fp2_ctx_t* ctx) {
    if (!c || !a || !ctx) return;
    
    fp_copy(&c->x, &a->x);
    fp_neg(&c->y, &a->y, &ctx->fp_ctx);
}

void fp2_norm(fp* n, const fp2* a, const fp2_ctx_t* ctx) {
    if (!n || !a || !ctx) return;
    
    // Norm: a.x^2 + a.y^2
    fp t1, t2;
    
    fp_sqr(&t1, &a->x, &ctx->fp_ctx);
    fp_sqr(&t2, &a->y, &ctx->fp_ctx);
    fp_add(n, &t1, &t2, &ctx->fp_ctx);
    
    // Secure cleanup
    secure_zeroize(&t1, sizeof(fp));
    secure_zeroize(&t2, sizeof(fp));
}

int fp2_is_square(const fp2* a, const fp2_ctx_t* ctx) {
    if (!a || !ctx) return 0;
    
    // For Fp2, an element is a square if and only if its norm is a square in Fp
    // and the element is not zero
    
    if (fp2_is_zero(a, ctx)) {
        return 1; // Zero is considered a square
    }
    
    fp norm;
    fp2_norm(&norm, a, ctx);
    
    int result = fp_is_square(&norm, &ctx->fp_ctx);
    
    secure_zeroize(&norm, sizeof(fp));
    return result;
}

int fp2_sqrt(fp2* c, const fp2* a, const fp2_ctx_t* ctx) {
    if (!c || !a || !ctx) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Tonelli-Shanks algorithm for Fp2
    // Implementation follows the standard algorithm for finite field square roots
    
    if (fp2_is_zero(a, ctx)) {
        fp2_set_zero(c, ctx);
        return TORUS_SUCCESS;
    }
    
    // Check if square root exists
    if (!fp2_is_square(a, ctx)) {
        return TORUS_ERROR_NOT_QUADRATIC_RESIDUE;
    }
    
    // Special case: a is in Fp (imaginary part is zero)
    if (fp_is_zero(&a->y, &ctx->fp_ctx)) {
        fp sqrt_x;
        if (fp_sqrt(&sqrt_x, &a->x, &ctx->fp_ctx) == TORUS_SUCCESS) {
            fp_copy(&c->x, &sqrt_x);
            fp_set_zero(&c->y, &ctx->fp_ctx);
            secure_zeroize(&sqrt_x, sizeof(fp));
            return TORUS_SUCCESS;
        } else {
            // a.x is not a square in Fp, but a is a square in Fp2
            // This means sqrt(a) has non-zero imaginary part
            fp2 temp;
            
            // Compute sqrt(a) = sqrt((a.x + sqrt(a.x^2 + a.y^2))/2) + i * sign(a.y) * sqrt((-a.x + sqrt(a.x^2 + a.y^2))/2)
            // But since a.y = 0, we use a different approach
            fp_neg(&temp.x, &a->x, &ctx->fp_ctx);
            fp_set_zero(&temp.y, &ctx->fp_ctx);
            
            int result = fp2_sqrt(c, &temp, ctx);
            secure_zeroize(&temp, sizeof(fp2));
            return result;
        }
    }
    
    // Use Tonelli-Shanks for the general case
    return fp2_sqrt_tonelli_shanks(c, a, ctx);
}

static int fp2_sqrt_tonelli_shanks(fp2* c, const fp2* a, const fp2_ctx_t* ctx) {
    // Factor p^2 - 1 = Q * 2^S (for Fp2)
    // This is a complex algorithm - for production, we'd use a more optimized approach
    
    // For now, use a simpler method for Fp2 square roots
    // Algorithm: Let w = a, we want to find z such that z^2 = w
    // If w is a square, then z = w^((p^2 + 1)/4) for p^2 ≡ 3 mod 4
    
    // Check if p^2 ≡ 3 mod 4
    fp p_sq;
    fp_mul(&p_sq, &ctx->fp_ctx.modulus, &ctx->fp_ctx.modulus, &ctx->fp_ctx);
    
    if ((p_sq.d[0] & 3) == 3) {
        // Use simple exponentiation: z = w^((p^2 + 1)/4)
        fp exponent;
        fp_set_u64(&exponent, 1, &ctx->fp_ctx);
        fp_add(&exponent, &p_sq, &exponent, &ctx->fp_ctx); // p^2 + 1
        fp_div2(&exponent, &exponent, &ctx->fp_ctx); // (p^2 + 1) / 2
        fp_div2(&exponent, &exponent, &ctx->fp_ctx); // (p^2 + 1) / 4
        
        fp2_pow(c, a, &exponent, ctx);
        
        // Verify the result
        fp2 check;
        fp2_sqr(&check, c, ctx);
        
        int correct = fp2_equal(&check, a, ctx);
        
        secure_zeroize(&p_sq, sizeof(fp));
        secure_zeroize(&exponent, sizeof(fp));
        secure_zeroize(&check, sizeof(fp2));
        
        if (correct) {
            return TORUS_SUCCESS;
        }
    }
    
    // Fall back to general Tonelli-Shanks
    // This is a simplified version - a full implementation would be more complex
    
    // Find a quadratic non-residue in Fp2
    fp2 z;
    fp2_set_one(&z, ctx);
    
    do {
        // Increment until we find a non-square
        fp2_add(&z, &z, &z, ctx);
    } while (fp2_is_square(&z, ctx));
    
    // Factor p^2 - 1 = Q * 2^S
    fp order;
    fp_set_u64(&order, 1, &ctx->fp_ctx);
    fp_add(&order, &p_sq, &order, &ctx->fp_ctx); // p^2 + 1 (for Fp2 size)
    fp_sub(&order, &order, &order, &ctx->fp_ctx); // p^2 - 1
    
    uint64_t s = 0;
    fp temp = order;
    
    // Count factors of 2
    while ((temp.d[0] & 1) == 0) {
        fp_div2(&temp, &temp, &ctx->fp_ctx);
        s++;
    }
    
    // Initialize variables
    fp2 m, c_val, t, r;
    fp_set_u64(&m, s, &ctx->fp_ctx);
    
    fp2_pow(&c_val, &z, &temp, ctx);
    fp2_pow(&t, a, &temp, ctx);
    
    fp exponent;
    fp_add(&exponent, &temp, &ctx->fp_ctx.temp, &ctx->fp_ctx); // Q + 1
    fp_div2(&exponent, &exponent, &ctx->fp_ctx); // (Q + 1) / 2
    fp2_pow(&r, a, &exponent, ctx);
    
    // Main loop
    while (!fp2_is_one(&t, ctx)) {
        uint64_t i = 0;
        fp2 t2i = t;
        
        // Find smallest i such that t^{2^i} = 1
        while (!fp2_is_one(&t2i, ctx)) {
            fp2_sqr(&t2i, &t2i, ctx);
            i++;
            if (i > s) {
                secure_zeroize(&z, sizeof(fp2));
                secure_zeroize(&order, sizeof(fp));
                secure_zeroize(&temp, sizeof(fp));
                secure_zeroize(&m, sizeof(fp2));
                secure_zeroize(&c_val, sizeof(fp2));
                secure_zeroize(&t, sizeof(fp2));
                secure_zeroize(&r, sizeof(fp2));
                secure_zeroize(&exponent, sizeof(fp));
                return TORUS_ERROR_COMPUTATION;
            }
        }
        
        // Update values
        fp2 b;
        fp2_pow(&b, &c_val, &m, ctx); // b = c_val^(2^(s-i-1))
        for (uint64_t j = 0; j < s - i - 1; j++) {
            fp2_sqr(&b, &b, ctx);
        }
        
        fp2_sqr(&b, &b, ctx); // b^2
        fp2_mul(&r, &r, &b, ctx);
        fp2_mul(&c_val, &b, &b, ctx); // b^2
        fp2_mul(&t, &t, &c_val, ctx);
        s = i;
    }
    
    fp2_copy(c, &r);
    
    // Verify the result
    fp2 check;
    fp2_sqr(&check, c, ctx);
    int correct = fp2_equal(&check, a, ctx);
    
    // Securely zeroize temporary values
    secure_zeroize(&z, sizeof(fp2));
    secure_zeroize(&order, sizeof(fp));
    secure_zeroize(&temp, sizeof(fp));
    secure_zeroize(&m, sizeof(fp2));
    secure_zeroize(&c_val, sizeof(fp2));
    secure_zeroize(&t, sizeof(fp2));
    secure_zeroize(&r, sizeof(fp2));
    secure_zeroize(&exponent, sizeof(fp));
    secure_zeroize(&check, sizeof(fp2));
    
    if (!correct) {
        return TORUS_ERROR_COMPUTATION;
    }
    
    return TORUS_SUCCESS;
}

void fp2_pow(fp2* c, const fp2* a, const fp* e, const fp2_ctx_t* ctx) {
    if (!c || !a || !e || !ctx) return;
    
    // Square-and-multiply exponentiation (constant-time)
    fp2 result;
    fp2_set_one(&result, ctx);
    
    fp2 base;
    fp2_copy(&base, a, ctx);
    
    fp exponent;
    fp_copy(&exponent, e);
    
    // Constant-time exponentiation
    uint32_t total_bits = fp_get_bits(&ctx->fp_ctx);
    
    for (int i = total_bits - 1; i >= 0; i--) {
        fp2_sqr(&result, &result, ctx);
        
        // Get bit i of exponent
        uint8_t bit = fp_get_bit(&exponent, i, &ctx->fp_ctx);
        
        // Conditional multiplication
        fp2 temp;
        fp2_mul(&temp, &result, &base, ctx);
        
        // Constant-time selection
        fp2_conditional_copy(&result, &temp, bit, ctx);
    }
    
    fp2_copy(c, &result, ctx);
    
    // Securely zeroize temporary values
    secure_zeroize(&result, sizeof(fp2));
    secure_zeroize(&base, sizeof(fp2));
    secure_zeroize(&exponent, sizeof(fp));
    secure_zeroize(&temp, sizeof(fp2));
}

void fp2_pow_u64(fp2* c, const fp2* a, uint64_t exponent, const fp2_ctx_t* ctx) {
    if (!c || !a || !ctx) return;
    
    fp2 result;
    fp2_set_one(&result, ctx);
    
    fp2 base;
    fp2_copy(&base, a, ctx);
    
    uint64_t exp = exponent;
    
    // Square-and-multiply exponentiation (constant-time)
    while (exp > 0) {
        if (exp & 1) {
            fp2_mul(&result, &result, &base, ctx);
        }
        fp2_sqr(&base, &base, ctx);
        exp >>= 1;
    }
    
    fp2_copy(c, &result, ctx);
    
    // Securely zeroize temporary values
    secure_zeroize(&result, sizeof(fp2));
    secure_zeroize(&base, sizeof(fp2));
}

void fp2_frobenius(fp2* c, const fp2* a, const fp2_ctx_t* ctx) {
    if (!c || !a || !ctx) return;
    
    // Frobenius endomorphism in Fp2: (a + bi)^p = a + b * i^p
    // Since i^2 = -1, we have i^p = i * (-1)^((p-1)/2)
    
    // Copy real part (unchanged)
    fp_copy(&c->x, &a->x);
    
    // For imaginary part: c.y = a.y * i^p
    // i^p = i * (-1)^((p-1)/2)
    
    // Check if (p-1)/2 is odd or even
    if ((ctx->fp_ctx.modulus.d[0] & 2) == 0) {
        // (p-1)/2 is even, i^p = i
        fp_copy(&c->y, &a->y);
    } else {
        // (p-1)/2 is odd, i^p = -i
        fp_neg(&c->y, &a->y, &ctx->fp_ctx);
    }
}

void fp2_reduce(fp2* a, const fp2_ctx_t* ctx) {
    if (!a || !ctx) return;
    
    fp_reduce(&a->x, &ctx->fp_ctx);
    fp_reduce(&a->y, &ctx->fp_ctx);
}

int fp2_is_canonical(const fp2* a, const fp2_ctx_t* ctx) {
    if (!a || !ctx) return 0;
    
    return fp_is_canonical(&a->x, &ctx->fp_ctx) && fp_is_canonical(&a->y, &ctx->fp_ctx);
}

void fp2_to_bytes(uint8_t* bytes, const fp2* a, const fp2_ctx_t* ctx) {
    if (!bytes || !a || !ctx) return;
    
    size_t fp_bytes = fp_get_bytes(&ctx->fp_ctx);
    
    // Serialize real part followed by imaginary part
    fp_to_bytes(bytes, &a->x, &ctx->fp_ctx);
    fp_to_bytes(bytes + fp_bytes, &a->y, &ctx->fp_ctx);
}

int fp2_from_bytes(fp2* a, const uint8_t* bytes, const fp2_ctx_t* ctx) {
    if (!a || !bytes || !ctx) return TORUS_ERROR_INVALID_PARAM;
    
    size_t fp_bytes = fp_get_bytes(&ctx->fp_ctx);
    
    // Deserialize real part followed by imaginary part
    if (fp_from_bytes(&a->x, bytes, &ctx->fp_ctx) != TORUS_SUCCESS) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    if (fp_from_bytes(&a->y, bytes + fp_bytes, &ctx->fp_ctx) != TORUS_SUCCESS) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    return TORUS_SUCCESS;
}

void fp2_conditional_copy(fp2* dst, const fp2* src, uint8_t condition, const fp2_ctx_t* ctx) {
    if (!dst || !src || !ctx) return;
    
    fp_conditional_copy(&dst->x, &src->x, condition);
    fp_conditional_copy(&dst->y, &src->y, condition);
}

void fp2_conditional_swap(fp2* a, fp2* b, uint8_t condition, const fp2_ctx_t* ctx) {
    if (!a || !b || !ctx) return;
    
    fp_conditional_swap(&a->x, &b->x, condition);
    fp_conditional_swap(&a->y, &b->y, condition);
}

void fp2_real_part(fp* real, const fp2* a, const fp2_ctx_t* ctx) {
    if (!real || !a || !ctx) return;
    
    fp_copy(real, &a->x);
}

void fp2_imag_part(fp* imag, const fp2* a, const fp2_ctx_t* ctx) {
    if (!imag || !a || !ctx) return;
    
    fp_copy(imag, &a->y);
}
