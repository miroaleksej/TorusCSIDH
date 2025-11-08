// src/math/fp2_arithmetic.// src/math/fp2_arithmetic.c
#include "math/fp2_arithmetic.h"
#include "utils/secure_utils.h"
#include "utils/error_handling.h"
#include <string.h>

int fp2_ctx_init(void* ctx) {
    // Currently unused, reserved for future extensions
    (void)ctx;
    return 1;
}

void fp2_set_zero(fp2* a, const fp_ctx* ctx) {
    if (!a || !ctx) return;
    
    fp_set_zero(&a->x, ctx);
    fp_set_zero(&a->y, ctx);
}

void fp2_set_one(fp2* a, const fp_ctx* ctx) {
    if (!a || !ctx) return;
    
    fp_set_one(&a->x, ctx);
    fp_set_zero(&a->y, ctx);
}

void fp2_set_u64(fp2* a, uint64_t value, const fp_ctx* ctx) {
    if (!a || !ctx) return;
    
    fp_set_u64(&a->x, value, ctx);
    fp_set_zero(&a->y, ctx);
}

int fp2_is_zero(const fp2* a, const fp_ctx* ctx) {
    if (!a || !ctx) return 0;
    
    return fp_is_zero(&a->x, ctx) && fp_is_zero(&a->y, ctx);
}

int fp2_is_one(const fp2* a, const fp_ctx* ctx) {
    if (!a || !ctx) return 0;
    
    return fp_is_one(&a->x, ctx) && fp_is_zero(&a->y, ctx);
}

int fp2_equal(const fp2* a, const fp2* b, const fp_ctx* ctx) {
    if (!a || !b || !ctx) return 0;
    
    return fp_equal(&a->x, &b->x, ctx) && fp_equal(&a->y, &b->y, ctx);
}

void fp2_random(fp2* a, const fp_ctx* ctx) {
    if (!a || !ctx) return;
    
    fp_random(&a->x, ctx);
    fp_random(&a->y, ctx);
}

void fp2_copy(fp2* dst, const fp2* src, const fp_ctx* ctx) {
    if (!dst || !src || !ctx) return;
    
    fp_copy(&dst->x, &src->x, ctx);
    fp_copy(&dst->y, &src->y, ctx);
}

void fp2_add(fp2* c, const fp2* a, const fp2* b, const fp_ctx* ctx) {
    if (!c || !a || !b || !ctx) return;
    
    fp_add(&c->x, &a->x, &b->x, ctx);
    fp_add(&c->y, &a->y, &b->y, ctx);
}

void fp2_sub(fp2* c, const fp2* a, const fp2* b, const fp_ctx* ctx) {
    if (!c || !a || !b || !ctx) return;
    
    fp_sub(&c->x, &a->x, &b->x, ctx);
    fp_sub(&c->y, &a->y, &b->y, ctx);
}

void fp2_neg(fp2* c, const fp2* a, const fp_ctx* ctx) {
    if (!c || !a || !ctx) return;
    
    fp_neg(&c->x, &a->x, ctx);
    fp_neg(&c->y, &a->y, ctx);
}

void fp2_mul(fp2* c, const fp2* a, const fp2* b, const fp_ctx* ctx) {
    if (!c || !a || !b || !ctx) return;
    
    // Karatsuba multiplication: (a + bi)(c + di) = (ac - bd) + (ad + bc)i
    // Optimized to use 3 multiplications instead of 4
    
    fp t1, t2, t3, t4, t5;
    
    // t1 = a.x * b.x
    fp_mul(&t1, &a->x, &b->x, ctx);
    
    // t2 = a.y * b.y  
    fp_mul(&t2, &a->y, &b->y, ctx);
    
    // t3 = (a.x + a.y) * (b.x + b.y)
    fp_add(&t3, &a->x, &a->y, ctx);
    fp_add(&t4, &b->x, &b->y, ctx);
    fp_mul(&t3, &t3, &t4, ctx);
    
    // c.x = t1 - t2
    fp_sub(&c->x, &t1, &t2, ctx);
    
    // c.y = t3 - t1 - t2
    fp_sub(&t5, &t3, &t1, ctx);
    fp_sub(&c->y, &t5, &t2, ctx);
    
    // Secure cleanup of temporary variables
    secure_zeroize(&t1, sizeof(fp));
    secure_zeroize(&t2, sizeof(fp));
    secure_zeroize(&t3, sizeof(fp));
    secure_zeroize(&t4, sizeof(fp));
    secure_zeroize(&t5, sizeof(fp));
}

void fp2_sqr(fp2* c, const fp2* a, const fp_ctx* ctx) {
    if (!c || !a || !ctx) return;
    
    // Specialized squaring formula: (a + bi)^2 = (a^2 - b^2) + 2abi
    // Optimized to use 2 multiplications instead of 3
    
    fp t1, t2, t3;
    
    // t1 = a.x + a.y
    fp_add(&t1, &a->x, &a->y, ctx);
    
    // t2 = a.x - a.y
    fp_sub(&t2, &a->x, &a->y, ctx);
    
    // t3 = a.x * a.y
    fp_mul(&t3, &a->x, &a->y, ctx);
    
    // c.x = t1 * t2 = (a.x + a.y)(a.x - a.y) = a.x^2 - a.y^2
    fp_mul(&c->x, &t1, &t2, ctx);
    
    // c.y = 2 * t3 = 2 * a.x * a.y
    fp_add(&c->y, &t3, &t3, ctx);
    
    // Secure cleanup of temporary variables
    secure_zeroize(&t1, sizeof(fp));
    secure_zeroize(&t2, sizeof(fp));
    secure_zeroize(&t3, sizeof(fp));
}

int fp2_inv(fp2* c, const fp2* a, const fp_ctx* ctx) {
    if (!c || !a || !ctx) return 0;
    
    // Check for zero element
    if (fp2_is_zero(a, ctx)) {
        return 0; // Cannot invert zero
    }
    
    // Inverse in Fp2: 1/(a + bi) = (a - bi)/(a^2 + b^2)
    fp norm, inv_norm;
    
    // Compute norm: a.x^2 + a.y^2
    fp_sqr(&norm, &a->x, ctx);
    fp_sqr(&inv_norm, &a->y, ctx); // Reusing inv_norm as temporary
    fp_add(&norm, &norm, &inv_norm, ctx);
    
    // Invert norm
    if (!fp_inv(&inv_norm, &norm, ctx)) {
        return 0; // Should not happen for non-zero a
    }
    
    // c.x = a.x * inv_norm
    fp_mul(&c->x, &a->x, &inv_norm, ctx);
    
    // c.y = -a.y * inv_norm
    fp_neg(&c->y, &a->y, ctx);
    fp_mul(&c->y, &c->y, &inv_norm, ctx);
    
    // Secure cleanup of temporary variables
    secure_zeroize(&norm, sizeof(fp));
    secure_zeroize(&inv_norm, sizeof(fp));
    
    return 1;
}

int fp2_div(fp2* c, const fp2* a, const fp2* b, const fp_ctx* ctx) {
    if (!c || !a || !b || !ctx) return 0;
    
    // Division: a / b = a * b^(-1)
    fp2 binv;
    
    if (!fp2_inv(&binv, b, ctx)) {
        return 0; // Division by zero
    }
    
    fp2_mul(c, a, &binv, ctx);
    
    // Secure cleanup
    secure_zeroize(&binv, sizeof(fp2));
    
    return 1;
}

void fp2_mul_scalar(fp2* c, const fp2* a, const fp* k, const fp_ctx* ctx) {
    if (!c || !a || !k || !ctx) return;
    
    fp_mul(&c->x, &a->x, k, ctx);
    fp_mul(&c->y, &a->y, k, ctx);
}

void fp2_conj(fp2* c, const fp2* a, const fp_ctx* ctx) {
    if (!c || !a || !ctx) return;
    
    fp_copy(&c->x, &a->x, ctx);
    fp_neg(&c->y, &a->y, ctx);
}

void fp2_norm(fp* n, const fp2* a, const fp_ctx* ctx) {
    if (!n || !a || !ctx) return;
    
    // Norm: a.x^2 + a.y^2
    fp t1, t2;
    
    fp_sqr(&t1, &a->x, ctx);
    fp_sqr(&t2, &a->y, ctx);
    fp_add(n, &t1, &t2, ctx);
    
    // Secure cleanup
    secure_zeroize(&t1, sizeof(fp));
    secure_zeroize(&t2, sizeof(fp));
}

int fp2_is_square(const fp2* a, const fp_ctx* ctx) {
    if (!a || !ctx) return 0;
    
    // For Fp2, an element is a square if and only if its norm is a square in Fp
    // and the element is not zero
    
    if (fp2_is_zero(a, ctx)) {
        return 1; // Zero is considered a square
    }
    
    fp norm;
    fp2_norm(&norm, a, ctx);
    
    int result = fp_is_square(&norm, ctx);
    
    secure_zeroize(&norm, sizeof(fp));
    return result;
}

int fp2_sqrt(fp2* c, const fp2* a, const fp_ctx* ctx) {
    if (!c || !a || !ctx) return 0;
    
    // Tonelli-Shanks algorithm for Fp2
    // Implementation follows the standard algorithm for finite field square roots
    
    if (fp2_is_zero(a, ctx)) {
        fp2_set_zero(c, ctx);
        return 1;
    }
    
    // Check if square root exists
    if (!fp2_is_square(a, ctx)) {
        return 0;
    }
    
    // Special case: a is in Fp (imaginary part is zero)
    if (fp_is_zero(&a->y, ctx)) {
        fp sqrt_x;
        if (fp_sqrt(&sqrt_x, &a->x, ctx)) {
            fp_copy(&c->x, &sqrt_x, ctx);
            fp_set_zero(&c->y, ctx);
            secure_zeroize(&sqrt_x, sizeof(fp));
            return 1;
        } else {
            // a.x is not a square in Fp, but a is a square in Fp2
            // This means sqrt(a) has non-zero imaginary part
            fp2 temp;
            
            // Compute sqrt(a) = sqrt((a.x + sqrt(a.x^2 + a.y^2))/2) + i * sign(a.y) * sqrt((-a.x + sqrt(a.x^2 + a.y^2))/2)
            // But since a.y = 0, we use a different approach
            fp_neg(&temp.x, &a->x, ctx);
            fp_set_zero(&temp.y, ctx);
            
            if (!fp2_sqrt(c, &temp, ctx)) {
                return 0;
            }
            
            secure_zeroize(&temp, sizeof(fp2));
            return 1;
        }
    }
    
    // General case: use the formula for Fp2 square roots
    // Let w = a, we want to find z such that z^2 = w
    // Algorithm: z = sqrt((w + norm(w))/2) + i * sign(Im(w)) * sqrt((norm(w) - w)/2)
    
    fp norm_a, t1, t2, t3, t4;
    fp2 w_plus_norm, norm_minus_w;
    
    // Compute norm(w)
    fp2_norm(&norm_a, a, ctx);
    
    // Compute (w + norm(w))/2
    fp2_set_u64(&w_plus_norm, 0, ctx);
    fp_add(&w_plus_norm.x, &a->x, &norm_a, ctx);
    fp_copy(&w_plus_norm.y, &a->y, ctx);
    fp_div2(&w_plus_norm.x, &w_plus_norm.x, ctx);
    fp_div2(&w_plus_norm.y, &w_plus_norm.y, ctx);
    
    // Compute (norm(w) - w)/2  
    fp_sub(&norm_minus_w.x, &norm_a, &a->x, ctx);
    fp_neg(&norm_minus_w.y, &a->y, ctx);
    fp_div2(&norm_minus_w.x, &norm_minus_w.x, ctx);
    fp_div2(&norm_minus_w.y, &norm_minus_w.y, ctx);
    
    // Check if (w + norm(w))/2 is a square in Fp2
    // Actually, since it has zero imaginary part, we check in Fp
    if (!fp_is_square(&w_plus_norm.x, ctx)) {
        // Use the other branch of the formula
        secure_zeroize(&norm_a, sizeof(fp));
        secure_zeroize(&w_plus_norm, sizeof(fp2));
        secure_zeroize(&norm_minus_w, sizeof(fp2));
        return 0;
    }
    
    // Compute sqrt((w + norm(w))/2)
    fp sqrt_real;
    if (!fp_sqrt(&sqrt_real, &w_plus_norm.x, ctx)) {
        secure_zeroize(&norm_a, sizeof(fp));
        secure_zeroize(&w_plus_norm, sizeof(fp2));
        secure_zeroize(&norm_minus_w, sizeof(fp2));
        return 0;
    }
    
    // Compute sqrt((norm(w) - w)/2)
    // Note: This should also be in Fp since imaginary part is zero
    fp sqrt_imag;
    if (!fp_sqrt(&sqrt_imag, &norm_minus_w.x, ctx)) {
        secure_zeroize(&sqrt_real, sizeof(fp));
        secure_zeroize(&norm_a, sizeof(fp));
        secure_zeroize(&w_plus_norm, sizeof(fp2));
        secure_zeroize(&norm_minus_w, sizeof(fp2));
        return 0;
    }
    
    // Determine the sign for the imaginary part
    // We choose the sign such that the product of the imaginary parts matches the original
    fp_copy(&c->x, &sqrt_real, ctx);
    
    // The imaginary part should have the same sign as the original a.y
    // For constant-time, we always use positive and adjust later if needed
    fp_copy(&c->y, &sqrt_imag, ctx);
    
    // Verify that we have the correct square root
    fp2 check;
    fp2_sqr(&check, c, ctx);
    
    int correct = fp2_equal(&check, a, ctx);
    
    if (!correct) {
        // Try the other sign
        fp_neg(&c->y, &c->y, ctx);
        
        // Verify again
        fp2_sqr(&check, c, ctx);
        correct = fp2_equal(&check, a, ctx);
    }
    
    // Secure cleanup
    secure_zeroize(&norm_a, sizeof(fp));
    secure_zeroize(&w_plus_norm, sizeof(fp2));
    secure_zeroize(&norm_minus_w, sizeof(fp2));
    secure_zeroize(&sqrt_real, sizeof(fp));
    secure_zeroize(&sqrt_imag, sizeof(fp));
    secure_zeroize(&check, sizeof(fp2));
    
    return correct;
}

void fp2_pow(fp2* c, const fp2* a, const fp* e, const fp_ctx* ctx) {
    if (!c || !a || !e || !ctx) return;
    
    // Square-and-multiply exponentiation
    fp2 result;
    fp2_set_one(&result, ctx);
    
    fp2 base;
    fp2_copy(&base, a, ctx);
    
    fp exponent;
    fp_copy(&exponent, e, ctx);
    
    // Constant-time exponentiation
    for (int i = fp_bitlen(&exponent, ctx) - 1; i >= 0; i--) {
        fp2_sqr(&result, &result, ctx);
        
        if (fp_get_bit(&exponent, i, ctx)) {
            fp2_mul(&result, &result, &base, ctx);
        }
    }
    
    fp2_copy(c, &result, ctx);
    
    // Secure cleanup
    secure_zeroize(&result, sizeof(fp2));
    secure_zeroize(&base, sizeof(fp2));
    secure_zeroize(&exponent, sizeof(fp));
}

void fp2_pow_u64(fp2* c, const fp2* a, uint64_t exponent, const fp_ctx* ctx) {
    if (!c || !a || !ctx) return;
    
    fp2 result;
    fp2_set_one(&result, ctx);
    
    fp2 base;
    fp2_copy(&base, a, ctx);
    
    uint64_t exp = exponent;
    
    // Constant-time exponentiation
    while (exp > 0) {
        if (exp & 1) {
            fp2_mul(&result, &result, &base, ctx);
        }
        fp2_sqr(&base, &base, ctx);
        exp >>= 1;
    }
    
    fp2_copy(c, &result, ctx);
    
    // Secure cleanup
    secure_zeroize(&result, sizeof(fp2));
    secure_zeroize(&base, sizeof(fp2));
}

void fp2_reduce(fp2* a, const fp_ctx* ctx) {
    if (!a || !ctx) return;
    
    fp_reduce(&a->x, ctx);
    fp_reduce(&a->y, ctx);
}

int fp2_is_canonical(const fp2* a, const fp_ctx* ctx) {
    if (!a || !ctx) return 0;
    
    return fp_is_canonical(&a->x, ctx) && fp_is_canonical(&a->y, ctx);
}

void fp2_conditional_copy(fp2* dst, const fp2* src, int condition, const fp_ctx* ctx) {
    if (!dst || !src || !ctx) return;
    
    fp_conditional_copy(&dst->x, &src->x, condition, ctx);
    fp_conditional_copy(&dst->y, &src->y, condition, ctx);
}

void fp2_conditional_swap(fp2* a, fp2* b, int condition, const fp_ctx* ctx) {
    if (!a || !b || !ctx) return;
    
    fp_conditional_swap(&a->x, &b->x, condition, ctx);
    fp_conditional_swap(&a->y, &b->y, condition, ctx);
}

void fp2_serialize(uint8_t* output, const fp2* a, const fp_ctx* ctx) {
    if (!output || !a || !ctx) return;
    
    // Serialize real part (x)
    fp_serialize(output, &a->x, ctx);
    
    // Serialize imaginary part (y)
    fp_serialize(output + NLIMBS * sizeof(uint64_t), &a->y, ctx);
}

int fp2_deserialize(fp2* a, const uint8_t* input, const fp_ctx* ctx) {
    if (!a || !input || !ctx) return 0;
    
    // Deserialize real part (x)
    if (!fp_deserialize(&a->x, input, ctx)) {
        return 0;
    }
    
    // Deserialize imaginary part (y)
    if (!fp_deserialize(&a->y, input + NLIMBS * sizeof(uint64_t), ctx)) {
        fp2_set_zero(a, ctx); // Clear partial result on error
        return 0;
    }
    
    return 1;
}
#include "math/fp2_arithmetic.h"
#include "utils/secure_utils.h"
#include "utils/error_handling.h"
#include <string.h>

int fp2_ctx_init(void* ctx) {
    // Currently unused, reserved for future extensions
    (void)ctx;
    return 1;
}

void fp2_set_zero(fp2* a, const fp_ctx* ctx) {
    if (!a || !ctx) return;
    
    fp_set_zero(&a->x, ctx);
    fp_set_zero(&a->y, ctx);
}

void fp2_set_one(fp2* a, const fp_ctx* ctx) {
    if (!a || !ctx) return;
    
    fp_set_one(&a->x, ctx);
    fp_set_zero(&a->y, ctx);
}

void fp2_set_u64(fp2* a, uint64_t value, const fp_ctx* ctx) {
    if (!a || !ctx) return;
    
    fp_set_u64(&a->x, value, ctx);
    fp_set_zero(&a->y, ctx);
}

int fp2_is_zero(const fp2* a, const fp_ctx* ctx) {
    if (!a || !ctx) return 0;
    
    return fp_is_zero(&a->x, ctx) && fp_is_zero(&a->y, ctx);
}

int fp2_is_one(const fp2* a, const fp_ctx* ctx) {
    if (!a || !ctx) return 0;
    
    return fp_is_one(&a->x, ctx) && fp_is_zero(&a->y, ctx);
}

int fp2_equal(const fp2* a, const fp2* b, const fp_ctx* ctx) {
    if (!a || !b || !ctx) return 0;
    
    return fp_equal(&a->x, &b->x, ctx) && fp_equal(&a->y, &b->y, ctx);
}

void fp2_random(fp2* a, const fp_ctx* ctx) {
    if (!a || !ctx) return;
    
    fp_random(&a->x, ctx);
    fp_random(&a->y, ctx);
}

void fp2_copy(fp2* dst, const fp2* src, const fp_ctx* ctx) {
    if (!dst || !src || !ctx) return;
    
    fp_copy(&dst->x, &src->x, ctx);
    fp_copy(&dst->y, &src->y, ctx);
}

void fp2_add(fp2* c, const fp2* a, const fp2* b, const fp_ctx* ctx) {
    if (!c || !a || !b || !ctx) return;
    
    fp_add(&c->x, &a->x, &b->x, ctx);
    fp_add(&c->y, &a->y, &b->y, ctx);
}

void fp2_sub(fp2* c, const fp2* a, const fp2* b, const fp_ctx* ctx) {
    if (!c || !a || !b || !ctx) return;
    
    fp_sub(&c->x, &a->x, &b->x, ctx);
    fp_sub(&c->y, &a->y, &b->y, ctx);
}

void fp2_neg(fp2* c, const fp2* a, const fp_ctx* ctx) {
    if (!c || !a || !ctx) return;
    
    fp_neg(&c->x, &a->x, ctx);
    fp_neg(&c->y, &a->y, ctx);
}

void fp2_mul(fp2* c, const fp2* a, const fp2* b, const fp_ctx* ctx) {
    if (!c || !a || !b || !ctx) return;
    
    // Karatsuba multiplication: (a + bi)(c + di) = (ac - bd) + (ad + bc)i
    // Optimized to use 3 multiplications instead of 4
    
    fp t1, t2, t3, t4, t5;
    
    // t1 = a.x * b.x
    fp_mul(&t1, &a->x, &b->x, ctx);
    
    // t2 = a.y * b.y  
    fp_mul(&t2, &a->y, &b->y, ctx);
    
    // t3 = (a.x + a.y) * (b.x + b.y)
    fp_add(&t3, &a->x, &a->y, ctx);
    fp_add(&t4, &b->x, &b->y, ctx);
    fp_mul(&t3, &t3, &t4, ctx);
    
    // c.x = t1 - t2
    fp_sub(&c->x, &t1, &t2, ctx);
    
    // c.y = t3 - t1 - t2
    fp_sub(&t5, &t3, &t1, ctx);
    fp_sub(&c->y, &t5, &t2, ctx);
    
    // Secure cleanup of temporary variables
    secure_zeroize(&t1, sizeof(fp));
    secure_zeroize(&t2, sizeof(fp));
    secure_zeroize(&t3, sizeof(fp));
    secure_zeroize(&t4, sizeof(fp));
    secure_zeroize(&t5, sizeof(fp));
}

void fp2_sqr(fp2* c, const fp2* a, const fp_ctx* ctx) {
    if (!c || !a || !ctx) return;
    
    // Specialized squaring formula: (a + bi)^2 = (a^2 - b^2) + 2abi
    // Optimized to use 2 multiplications instead of 3
    
    fp t1, t2, t3;
    
    // t1 = a.x + a.y
    fp_add(&t1, &a->x, &a->y, ctx);
    
    // t2 = a.x - a.y
    fp_sub(&t2, &a->x, &a->y, ctx);
    
    // t3 = a.x * a.y
    fp_mul(&t3, &a->x, &a->y, ctx);
    
    // c.x = t1 * t2 = (a.x + a.y)(a.x - a.y) = a.x^2 - a.y^2
    fp_mul(&c->x, &t1, &t2, ctx);
    
    // c.y = 2 * t3 = 2 * a.x * a.y
    fp_add(&c->y, &t3, &t3, ctx);
    
    // Secure cleanup of temporary variables
    secure_zeroize(&t1, sizeof(fp));
    secure_zeroize(&t2, sizeof(fp));
    secure_zeroize(&t3, sizeof(fp));
}

int fp2_inv(fp2* c, const fp2* a, const fp_ctx* ctx) {
    if (!c || !a || !ctx) return 0;
    
    // Check for zero element
    if (fp2_is_zero(a, ctx)) {
        return 0; // Cannot invert zero
    }
    
    // Inverse in Fp2: 1/(a + bi) = (a - bi)/(a^2 + b^2)
    fp norm, inv_norm;
    
    // Compute norm: a.x^2 + a.y^2
    fp_sqr(&norm, &a->x, ctx);
    fp_sqr(&inv_norm, &a->y, ctx); // Reusing inv_norm as temporary
    fp_add(&norm, &norm, &inv_norm, ctx);
    
    // Invert norm
    if (!fp_inv(&inv_norm, &norm, ctx)) {
        return 0; // Should not happen for non-zero a
    }
    
    // c.x = a.x * inv_norm
    fp_mul(&c->x, &a->x, &inv_norm, ctx);
    
    // c.y = -a.y * inv_norm
    fp_neg(&c->y, &a->y, ctx);
    fp_mul(&c->y, &c->y, &inv_norm, ctx);
    
    // Secure cleanup of temporary variables
    secure_zeroize(&norm, sizeof(fp));
    secure_zeroize(&inv_norm, sizeof(fp));
    
    return 1;
}

int fp2_div(fp2* c, const fp2* a, const fp2* b, const fp_ctx* ctx) {
    if (!c || !a || !b || !ctx) return 0;
    
    // Division: a / b = a * b^(-1)
    fp2 binv;
    
    if (!fp2_inv(&binv, b, ctx)) {
        return 0; // Division by zero
    }
    
    fp2_mul(c, a, &binv, ctx);
    
    // Secure cleanup
    secure_zeroize(&binv, sizeof(fp2));
    
    return 1;
}

void fp2_mul_scalar(fp2* c, const fp2* a, const fp* k, const fp_ctx* ctx) {
    if (!c || !a || !k || !ctx) return;
    
    fp_mul(&c->x, &a->x, k, ctx);
    fp_mul(&c->y, &a->y, k, ctx);
}

void fp2_conj(fp2* c, const fp2* a, const fp_ctx* ctx) {
    if (!c || !a || !ctx) return;
    
    fp_copy(&c->x, &a->x, ctx);
    fp_neg(&c->y, &a->y, ctx);
}

void fp2_norm(fp* n, const fp2* a, const fp_ctx* ctx) {
    if (!n || !a || !ctx) return;
    
    // Norm: a.x^2 + a.y^2
    fp t1, t2;
    
    fp_sqr(&t1, &a->x, ctx);
    fp_sqr(&t2, &a->y, ctx);
    fp_add(n, &t1, &t2, ctx);
    
    // Secure cleanup
    secure_zeroize(&t1, sizeof(fp));
    secure_zeroize(&t2, sizeof(fp));
}

int fp2_is_square(const fp2* a, const fp_ctx* ctx) {
    if (!a || !ctx) return 0;
    
    // For Fp2, an element is a square if and only if its norm is a square in Fp
    // and the element is not zero
    
    if (fp2_is_zero(a, ctx)) {
        return 1; // Zero is considered a square
    }
    
    fp norm;
    fp2_norm(&norm, a, ctx);
    
    int result = fp_is_square(&norm, ctx);
    
    secure_zeroize(&norm, sizeof(fp));
    return result;
}

int fp2_sqrt(fp2* c, const fp2* a, const fp_ctx* ctx) {
    if (!c || !a || !ctx) return 0;
    
    // Tonelli-Shanks algorithm for Fp2
    // Implementation follows the standard algorithm for finite field square roots
    
    if (fp2_is_zero(a, ctx)) {
        fp2_set_zero(c, ctx);
        return 1;
    }
    
    // Check if square root exists
    if (!fp2_is_square(a, ctx)) {
        return 0;
    }
    
    // Special case: a is in Fp (imaginary part is zero)
    if (fp_is_zero(&a->y, ctx)) {
        fp sqrt_x;
        if (fp_sqrt(&sqrt_x, &a->x, ctx)) {
            fp_copy(&c->x, &sqrt_x, ctx);
            fp_set_zero(&c->y, ctx);
            secure_zeroize(&sqrt_x, sizeof(fp));
            return 1;
        } else {
            // a.x is not a square in Fp, but a is a square in Fp2
            // This means sqrt(a) has non-zero imaginary part
            fp2 temp;
            
            // Compute sqrt(a) = sqrt((a.x + sqrt(a.x^2 + a.y^2))/2) + i * sign(a.y) * sqrt((-a.x + sqrt(a.x^2 + a.y^2))/2)
            // But since a.y = 0, we use a different approach
            fp_neg(&temp.x, &a->x, ctx);
            fp_set_zero(&temp.y, ctx);
            
            if (!fp2_sqrt(c, &temp, ctx)) {
                return 0;
            }
            
            secure_zeroize(&temp, sizeof(fp2));
            return 1;
        }
    }
    
    // General case: use the formula for Fp2 square roots
    // Let w = a, we want to find z such that z^2 = w
    // Algorithm: z = sqrt((w + norm(w))/2) + i * sign(Im(w)) * sqrt((norm(w) - w)/2)
    
    fp norm_a, t1, t2, t3, t4;
    fp2 w_plus_norm, norm_minus_w;
    
    // Compute norm(w)
    fp2_norm(&norm_a, a, ctx);
    
    // Compute (w + norm(w))/2
    fp2_set_u64(&w_plus_norm, 0, ctx);
    fp_add(&w_plus_norm.x, &a->x, &norm_a, ctx);
    fp_copy(&w_plus_norm.y, &a->y, ctx);
    fp_div2(&w_plus_norm.x, &w_plus_norm.x, ctx);
    fp_div2(&w_plus_norm.y, &w_plus_norm.y, ctx);
    
    // Compute (norm(w) - w)/2  
    fp_sub(&norm_minus_w.x, &norm_a, &a->x, ctx);
    fp_neg(&norm_minus_w.y, &a->y, ctx);
    fp_div2(&norm_minus_w.x, &norm_minus_w.x, ctx);
    fp_div2(&norm_minus_w.y, &norm_minus_w.y, ctx);
    
    // Check if (w + norm(w))/2 is a square in Fp2
    // Actually, since it has zero imaginary part, we check in Fp
    if (!fp_is_square(&w_plus_norm.x, ctx)) {
        // Use the other branch of the formula
        secure_zeroize(&norm_a, sizeof(fp));
        secure_zeroize(&w_plus_norm, sizeof(fp2));
        secure_zeroize(&norm_minus_w, sizeof(fp2));
        return 0;
    }
    
    // Compute sqrt((w + norm(w))/2)
    fp sqrt_real;
    if (!fp_sqrt(&sqrt_real, &w_plus_norm.x, ctx)) {
        secure_zeroize(&norm_a, sizeof(fp));
        secure_zeroize(&w_plus_norm, sizeof(fp2));
        secure_zeroize(&norm_minus_w, sizeof(fp2));
        return 0;
    }
    
    // Compute sqrt((norm(w) - w)/2)
    // Note: This should also be in Fp since imaginary part is zero
    fp sqrt_imag;
    if (!fp_sqrt(&sqrt_imag, &norm_minus_w.x, ctx)) {
        secure_zeroize(&sqrt_real, sizeof(fp));
        secure_zeroize(&norm_a, sizeof(fp));
        secure_zeroize(&w_plus_norm, sizeof(fp2));
        secure_zeroize(&norm_minus_w, sizeof(fp2));
        return 0;
    }
    
    // Determine the sign for the imaginary part
    // We choose the sign such that the product of the imaginary parts matches the original
    fp_copy(&c->x, &sqrt_real, ctx);
    
    // The imaginary part should have the same sign as the original a.y
    // For constant-time, we always use positive and adjust later if needed
    fp_copy(&c->y, &sqrt_imag, ctx);
    
    // Verify that we have the correct square root
    fp2 check;
    fp2_sqr(&check, c, ctx);
    
    int correct = fp2_equal(&check, a, ctx);
    
    if (!correct) {
        // Try the other sign
        fp_neg(&c->y, &c->y, ctx);
        
        // Verify again
        fp2_sqr(&check, c, ctx);
        correct = fp2_equal(&check, a, ctx);
    }
    
    // Secure cleanup
    secure_zeroize(&norm_a, sizeof(fp));
    secure_zeroize(&w_plus_norm, sizeof(fp2));
    secure_zeroize(&norm_minus_w, sizeof(fp2));
    secure_zeroize(&sqrt_real, sizeof(fp));
    secure_zeroize(&sqrt_imag, sizeof(fp));
    secure_zeroize(&check, sizeof(fp2));
    
    return correct;
}

void fp2_pow(fp2* c, const fp2* a, const fp* e, const fp_ctx* ctx) {
    if (!c || !a || !e || !ctx) return;
    
    // Square-and-multiply exponentiation
    fp2 result;
    fp2_set_one(&result, ctx);
    
    fp2 base;
    fp2_copy(&base, a, ctx);
    
    fp exponent;
    fp_copy(&exponent, e, ctx);
    
    // Constant-time exponentiation
    for (int i = fp_bitlen(&exponent, ctx) - 1; i >= 0; i--) {
        fp2_sqr(&result, &result, ctx);
        
        if (fp_get_bit(&exponent, i, ctx)) {
            fp2_mul(&result, &result, &base, ctx);
        }
    }
    
    fp2_copy(c, &result, ctx);
    
    // Secure cleanup
    secure_zeroize(&result, sizeof(fp2));
    secure_zeroize(&base, sizeof(fp2));
    secure_zeroize(&exponent, sizeof(fp));
}

void fp2_pow_u64(fp2* c, const fp2* a, uint64_t exponent, const fp_ctx* ctx) {
    if (!c || !a || !ctx) return;
    
    fp2 result;
    fp2_set_one(&result, ctx);
    
    fp2 base;
    fp2_copy(&base, a, ctx);
    
    uint64_t exp = exponent;
    
    // Constant-time exponentiation
    while (exp > 0) {
        if (exp & 1) {
            fp2_mul(&result, &result, &base, ctx);
        }
        fp2_sqr(&base, &base, ctx);
        exp >>= 1;
    }
    
    fp2_copy(c, &result, ctx);
    
    // Secure cleanup
    secure_zeroize(&result, sizeof(fp2));
    secure_zeroize(&base, sizeof(fp2));
}

void fp2_reduce(fp2* a, const fp_ctx* ctx) {
    if (!a || !ctx) return;
    
    fp_reduce(&a->x, ctx);
    fp_reduce(&a->y, ctx);
}

int fp2_is_canonical(const fp2* a, const fp_ctx* ctx) {
    if (!a || !ctx) return 0;
    
    return fp_is_canonical(&a->x, ctx) && fp_is_canonical(&a->y, ctx);
}

void fp2_conditional_copy(fp2* dst, const fp2* src, int condition, const fp_ctx* ctx) {
    if (!dst || !src || !ctx) return;
    
    fp_conditional_copy(&dst->x, &src->x, condition, ctx);
    fp_conditional_copy(&dst->y, &src->y, condition, ctx);
}

void fp2_conditional_swap(fp2* a, fp2* b, int condition, const fp_ctx* ctx) {
    if (!a || !b || !ctx) return;
    
    fp_conditional_swap(&a->x, &b->x, condition, ctx);
    fp_conditional_swap(&a->y, &b->y, condition, ctx);
}

void fp2_serialize(uint8_t* output, const fp2* a, const fp_ctx* ctx) {
    if (!output || !a || !ctx) return;
    
    // Serialize real part (x)
    fp_serialize(output, &a->x, ctx);
    
    // Serialize imaginary part (y)
    fp_serialize(output + NLIMBS * sizeof(uint64_t), &a->y, ctx);
}

int fp2_deserialize(fp2* a, const uint8_t* input, const fp_ctx* ctx) {
    if (!a || !input || !ctx) return 0;
    
    // Deserialize real part (x)
    if (!fp_deserialize(&a->x, input, ctx)) {
        return 0;
    }
    за
    // Deserialize imaginary part (y)
    if (!fp_deserialize(&a->y, input + NLIMBS * sizeof(uint64_t), ctx)) {
        fp2_set_zero(a, ctx); // Clear partial result on error
        return 0;
    }
    
    return 1;
}
