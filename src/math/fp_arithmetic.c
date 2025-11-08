// src/math/fp_arithmetic.c
#include "math/fp_arithmetic.h"
#include "math/montgomery.h"
#include "utils/secure_utils.h"
#include "utils/random.h"
#include "utils/error_handling.h"

#include <string.h>

// Internal function declarations
static void fp_add_impl(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx);
static void fp_sub_impl(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx);
static void fp_mul_impl(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx);
static void fp_reduce_impl(fp* a, const fp_ctx_t* ctx);
static int fp_inv_fermat(fp* c, const fp* a, const fp_ctx_t* ctx);
static int fp_sqrt_tonelli_shanks(fp* c, const fp* a, const fp_ctx_t* ctx);

int fp_ctx_init(fp_ctx_t* ctx, const fp* modulus) {
    if (!ctx || !modulus) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Copy modulus
    fp_copy(&ctx->modulus, modulus);
    
    // Precompute Montgomery constants
    if (montgomery_ctx_init(&ctx->montgomery_ctx, modulus) != TORUS_SUCCESS) {
        return TORUS_ERROR_COMPUTATION;
    }
    
    // Precompute p - 2 for exponentiation
    fp_set_one(&ctx->p_minus_2, ctx);
    fp_add(&ctx->p_minus_2, modulus, &ctx->p_minus_2, ctx); // p + 1
    fp_sub(&ctx->p_minus_2, &ctx->p_minus_2, &ctx->p_minus_2, ctx); // p - 2
    
    // Precompute (p + 1) / 4 for square roots (if p ≡ 3 mod 4)
    fp_set_u64(&ctx->p_plus_1_div_4, 1, ctx);
    fp_add(&ctx->p_plus_1_div_4, modulus, &ctx->p_plus_1_div_4, ctx); // p + 1
    fp_set_u64(&ctx->temp, 4, ctx);
    fp_inv(&ctx->temp, &ctx->temp, ctx); // 1/4
    fp_mul(&ctx->p_plus_1_div_4, &ctx->p_plus_1_div_4, &ctx->temp, ctx); // (p + 1)/4
    
    return TORUS_SUCCESS;
}

void fp_ctx_cleanup(fp_ctx_t* ctx) {
    if (!ctx) return;
    
    // Securely zeroize all sensitive data
    secure_zeroize(ctx, sizeof(fp_ctx_t));
}

void fp_set_zero(fp* a) {
    if (!a) return;
    
    for (size_t i = 0; i < NLIMBS; i++) {
        a->d[i] = 0;
    }
}

void fp_set_one(fp* a, const fp_ctx_t* ctx) {
    if (!a || !ctx) return;
    
    fp_set_zero(a);
    a->d[0] = 1;
    fp_reduce(a, ctx);
}

int fp_is_zero(const fp* a) {
    if (!a) return 0;
    
    uint64_t result = 0;
    for (size_t i = 0; i < NLIMBS; i++) {
        result |= a->d[i];
    }
    
    // Constant-time comparison: returns 1 if all limbs are zero
    return (result == 0);
}

int fp_is_one(const fp* a, const fp_ctx_t* ctx) {
    if (!a || !ctx) return 0;
    
    fp one;
    fp_set_one(&one, ctx);
    return fp_equal(a, &one);
}

int fp_equal(const fp* a, const fp* b) {
    if (!a || !b) return 0;
    
    uint64_t diff = 0;
    for (size_t i = 0; i < NLIMBS; i++) {
        diff |= (a->d[i] ^ b->d[i]);
    }
    
    // Constant-time comparison: returns 1 if all limbs are equal
    return (diff == 0);
}

void fp_copy(fp* dst, const fp* src) {
    if (!dst || !src) return;
    
    for (size_t i = 0; i < NLIMBS; i++) {
        dst->d[i] = src->d[i];
    }
}

int fp_random(fp* a, const fp_ctx_t* ctx) {
    if (!a || !ctx) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Generate random bytes
    uint8_t random_bytes[NLIMBS * sizeof(uint64_t)];
    if (random_bytes_secure(random_bytes, sizeof(random_bytes)) != TORUS_SUCCESS) {
        return TORUS_ERROR_RANDOM;
    }
    
    // Convert to limbs
    for (size_t i = 0; i < NLIMBS; i++) {
        a->d[i] = 0;
        for (size_t j = 0; j < sizeof(uint64_t); j++) {
            a->d[i] |= ((uint64_t)random_bytes[i * sizeof(uint64_t) + j]) << (j * 8);
        }
    }
    
    // Ensure the value is less than modulus
    fp_reduce(a, ctx);
    
    return TORUS_SUCCESS;
}

void fp_add(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx) {
#if defined(__AVX2__)
    if (cpu_has_avx2()) {
        fp_add_avx2(c, a, b, ctx);
        return;
    }
#elif defined(__ARM_NEON)
    if (cpu_has_neon()) {
        fp_add_neon(c, a, b, ctx);
        return;
    }
#endif
    
    fp_add_impl(c, a, b, ctx);
}

static void fp_add_impl(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx) {
    uint64_t carry = 0;
    fp temp;
    
    // Add a + b
    for (size_t i = 0; i < NLIMBS; i++) {
        uint64_t sum = a->d[i] + b->d[i] + carry;
        carry = (sum < a->d[i]) || (carry && (sum == a->d[i]));
        temp.d[i] = sum;
    }
    
    // Subtract modulus if result >= modulus
    uint64_t borrow = 0;
    fp reduced;
    for (size_t i = 0; i < NLIMBS; i++) {
        uint64_t diff = temp.d[i] - ctx->modulus.d[i] - borrow;
        borrow = (temp.d[i] < ctx->modulus.d[i] + borrow) || 
                (borrow && (temp.d[i] == ctx->modulus.d[i] + borrow));
        reduced.d[i] = diff;
    }
    
    // Constant-time selection: use reduced if borrow == 0, else use temp
    uint64_t mask = ~(uint64_t)0 + !borrow; // mask = (borrow == 0) ? ~0 : 0
    for (size_t i = 0; i < NLIMBS; i++) {
        c->d[i] = (temp.d[i] & mask) | (reduced.d[i] & ~mask);
    }
}

void fp_sub(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx) {
    uint64_t borrow = 0;
    fp temp;
    
    // Subtract a - b
    for (size_t i = 0; i < NLIMBS; i++) {
        uint64_t diff = a->d[i] - b->d[i] - borrow;
        borrow = (a->d[i] < b->d[i] + borrow) || 
                (borrow && (a->d[i] == b->d[i] + borrow));
        temp.d[i] = diff;
    }
    
    // Add modulus if result is negative
    uint64_t carry = 0;
    fp adjusted;
    for (size_t i = 0; i < NLIMBS; i++) {
        uint64_t sum = temp.d[i] + ctx->modulus.d[i] + carry;
        carry = (sum < temp.d[i]) || (carry && (sum == temp.d[i]));
        adjusted.d[i] = sum;
    }
    
    // Constant-time selection: use adjusted if borrow == 1, else use temp
    uint64_t mask = ~(uint64_t)0 + borrow; // mask = (borrow == 1) ? ~0 : 0
    for (size_t i = 0; i < NLIMBS; i++) {
        c->d[i] = (temp.d[i] & ~mask) | (adjusted.d[i] & mask);
    }
}

void fp_mul(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx) {
#if defined(__AVX2__)
    if (cpu_has_avx2()) {
        fp_mul_avx2(c, a, b, ctx);
        return;
    }
#elif defined(__ARM_NEON)
    if (cpu_has_neon()) {
        fp_mul_neon(c, a, b, ctx);
        return;
    }
#endif
    
    fp_mul_impl(c, a, b, ctx);
}

static void fp_mul_impl(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx) {
    // Use Montgomery multiplication for better performance
    montgomery_multiply(c, a, b, &ctx->montgomery_ctx);
}

void fp_sqr(fp* c, const fp* a, const fp_ctx_t* ctx) {
    // Square is just multiplication with itself
    fp_mul(c, a, a, ctx);
}

int fp_inv(fp* c, const fp* a, const fp_ctx_t* ctx) {
    if (!c || !a || !ctx) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    if (fp_is_zero(a)) {
        return TORUS_ERROR_DIVISION_BY_ZERO;
    }
    
    // Use Fermat's little theorem: a^{-1} = a^{p-2} mod p
    return fp_inv_fermat(c, a, ctx);
}

static int fp_inv_fermat(fp* c, const fp* a, const fp_ctx_t* ctx) {
    fp result;
    fp_set_one(&result, ctx);
    
    fp base = *a;
    fp exponent = ctx->p_minus_2;
    
    // Square-and-multiply exponentiation (constant-time)
    for (int i = FP_BITS - 1; i >= 0; i--) {
        fp_sqr(&result, &result, ctx);
        
        // Get bit i of exponent
        int limb_idx = i / 64;
        int bit_idx = i % 64;
        uint64_t bit = (exponent.d[limb_idx] >> bit_idx) & 1;
        
        // Conditional multiplication
        fp temp;
        fp_mul(&temp, &result, &base, ctx);
        
        // Constant-time selection
        fp_cmov(&result, &temp, bit);
    }
    
    fp_copy(c, &result);
    
    // Securely zeroize temporary values
    secure_zeroize(&result, sizeof(result));
    secure_zeroize(&base, sizeof(base));
    secure_zeroize(&temp, sizeof(temp));
    
    return TORUS_SUCCESS;
}

void fp_neg(fp* c, const fp* a, const fp_ctx_t* ctx) {
    if (!c || !a || !ctx) return;
    
    // -a = p - a
    fp_sub(c, &ctx->modulus, a, ctx);
}

void fp_pow(fp* c, const fp* a, const fp* e, const fp_ctx_t* ctx) {
    if (!c || !a || !e || !ctx) return;
    
    fp result;
    fp_set_one(&result, ctx);
    
    fp base = *a;
    fp exponent = *e;
    
    // Square-and-multiply exponentiation (constant-time)
    for (int i = FP_BITS - 1; i >= 0; i--) {
        fp_sqr(&result, &result, ctx);
        
        // Get bit i of exponent
        int limb_idx = i / 64;
        int bit_idx = i % 64;
        uint64_t bit = (exponent.d[limb_idx] >> bit_idx) & 1;
        
        // Conditional multiplication
        fp temp;
        fp_mul(&temp, &result, &base, ctx);
        
        // Constant-time selection
        fp_cmov(&result, &temp, bit);
    }
    
    fp_copy(c, &result);
    
    // Securely zeroize temporary values
    secure_zeroize(&result, sizeof(result));
    secure_zeroize(&base, sizeof(base));
    secure_zeroize(&temp, sizeof(temp));
}

void fp_reduce(fp* a, const fp_ctx_t* ctx) {
    fp_reduce_impl(a, ctx);
}

static void fp_reduce_impl(fp* a, const fp_ctx_t* ctx) {
    // Check if a >= modulus
    uint64_t borrow = 0;
    for (size_t i = 0; i < NLIMBS; i++) {
        uint64_t diff = a->d[i] - ctx->modulus.d[i] - borrow;
        borrow = (a->d[i] < ctx->modulus.d[i] + borrow) || 
                (borrow && (a->d[i] == ctx->modulus.d[i] + borrow));
    }
    
    // If borrow == 0, then a >= modulus, subtract modulus
    if (!borrow) {
        borrow = 0;
        for (size_t i = 0; i < NLIMBS; i++) {
            uint64_t diff = a->d[i] - ctx->modulus.d[i] - borrow;
            borrow = (a->d[i] < ctx->modulus.d[i] + borrow) || 
                    (borrow && (a->d[i] == ctx->modulus.d[i] + borrow));
            a->d[i] = diff;
        }
    }
}

int fp_is_square(const fp* a, const fp_ctx_t* ctx) {
    if (!a || !ctx) return 0;
    
    if (fp_is_zero(a)) {
        return 1; // 0 is a square
    }
    
    // Use Euler's criterion: a is quadratic residue if a^{(p-1)/2} = 1
    fp exponent;
    fp_set_one(&exponent, ctx);
    fp_add(&exponent, &ctx->modulus, &exponent, ctx); // p + 1
    fp_sub(&exponent, &exponent, &exponent, ctx); // p - 1
    fp_set_u64(&ctx->temp, 2, ctx);
    fp_inv(&ctx->temp, &ctx->temp, ctx); // 1/2
    fp_mul(&exponent, &exponent, &ctx->temp, ctx); // (p - 1)/2
    
    fp result;
    fp_pow(&result, a, &exponent, ctx);
    
    return fp_is_one(&result, ctx);
}

int fp_sqrt(fp* c, const fp* a, const fp_ctx_t* ctx) {
    if (!c || !a || !ctx) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    if (fp_is_zero(a)) {
        fp_set_zero(c);
        return TORUS_SUCCESS;
    }
    
    // Check if a is quadratic residue
    if (!fp_is_square(a, ctx)) {
        return TORUS_ERROR_NOT_QUADRATIC_RESIDUE;
    }
    
    // Use Tonelli-Shanks algorithm for general case
    return fp_sqrt_tonelli_shanks(c, a, ctx);
}

static int fp_sqrt_tonelli_shanks(fp* c, const fp* a, const fp_ctx_t* ctx) {
    // Factor p - 1 = Q * 2^S
    fp q = ctx->modulus;
    fp_set_one(&q, ctx);
    fp_sub(&q, &q, &q, ctx); // q = p - 1
    
    uint64_t s = 0;
    fp temp = q;
    
    // Count factors of 2: while temp is even
    while ((temp.d[0] & 1) == 0) {
        fp_set_u64(&ctx->temp, 2, ctx);
        fp_inv(&ctx->temp, &ctx->temp, ctx); // 1/2
        fp_mul(&temp, &temp, &ctx->temp, ctx);
        s++;
    }
    
    // Find a quadratic non-residue z
    fp z;
    fp_set_one(&z, ctx);
    do {
        fp_add(&z, &z, &ctx->montgomery_ctx.one, ctx); // z = z + 1
    } while (fp_is_square(&z, ctx));
    
    // Initialize variables
    fp m = {0};
    fp_set_u64(&m, s, ctx);
    
    fp c_val = {0};
    fp_pow(&c_val, &z, &q, ctx);
    
    fp t = {0};
    fp_pow(&t, a, &q, ctx);
    
    fp r = {0};
    fp_set_u64(&ctx->temp, (q.d[0] + 1) >> 1, ctx);
    fp_pow(&r, a, &ctx->temp, ctx);
    
    // Main loop
    while (!fp_is_one(&t, ctx)) {
        uint64_t i = 0;
        fp t2i = t;
        
        // Find smallest i such that t^{2^i} = 1
        while (!fp_is_one(&t2i, ctx)) {
            fp_sqr(&t2i, &t2i, ctx);
            i++;
            if (i > s) {
                return TORUS_ERROR_COMPUTATION;
            }
        }
        
        // Update values
        fp b = c_val;
        for (uint64_t j = 0; j < s - i - 1; j++) {
            fp_sqr(&b, &b, ctx);
        }
        
        fp_sqr(&b, &b, ctx); // b^2
        fp_mul(&r, &r, &b, ctx);
        fp_mul(&c_val, &b, &b, ctx); // b^2
        fp_mul(&t, &t, &c_val, ctx);
        s = i;
    }
    
    fp_copy(c, &r);
    return TORUS_SUCCESS;
}

void fp_to_montgomery(fp* c, const fp* a, const fp_ctx_t* ctx) {
    montgomery_to_montgomery(c, a, &ctx->montgomery_ctx);
}

void fp_from_montgomery(fp* c, const fp* a, const fp_ctx_t* ctx) {
    montgomery_from_montgomery(c, a, &ctx->montgomery_ctx);
}

void fp_cmov(fp* dst, const fp* src, uint8_t condition) {
    if (!dst || !src) return;
    
    // Convert condition to mask: 0 -> 0x00..., 1 -> 0xFF...
    uint64_t mask = ~(uint64_t)0 + !condition;
    
    for (size_t i = 0; i < NLIMBS; i++) {
        dst->d[i] = (dst->d[i] & mask) | (src->d[i] & ~mask);
    }
}

void fp_cswap(fp* a, fp* b, uint8_t condition) {
    if (!a || !b) return;
    
    // Convert condition to mask: 0 -> 0x00..., 1 -> 0xFF...
    uint64_t mask = ~(uint64_t)0 + !condition;
    
    for (size_t i = 0; i < NLIMBS; i++) {
        uint64_t diff = (a->d[i] ^ b->d[i]) & mask;
        a->d[i] ^= diff;
        b->d[i] ^= diff;
    }
}

// AVX2 optimized versions
#ifdef __AVX2__
#include <immintrin.h>

void fp_add_avx2(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx) {
    // Process 4 limbs at a time with AVX2
    for (size_t i = 0; i < NLIMBS; i += 4) {
        __m256i a_vec = _mm256_loadu_si256((__m256i*)&a->d[i]);
        __m256i b_vec = _mm256_loadu_si256((__m256i*)&b->d[i]);
        __m256i sum = _mm256_add_epi64(a_vec, b_vec);
        _mm256_storeu_si256((__m256i*)&c->d[i], sum);
    }
    
    // Still need modular reduction
    fp_reduce_impl(c, ctx);
}

void fp_mul_avx2(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx) {
    // Fall back to standard implementation for now
    // AVX2 Montgomery multiplication would be more complex
    fp_mul_impl(c, a, b, ctx);
}
#endif

// ARM NEON optimized versions  
#ifdef __ARM_NEON
#include <arm_neon.h>

void fp_add_neon(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx) {
    // Process 2 limbs at a time with NEON
    for (size_t i = 0; i < NLIMBS; i += 2) {
        uint64x2_t a_vec = vld1q_u64(&a->d[i]);
        uint64x2_t b_vec = vld1q_u64(&b->d[i]);
        uint64x2_t sum = vaddq_u64(a_vec, b_vec);
        vst1q_u64(&c->d[i], sum);
    }
    
    // Still need modular reduction
    fp_reduce_impl(c, ctx);
}

void fp_mul_neon(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx) {
    // Fall back to standard implementation
    fp_mul_impl(c, a, b, ctx);
}
#endif
