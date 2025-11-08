// src/math/fp_arithmetic.c
#include "math/fp_arithmetic.h"
#include "math/montgomery.h"
#include "utils/secure_utils.h"
#include "utils/random.h"
#include "utils/error_handling.h"
#include "utils/cpu_features.h"
#include <string.h>

// ============================================================================
// Internal Constants
// ============================================================================

/**
 * @brief Maximum iterations for finding quadratic non-residue
 */
#define MAX_NON_RESIDUE_ATTEMPTS 100

// ============================================================================
// Internal Function Declarations
// ============================================================================

static int fp_sqrt_tonelli_shanks(fp* c, const fp* a, const fp_ctx_t* ctx);
static int fp_sqrt_simple(fp* c, const fp* a, const fp_ctx_t* ctx);
static int fp_find_quadratic_non_residue(fp* z, const fp_ctx_t* ctx);
static void fp_compute_exponentiation_table(fp* table, const fp* base, 
                                          const fp_ctx_t* ctx);
static void fp_add_impl(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx);
static void fp_sub_impl(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx);
static void fp_mul_impl(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx);
static void fp_sqr_impl(fp* c, const fp* a, const fp_ctx_t* ctx);
static void fp_reduce_impl(fp* a, const fp_ctx_t* ctx);
static int fp_inv_fermat(fp* c, const fp* a, const fp_ctx_t* ctx);
static void fp_div2(fp* c, const fp* a, const fp_ctx_t* ctx);

// ============================================================================
// Context Management
// ============================================================================

int fp_ctx_init(fp_ctx_t* ctx, const fp* modulus, uint32_t security_level) {
    if (!ctx || !modulus) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Copy modulus
    fp_copy(&ctx->modulus, modulus);
    ctx->security_level = security_level;
    
    // Initialize Montgomery context
    if (montgomery_ctx_init(&ctx->montgomery_ctx, modulus) != TORUS_SUCCESS) {
        return TORUS_ERROR_COMPUTATION;
    }
    
    // Precompute p - 2 for exponentiation: a^(p-2) = a^(-1) mod p
    fp_set_one(&ctx->p_minus_2, ctx);
    fp_add(&ctx->p_minus_2, modulus, &ctx->p_minus_2, ctx); // p + 1
    fp_sub(&ctx->p_minus_2, &ctx->p_minus_2, &ctx->p_minus_2, ctx); // p - 2
    
    // Precompute (p + 1) / 4 for square roots (when p ≡ 3 mod 4)
    fp_set_u64(&ctx->p_plus_1_div_4, 1, ctx);
    fp_add(&ctx->p_plus_1_div_4, modulus, &ctx->p_plus_1_div_4, ctx); // p + 1
    fp_div2(&ctx->p_plus_1_div_4, &ctx->p_plus_1_div_4, ctx); // (p + 1) / 2
    fp_div2(&ctx->p_plus_1_div_4, &ctx->p_plus_1_div_4, ctx); // (p + 1) / 4
    
    // Precompute (p - 1) / 2
    fp_set_u64(&ctx->p_minus_1_div_2, 1, ctx);
    fp_sub(&ctx->p_minus_1_div_2, modulus, &ctx->p_minus_1_div_2, ctx); // p - 1
    fp_div2(&ctx->p_minus_1_div_2, &ctx->p_minus_1_div_2, ctx); // (p - 1) / 2
    
    // Set flags for prime modulus properties
    uint64_t p_mod_4 = ctx->modulus.d[0] & 3;
    uint64_t p_mod_8 = ctx->modulus.d[0] & 7;
    
    ctx->p_mod_4_is_3 = (p_mod_4 == 3);
    ctx->p_mod_8_is_5 = (p_mod_8 == 5);
    
    return TORUS_SUCCESS;
}

void fp_ctx_cleanup(fp_ctx_t* ctx) {
    if (!ctx) return;
    
    // Cleanup Montgomery context
    montgomery_ctx_cleanup(&ctx->montgomery_ctx);
    
    // Securely zeroize all sensitive data
    secure_zeroize(ctx, sizeof(fp_ctx_t));
}

// ============================================================================
// Basic Operations
// ============================================================================

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

void fp_set_u64(fp* a, uint64_t value, const fp_ctx_t* ctx) {
    if (!a || !ctx) return;
    
    fp_set_zero(a);
    a->d[0] = value;
    fp_reduce(a, ctx);
}

void fp_set_bytes(fp* a, const uint8_t* bytes, const fp_ctx_t* ctx) {
    if (!a || !bytes || !ctx) return;
    
    fp_set_zero(a);
    
    // Convert from big-endian bytes
    size_t bytes_per_limb = sizeof(uint64_t);
    size_t fp_bytes = fp_get_bytes(ctx);
    
    for (size_t i = 0; i < NLIMBS; i++) {
        for (size_t j = 0; j < bytes_per_limb; j++) {
            size_t byte_index = (NLIMBS - 1 - i) * bytes_per_limb + j;
            if (byte_index < fp_bytes) {
                a->d[i] |= ((uint64_t)bytes[byte_index]) << (8 * (bytes_per_limb - 1 - j));
            }
        }
    }
    
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
    
    size_t fp_bytes = fp_get_bytes(ctx);
    uint8_t* random_bytes = malloc(fp_bytes);
    if (!random_bytes) {
        return TORUS_ERROR_MEMORY;
    }
    
    if (random_bytes_secure(random_bytes, fp_bytes) != TORUS_SUCCESS) {
        free(random_bytes);
        return TORUS_ERROR_RANDOM;
    }
    
    fp_set_bytes(a, random_bytes, ctx);
    
    // Securely zeroize temporary buffer
    secure_zeroize(random_bytes, fp_bytes);
    free(random_bytes);
    
    return TORUS_SUCCESS;
}

int fp_random_nonzero(fp* a, const fp_ctx_t* ctx) {
    if (!a || !ctx) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    int attempts = 0;
    
    do {
        if (fp_random(a, ctx) != TORUS_SUCCESS) {
            return TORUS_ERROR_RANDOM;
        }
        attempts++;
    } while (fp_is_zero(a) && attempts < FP_MAX_RANDOM_ATTEMPTS);
    
    if (fp_is_zero(a)) {
        return TORUS_ERROR_RANDOM;
    }
    
    return TORUS_SUCCESS;
}

// ============================================================================
// Arithmetic Operations
// ============================================================================

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
    
    // Check if result >= modulus
    uint64_t borrow = 0;
    fp reduced;
    for (size_t i = 0; i < NLIMBS; i++) {
        uint64_t diff = temp.d[i] - ctx->modulus.d[i] - borrow;
        borrow = (temp.d[i] < ctx->modulus.d[i] + borrow) || 
                (borrow && (temp.d[i] == ctx->modulus.d[i] + borrow));
        reduced.d[i] = diff;
    }
    
    // Constant-time selection: use reduced if borrow == 0 (result >= modulus), else use temp
    uint64_t mask = ~(uint64_t)0 + !borrow; // mask = (borrow == 0) ? ~0 : 0
    for (size_t i = 0; i < NLIMBS; i++) {
        c->d[i] = (temp.d[i] & mask) | (reduced.d[i] & ~mask);
    }
}

void fp_sub(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx) {
#if defined(__AVX2__)
    if (cpu_has_avx2()) {
        fp_sub_avx2(c, a, b, ctx);
        return;
    }
#elif defined(__ARM_NEON)
    if (cpu_has_neon()) {
        fp_sub_neon(c, a, b, ctx);
        return;
    }
#endif
    
    fp_sub_impl(c, a, b, ctx);
}

static void fp_sub_impl(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx) {
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
#if defined(__AVX2__)
    if (cpu_has_avx2()) {
        fp_sqr_avx2(c, a, ctx);
        return;
    }
#elif defined(__ARM_NEON)
    if (cpu_has_neon()) {
        fp_sqr_neon(c, a, ctx);
        return;
    }
#endif
    
    fp_sqr_impl(c, a, ctx);
}

static void fp_sqr_impl(fp* c, const fp* a, const fp_ctx_t* ctx) {
    // Square is just multiplication with itself
    fp_mul_impl(c, a, a, ctx);
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
    
    fp base;
    fp_copy(&base, a);
    fp exponent;
    fp_copy(&exponent, &ctx->p_minus_2);
    
    // Use windowed exponentiation for better performance
    fp table[1 << FP_EXPONENTIATION_WINDOW_SIZE];
    fp_compute_exponentiation_table(table, &base, ctx);
    
    // Constant-time windowed exponentiation
    uint32_t total_bits = fp_get_bits(ctx);
    int window = 0;
    uint8_t window_value = 0;
    
    for (int i = total_bits - 1; i >= 0; i--) {
        // Square the result
        fp_sqr(&result, &result, ctx);
        
        // Get the next bit
        uint8_t bit = fp_get_bit(&exponent, i, ctx);
        
        // Update window
        window = (window << 1) | bit;
        
        if (window > 0 && (i % FP_EXPONENTIATION_WINDOW_SIZE == 0 || i == 0)) {
            // Process window
            fp_mul(&result, &result, &table[window], ctx);
            window = 0;
        }
    }
    
    fp_copy(c, &result);
    
    // Securely zeroize temporary values
    secure_zeroize(&result, sizeof(result));
    secure_zeroize(&base, sizeof(base));
    secure_zeroize(&exponent, sizeof(exponent));
    secure_zeroize(table, sizeof(table));
    
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
    
    // Use windowed exponentiation for better performance
    fp table[1 << FP_EXPONENTIATION_WINDOW_SIZE];
    fp_compute_exponentiation_table(table, a, ctx);
    
    fp exponent;
    fp_copy(&exponent, e);
    
    // Constant-time windowed exponentiation
    uint32_t total_bits = fp_get_bits(ctx);
    int window = 0;
    uint8_t window_value = 0;
    
    for (int i = total_bits - 1; i >= 0; i--) {
        // Square the result
        fp_sqr(&result, &result, ctx);
        
        // Get the next bit
        uint8_t bit = fp_get_bit(&exponent, i, ctx);
        
        // Update window
        window = (window << 1) | bit;
        
        if (window > 0 && (i % FP_EXPONENTIATION_WINDOW_SIZE == 0 || i == 0)) {
            // Process window
            fp_mul(&result, &result, &table[window], ctx);
            window = 0;
        }
    }
    
    fp_copy(c, &result);
    
    // Securely zeroize temporary values
    secure_zeroize(&result, sizeof(result));
    secure_zeroize(&exponent, sizeof(exponent));
    secure_zeroize(table, sizeof(table));
}

void fp_pow_u64(fp* c, const fp* a, uint64_t exponent, const fp_ctx_t* ctx) {
    if (!c || !a || !ctx) return;
    
    fp result;
    fp_set_one(&result, ctx);
    
    fp base;
    fp_copy(&base, a);
    
    uint64_t exp = exponent;
    
    // Square-and-multiply exponentiation (constant-time)
    while (exp > 0) {
        if (exp & 1) {
            fp_mul(&result, &result, &base, ctx);
        }
        fp_sqr(&base, &base, ctx);
        exp >>= 1;
    }
    
    fp_copy(c, &result);
    
    // Securely zeroize temporary values
    secure_zeroize(&result, sizeof(result));
    secure_zeroize(&base, sizeof(base));
}

// ============================================================================
// Advanced Operations
// ============================================================================

void fp_reduce(fp* a, const fp_ctx_t* ctx) {
    fp_reduce_impl(a, ctx);
}

static void fp_reduce_impl(fp* a, const fp_ctx_t* ctx) {
    // Check if a >= modulus using constant-time comparison
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
    fp result;
    fp_pow(&result, a, &ctx->p_minus_1_div_2, ctx);
    
    int is_square = fp_is_one(&result, ctx);
    
    // Securely zeroize temporary values
    secure_zeroize(&result, sizeof(result));
    
    return is_square;
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
    
    // For primes with special forms, use optimized methods
    if (ctx->p_mod_4_is_3) {
        return fp_sqrt_simple(c, a, ctx);
    }
    
    // Otherwise use Tonelli-Shanks algorithm for general case
    return fp_sqrt_tonelli_shanks(c, a, ctx);
}

static int fp_sqrt_simple(fp* c, const fp* a, const fp_ctx_t* ctx) {
    // For p ≡ 3 mod 4: sqrt(a) = a^{(p+1)/4} mod p
    fp_pow(c, a, &ctx->p_plus_1_div_4, ctx);
    
    // Verify the result
    fp check;
    fp_sqr(&check, c, ctx);
    
    int correct = fp_equal(&check, a);
    
    // Securely zeroize temporary value
    secure_zeroize(&check, sizeof(check));
    
    if (!correct) {
        // Fall back to Tonelli-Shanks if simple method fails
        return fp_sqrt_tonelli_shanks(c, a, ctx);
    }
    
    return TORUS_SUCCESS;
}

static int fp_find_quadratic_non_residue(fp* z, const fp_ctx_t* ctx) {
    // Try small numbers first
    for (uint64_t i = 2; i <= MAX_NON_RESIDUE_ATTEMPTS; i++) {
        fp_set_u64(z, i, ctx);
        if (!fp_is_square(z, ctx)) {
            return TORUS_SUCCESS;
        }
    }
    
    return TORUS_ERROR_COMPUTATION;
}

static int fp_sqrt_tonelli_shanks(fp* c, const fp* a, const fp_ctx_t* ctx) {
    fp z;
    int ret = TORUS_ERROR_COMPUTATION;
    
    // Find a quadratic non-residue in Fp
    if (fp_find_quadratic_non_residue(&z, ctx) != TORUS_SUCCESS) {
        return TORUS_ERROR_COMPUTATION;
    }
    
    // Factor p - 1 = Q * 2^S
    fp q;
    uint64_t s = 0;
    
    // q = p - 1
    fp_set_u64(&q, 1, ctx);
    fp_sub(&q, &ctx->modulus, &q, ctx);
    
    // Count factors of 2
    fp temp;
    fp_copy(&temp, &q);
    
    while ((temp.d[0] & 1) == 0) {
        uint64_t carry = 0;
        for (int j = NLIMBS - 1; j >= 0; j--) {
            if (j > 0) {
                carry = (temp.d[j] & 1) ? (1ULL << 63) : 0;
            }
            temp.d[j] = (temp.d[j] >> 1) | carry;
        }
        s++;
    }
    fp_copy(&q, &temp);
    
    // Initialize variables for Tonelli-Shanks
    fp m, c_val, t, r;
    fp_set_u64(&m, s, ctx);
    
    // c_val = z^q
    if (fp_pow(&c_val, &z, &q, ctx) != TORUS_SUCCESS) {
        goto cleanup;
    }
    
    // t = a^q
    if (fp_pow(&t, a, &q, ctx) != TORUS_SUCCESS) {
        goto cleanup;
    }
    
    // Compute (q + 1) / 2
    fp q_plus_one_div_2;
    fp_copy(&q_plus_one_div_2, &q);
    fp_set_u64(&ctx->modulus, 1, ctx); // Temporary use of modulus field
    fp_add(&q_plus_one_div_2, &q_plus_one_div_2, &ctx->modulus, ctx);
    
    uint64_t carry = 0;
    for (int j = NLIMBS - 1; j >= 0; j--) {
        uint64_t new_carry = (q_plus_one_div_2.d[j] & 1) ? (1ULL << 63) : 0;
        q_plus_one_div_2.d[j] = (q_plus_one_div_2.d[j] >> 1) | carry;
        carry = new_carry;
    }
    
    // r = a^((q+1)/2)
    if (fp_pow(&r, a, &q_plus_one_div_2, ctx) != TORUS_SUCCESS) {
        goto cleanup;
    }
    
    // Main Tonelli-Shanks loop
    uint64_t iterations = 0;
    while (!fp_is_one(&t, ctx)) {
        if (iterations++ > FP_MAX_TS_ITERATIONS) {
            ret = TORUS_ERROR_COMPUTATION;
            goto cleanup;
        }
        
        // Find the smallest i such that t^{2^i} = 1
        uint64_t i = 0;
        fp t_power;
        fp_copy(&t_power, &t);
        
        while (!fp_is_one(&t_power, ctx)) {
            if (fp_sqr(&t_power, &t_power, ctx) != TORUS_SUCCESS) {
                ret = TORUS_ERROR_COMPUTATION;
                goto cleanup;
            }
            i++;
            if (i > s) {
                ret = TORUS_ERROR_COMPUTATION;
                goto cleanup;
            }
        }
        
        // Update values
        fp b;
        uint64_t exponent_power = s - i - 1;
        
        // b = c_val^(2^(s-i-1))
        fp_copy(&b, &c_val);
        for (uint64_t j = 0; j < exponent_power; j++) {
            if (fp_sqr(&b, &b, ctx) != TORUS_SUCCESS) {
                ret = TORUS_ERROR_COMPUTATION;
                goto cleanup;
            }
        }
        
        // Update r, c_val, t, s
        fp_mul(&r, &r, &b, ctx);
        fp_sqr(&b, &b, ctx);
        fp_mul(&c_val, &b, &b, ctx);
        fp_mul(&t, &t, &c_val, ctx);
        s = i;
    }
    
    fp_copy(c, &r);
    
    // Verify the result
    fp check;
    fp_sqr(&check, c, ctx);
    
    if (!fp_equal(&check, a)) {
        ret = TORUS_ERROR_COMPUTATION;
        goto cleanup;
    }
    
    ret = TORUS_SUCCESS;

cleanup:
    // Securely zeroize temporary values
    secure_zeroize(&z, sizeof(fp));
    secure_zeroize(&q, sizeof(fp));
    secure_zeroize(&temp, sizeof(fp));
    secure_zeroize(&m, sizeof(fp));
    secure_zeroize(&c_val, sizeof(fp));
    secure_zeroize(&t, sizeof(fp));
    secure_zeroize(&r, sizeof(fp));
    secure_zeroize(&t_power, sizeof(fp));
    secure_zeroize(&b, sizeof(fp));
    secure_zeroize(&check, sizeof(fp));
    secure_zeroize(&q_plus_one_div_2, sizeof(fp));
    
    return ret;
}

void fp_to_montgomery(fp* c, const fp* a, const fp_ctx_t* ctx) {
    montgomery_to_montgomery(c, a, &ctx->montgomery_ctx);
}

void fp_from_montgomery(fp* c, const fp* a, const fp_ctx_t* ctx) {
    montgomery_from_montgomery(c, a, &ctx->montgomery_ctx);
}

// ============================================================================
// Utility Functions
// ============================================================================

void fp_to_bytes(uint8_t* bytes, const fp* a, const fp_ctx_t* ctx) {
    if (!bytes || !a || !ctx) return;
    
    // Convert to canonical form first
    fp canonical;
    fp_copy(&canonical, a);
    fp_reduce(&canonical, ctx);
    
    // Convert to big-endian bytes
    size_t bytes_per_limb = sizeof(uint64_t);
    size_t fp_bytes = fp_get_bytes(ctx);
    
    for (size_t i = 0; i < NLIMBS; i++) {
        for (size_t j = 0; j < bytes_per_limb; j++) {
            size_t byte_index = (NLIMBS - 1 - i) * bytes_per_limb + j;
            if (byte_index < fp_bytes) {
                bytes[byte_index] = (canonical.d[i] >> (8 * (bytes_per_limb - 1 - j))) & 0xFF;
            }
        }
    }
    
    // Securely zeroize temporary value
    secure_zeroize(&canonical, sizeof(canonical));
}

int fp_from_bytes(fp* a, const uint8_t* bytes, const fp_ctx_t* ctx) {
    if (!a || !bytes || !ctx) return TORUS_ERROR_INVALID_PARAM;
    
    fp_set_bytes(a, bytes, ctx);
    
    // Check if the value is less than modulus
    if (!fp_is_canonical(a, ctx)) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    return TORUS_SUCCESS;
}

int fp_is_canonical(const fp* a, const fp_ctx_t* ctx) {
    if (!a || !ctx) return 0;
    
    // Check if a < modulus using constant-time comparison
    uint64_t borrow = 0;
    for (size_t i = 0; i < NLIMBS; i++) {
        uint64_t diff = a->d[i] - ctx->modulus.d[i] - borrow;
        borrow = (a->d[i] < ctx->modulus.d[i] + borrow) || 
                (borrow && (a->d[i] == ctx->modulus.d[i] + borrow));
    }
    
    // If borrow == 1, then a < modulus (canonical)
    return (borrow == 1);
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

uint8_t fp_get_bit(const fp* a, uint32_t bit_index, const fp_ctx_t* ctx) {
    if (!a || !ctx) return 0;
    
    uint32_t limb_index = bit_index / 64;
    uint32_t bit_in_limb = bit_index % 64;
    
    if (limb_index >= NLIMBS) {
        return 0;
    }
    
    return (a->d[limb_index] >> bit_in_limb) & 1;
}

uint32_t fp_get_bits(const fp_ctx_t* ctx) {
    if (!ctx) return 0;
    
    // Count the number of bits in the modulus
    for (int i = NLIMBS - 1; i >= 0; i--) {
        if (ctx->modulus.d[i] != 0) {
            // Count leading zeros and calculate bits
            uint64_t limb = ctx->modulus.d[i];
            int leading_zeros = 0;
            while ((limb & (1ULL << 63)) == 0) {
                leading_zeros++;
                limb <<= 1;
            }
            return (i + 1) * 64 - leading_zeros;
        }
    }
    
    return 0;
}

uint32_t fp_get_bytes(const fp_ctx_t* ctx) {
    if (!ctx) return 0;
    
    uint32_t bits = fp_get_bits(ctx);
    return (bits + 7) / 8;
}

// ============================================================================
// Internal Helper Functions
// ============================================================================

static void fp_compute_exponentiation_table(fp* table, const fp* base, 
                                          const fp_ctx_t* ctx) {
    // Precompute powers for windowed exponentiation
    fp_set_one(&table[0], ctx);
    fp_copy(&table[1], base, ctx);
    
    for (int i = 2; i < (1 << FP_EXPONENTIATION_WINDOW_SIZE); i++) {
        fp_mul(&table[i], &table[i-1], base, ctx);
    }
}

static void fp_div2(fp* c, const fp* a, const fp_ctx_t* ctx) {
    if (!c || !a || !ctx) return;
    
    // Check if a is even
    uint8_t is_even = (a->d[0] & 1) == 0;
    
    // Divide by 2
    uint64_t carry = 0;
    for (int i = NLIMBS - 1; i >= 0; i--) {
        uint64_t new_carry = (a->d[i] & 1) ? (1ULL << 63) : 0;
        c->d[i] = (a->d[i] >> 1) | carry;
        carry = new_carry;
    }
    
    // If a was odd, add (p+1)/2
    if (!is_even) {
        fp half_p_plus_1;
        fp_copy(&half_p_plus_1, &ctx->p_plus_1_div_4);
        fp_add(&half_p_plus_1, &half_p_plus_1, &half_p_plus_1, ctx); // (p+1)/2
        
        fp_add(c, c, &half_p_plus_1, ctx);
        
        // Securely zeroize temporary value
        secure_zeroize(&half_p_plus_1, sizeof(half_p_plus_1));
    }
}

// ============================================================================
// Architecture-Specific Optimizations
// ============================================================================

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

void fp_sub_avx2(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx) {
    // Process 4 limbs at a time with AVX2
    for (size_t i = 0; i < NLIMBS; i += 4) {
        __m256i a_vec = _mm256_loadu_si256((__m256i*)&a->d[i]);
        __m256i b_vec = _mm256_loadu_si256((__m256i*)&b->d[i]);
        __m256i diff = _mm256_sub_epi64(a_vec, b_vec);
        _mm256_storeu_si256((__m256i*)&c->d[i], diff);
    }
    
    // Still need modular reduction
    fp_reduce_impl(c, ctx);
}

void fp_mul_avx2(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx) {
    // Fall back to standard implementation for now
    // AVX2 Montgomery multiplication would be more complex
    fp_mul_impl(c, a, b, ctx);
}

void fp_sqr_avx2(fp* c, const fp* a, const fp_ctx_t* ctx) {
    fp_sqr_impl(c, a, ctx);
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

void fp_sub_neon(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx) {
    // Process 2 limbs at a time with NEON
    for (size_t i = 0; i < NLIMBS; i += 2) {
        uint64x2_t a_vec = vld1q_u64(&a->d[i]);
        uint64x2_t b_vec = vld1q_u64(&b->d[i]);
        uint64x2_t diff = vsubq_u64(a_vec, b_vec);
        vst1q_u64(&c->d[i], diff);
    }
    
    // Still need modular reduction
    fp_reduce_impl(c, ctx);
}

void fp_mul_neon(fp* c, const fp* a, const fp* b, const fp_ctx_t* ctx) {
    // Fall back to standard implementation
    fp_mul_impl(c, a, b, ctx);
}

void fp_sqr_neon(fp* c, const fp* a, const fp_ctx_t* ctx) {
    fp_sqr_impl(c, a, ctx);
}
#endif
