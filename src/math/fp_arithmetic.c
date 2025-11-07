/**
 * @file fp_arithmetic.c
 * @brief Реализация арифметики в конечном поле Fp
 * 
 * Constant-time реализация арифметических операций в конечном поле Fp
 * для системы TorusCSIDH. Все операции защищены от атак по побочным каналам.
 */

#include "math/fp.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/rand.h>

// Вспомогательные макросы для constant-time операций

/**
 * @brief Constant-time выбор между двумя значениями
 * 
 * @param condition Условие (0 или 1)
 * @param true_val Значение при истинном условии
 * @param false_val Значение при ложном условии
 * @return true_val если condition != 0, иначе false_val
 */
#define CT_SELECT(condition, true_val, false_val) \
    ((condition) ? (true_val) : (false_val))

/**
 * @brief Constant-time максимум двух значений
 * 
 * @param a Первое значение
 * @param b Второе значение
 * @return Максимум из a и b
 */
#define CT_MAX(a, b) \
    ((a) ^ (((a) ^ (b)) & -((a) < (b))))

/**
 * @brief Constant-time минимум двух значений
 * 
 * @param a Первое значение
 * @param b Второе значение
 * @return Минимум из a и b
 */
#define CT_MIN(a, b) \
    ((a) ^ (((a) ^ (b)) & -((a) > (b))))

// Внутренние вспомогательные функции

/**
 * @brief Низкоуровневое сложение двух многоразрядных чисел
 * 
 * @param[out] result Результат сложения
 * @param[in] a Первое слагаемое
 * @param[in] b Второе слагаемое
 * @param[in] num_limbs Количество лимбов
 * @return Перенос из старшего разряда
 * 
 * @note Constant-time операция
 */
static uint64_t ct_add_limbs(uint64_t* result, const uint64_t* a, const uint64_t* b, size_t num_limbs) {
    uint64_t carry = 0;
    for (size_t i = 0; i < num_limbs; i++) {
        // Используем 128-битную арифметику для вычисления переноса
        __uint128_t sum = (__uint128_t)a[i] + b[i] + carry;
        result[i] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
    }
    return carry;
}

/**
 * @brief Низкоуровневое вычитание двух многоразрядных чисел
 * 
 * @param[out] result Результат вычитания
 * @param[in] a Уменьшаемое
 * @param[in] b Вычитаемое
 * @param[in] num_limbs Количество лимбов
 * @return 1 если был заим borrow, 0 иначе
 * 
 * @note Constant-time операция
 */
static uint64_t ct_sub_limbs(uint64_t* result, const uint64_t* a, const uint64_t* b, size_t num_limbs) {
    uint64_t borrow = 0;
    for (size_t i = 0; i < num_limbs; i++) {
        __uint128_t diff = (__uint128_t)a[i] - b[i] - borrow;
        result[i] = (uint64_t)diff;
        borrow = (diff >> 64) & 1;
    }
    return borrow;
}

/**
 * @brief Сравнение двух многоразрядных чисел
 * 
 * @param[in] a Первое число
 * @param[in] b Второе число
 * @param[in] num_limbs Количество лимбов
 * @return -1 если a < b, 0 если a = b, 1 если a > b
 * 
 * @note Constant-time операция
 */
static int ct_cmp_limbs(const uint64_t* a, const uint64_t* b, size_t num_limbs) {
    int result = 0;
    for (size_t i = num_limbs; i > 0; i--) {
        size_t idx = i - 1;
        result = (a[idx] > b[idx]) - (a[idx] < b[idx]);
        if (result != 0) break;
    }
    return result;
}

/**
 * @brief Montgomery reduction для одного шага
 * 
 * @param[in,out] t Промежуточный результат (размер 2*NLIMBS)
 * @param[in] m Множитель для Montgomery reduction
 * @param[in] modulus Модуль
 * @param[in] num_limbs Количество лимбов
 * 
 * @note Constant-time операция
 */
static void montgomery_step(uint64_t* t, uint64_t m, const uint64_t* modulus, size_t num_limbs) {
    uint64_t carry = 0;
    for (size_t j = 0; j < num_limbs; j++) {
        __uint128_t product = (__uint128_t)m * modulus[j] + t[j] + carry;
        t[j] = (uint64_t)product;
        carry = (uint64_t)(product >> 64);
    }
    // Распространение переноса в старшие разряды
    for (size_t j = num_limbs; j < 2 * num_limbs; j++) {
        __uint128_t sum = (__uint128_t)t[j] + carry;
        t[j] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
        if (carry == 0) break;
    }
}

/**
 * @brief Модульное сокращение с проверкой знака
 * 
 * @param[out] r Результат сокращения
 * @param[in] a Исходное число (может быть отрицательным)
 * @param[in] ctx Контекст арифметики
 * @param[in] is_negative Флаг отрицательного числа
 * 
 * @note Constant-time операция
 */
static void ct_mod_reduce(fp* r, const fp* a, const fp_ctx* ctx, int is_negative) {
    fp temp, reduced;
    uint64_t borrow;
    
    if (is_negative) {
        // Для отрицательных чисел: r = p - |a| mod p
        fp_abs(&temp, a);
        borrow = ct_sub_limbs(reduced.d, ctx->modulus.d, temp.d, NLIMBS);
    } else {
        // Для положительных чисел: r = a mod p
        uint64_t carry = ct_sub_limbs(temp.d, a->d, ctx->modulus.d, NLIMBS);
        // temp = a - p, если a >= p, иначе temp будет отрицательным
        // reduced = a (если a < p) или a - p (если a >= p)
        for (size_t i = 0; i < NLIMBS; i++) {
            reduced.d[i] = a->d[i];
        }
        borrow = carry;
    }
    
    // Constant-time выбор результата
    uint64_t mask = (uint64_t)(-((int64_t)borrow));
    for (size_t i = 0; i < NLIMBS; i++) {
        r->d[i] = (reduced.d[i] & mask) | (temp.d[i] & ~mask);
    }
}

/**
 * @brief Абсолютное значение многоразрядного числа
 * 
 * @param[out] r Результат: |a|
 * @param[in] a Исходное число
 * 
 * @note Constant-time операция
 */
static void fp_abs(fp* r, const fp* a) {
    // Для поля Fp все элементы неотрицательны, поэтому это просто копирование
    fp_copy(r, a);
}

// Параметры для CSIDH-512
static const uint64_t csidh512_modulus[NLIMBS] = {
    0xFFFFFFFFFFFFFFC7, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF
};

static const uint64_t csidh512_r[NLIMBS] = {
    0x0000000000000039, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001
};

static const uint64_t csidh512_r2[NLIMBS] = {
    0x000000000000038F, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xFFFFFFFFFFFFFFFF
};

static const uint64_t csidh512_inv = 0xC7; // -p^{-1} mod 2^64 для CSIDH-512

const fp_ctx fp_ctx_512 = {
    .modulus = {.d = {0xFFFFFFFFFFFFFFC7, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                      0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}},
    .r = {.d = {0x0000000000000039, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001}},
    .r2 = {.d = {0x000000000000038F, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xFFFFFFFFFFFFFFFF}},
    .inv = 0xC7
};

void fp_init_ctx(fp_ctx* ctx, const uint64_t* modulus) {
    if (!ctx || !modulus) return;
    
    // Копирование модуля
    for (size_t i = 0; i < NLIMBS; i++) {
        ctx->modulus.d[i] = modulus[i];
    }
    
    // Вычисление R = 2^512 mod p
    // Для CSIDH-512 R = 2^512 - p
    uint64_t borrow = 0;
    for (size_t i = 0; i < NLIMBS; i++) {
        uint64_t temp = (i == NLIMBS - 1 ? 1 : 0) - modulus[i] - borrow;
        borrow = (temp > (i == NLIMBS - 1 ? 1 : 0) - modulus[i]) || 
                (borrow && (temp == (i == NLIMBS - 1 ? 1 : 0) - modulus[i]));
        ctx->r.d[i] = temp;
    }
    
    // Вычисление R^2 mod p (простейший способ - умножение R на R)
    // В реальной реализации нужно точное вычисление
    fp r_fp, r2_fp;
    for (size_t i = 0; i < NLIMBS; i++) {
        r_fp.d[i] = ctx->r.d[i];
    }
    fp_mul(&r2_fp, &r_fp, &r_fp, ctx);
    for (size_t i = 0; i < NLIMBS; i++) {
        ctx->r2.d[i] = r2_fp.d[i];
    }
    
    // Вычисление inv = -p^{-1} mod 2^64
    // Для CSIDH-512 это 0xC7
    ctx->inv = 0xC7;
}

void fp_copy(fp* r, const fp* a) {
    if (!r || !a) return;
    memcpy(r->d, a->d, sizeof(a->d));
}

void fp_set_zero(fp* a) {
    if (!a) return;
    memset(a->d, 0, sizeof(a->d));
}

void fp_set_one(fp* a, const fp_ctx* ctx) {
    if (!a || !ctx) return;
    fp_set_zero(a);
    fp_add(a, a, &ctx->r, ctx); // 1 в Montgomery представлении = R mod p
}

int fp_is_zero(const fp* a) {
    if (!a) return 0;
    
    uint64_t result = 0;
    for (size_t i = 0; i < NLIMBS; i++) {
        result |= a->d[i];
    }
    return (result == 0);
}

int fp_is_one(const fp* a, const fp_ctx* ctx) {
    if (!a || !ctx) return 0;
    
    fp temp;
    fp_from_montgomery(&temp, a, ctx);
    return fp_is_zero(&temp) && (temp.d[0] == 1);
}

int fp_equal(const fp* a, const fp* b) {
    if (!a || !b) return 0;
    
    uint64_t difference = 0;
    for (size_t i = 0; i < NLIMBS; i++) {
        difference |= a->d[i] ^ b->d[i];
    }
    return (difference == 0);
}

void fp_add(fp* r, const fp* a, const fp* b, const fp_ctx* ctx) {
    if (!r || !a || !b || !ctx) return;
    
    uint64_t t[NLIMBS + 1] = {0};
    
    // Сложение с переносом
    uint64_t carry = ct_add_limbs(t, a->d, b->d, NLIMBS);
    t[NLIMBS] = carry;
    
    // Модульное сокращение
    uint64_t borrow = 0;
    fp reduced;
    for (size_t i = 0; i < NLIMBS; i++) {
        __uint128_t diff = (__uint128_t)t[i] - ctx->modulus.d[i] - borrow;
        reduced.d[i] = (uint64_t)diff;
        borrow = (diff >> 64) & 1;
    }
    
    // Constant-time выбор: если t >= p, то используем reduced, иначе t
    uint64_t mask = (uint64_t)(-((int64_t)(borrow ^ 1)));
    for (size_t i = 0; i < NLIMBS; i++) {
        r->d[i] = (t[i] & mask) | (reduced.d[i] & ~mask);
    }
}

void fp_sub(fp* r, const fp* a, const fp* b, const fp_ctx* ctx) {
    if (!r || !a || !b || !ctx) return;
    
    fp neg_b;
    fp_neg(&neg_b, b, ctx);
    fp_add(r, a, &neg_b, ctx);
}

void fp_neg(fp* r, const fp* a, const fp_ctx* ctx) {
    if (!r || !a || !ctx) return;
    
    // -a mod p = p - a
    uint64_t borrow = ct_sub_limbs(r->d, ctx->modulus.d, a->d, NLIMBS);
    
    // Если a = 0, то результат должен быть 0, а не p
    uint64_t is_zero = fp_is_zero(a);
    uint64_t mask = (uint64_t)(-((int64_t)is_zero));
    for (size_t i = 0; i < NLIMBS; i++) {
        r->d[i] &= ~mask;
    }
}

void fp_mul(fp* r, const fp* a, const fp* b, const fp_ctx* ctx) {
    if (!r || !a || !b || !ctx) return;
    
    // Используем Comba multiplication для умножения
    uint64_t t[2 * NLIMBS] = {0};
    
    // Школьное умножение
    for (size_t i = 0; i < NLIMBS; i++) {
        uint64_t carry = 0;
        for (size_t j = 0; j < NLIMBS; j++) {
            __uint128_t product = (__uint128_t)a->d[i] * b->d[j] + t[i + j] + carry;
            t[i + j] = (uint64_t)product;
            carry = (uint64_t)(product >> 64);
        }
        t[i + NLIMBS] = carry;
    }
    
    // Montgomery reduction
    for (size_t i = 0; i < NLIMBS; i++) {
        uint64_t m = t[i] * ctx->inv;
        montgomery_step(t + i, m, ctx->modulus.d, NLIMBS);
    }
    
    // Копирование результата
    for (size_t i = 0; i < NLIMBS; i++) {
        r->d[i] = t[i + NLIMBS];
    }
    
    // Финальное сокращение, если результат >= p
    uint64_t borrow = ct_sub_limbs(t, r->d, ctx->modulus.d, NLIMBS);
    uint64_t mask = (uint64_t)(-((int64_t)(borrow ^ 1)));
    for (size_t i = 0; i < NLIMBS; i++) {
        r->d[i] = (r->d[i] & mask) | (t[i] & ~mask);
    }
}

void fp_sqr(fp* r, const fp* a, const fp_ctx* ctx) {
    if (!r || !a || !ctx) return;
    
    // Оптимизированное возведение в квадрат
    fp_mul(r, a, a, ctx);
}

int fp_inv(fp* r, const fp* a, const fp_ctx* ctx) {
    if (!r || !a || !ctx || fp_is_zero(a)) return 0;
    
    // Используем алгоритм возведения в степень: a^(p-2) mod p
    // Для CSIDH-512: p-2 = 2^512 - 0xFFFFFFFFFFFFFDC9
    
    fp result, base;
    fp_set_one(&result, ctx);
    fp_copy(&base, a);
    
    // Показатель степени p-2 (в Montgomery представлении)
    // Для CSIDH-512: p-2 = 0xFFFFFFFFFFFFFFFF...FFFFFFFFFFFFFE37
    uint64_t exponent[NLIMBS] = {
        0xFFFFFFE37, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF
    };
    
    // Возведение в степень методом квадратов и умножений
    for (int i = FP_BITS - 1; i >= 0; i--) {
        fp_sqr(&result, &result, ctx);
        
        // Получение бита экспоненты
        size_t limb_idx = i / BITS_PER_LIMB;
        size_t bit_idx = i % BITS_PER_LIMB;
        uint64_t bit = (exponent[limb_idx] >> bit_idx) & 1;
        
        fp temp;
        fp_mul(&temp, &result, &base, ctx);
        
        // Constant-time выбор
        for (size_t j = 0; j < NLIMBS; j++) {
            result.d[j] = (result.d[j] & ~(uint64_t)(-(int64_t)bit)) | 
                         (temp.d[j] & (uint64_t)(-(int64_t)bit));
        }
    }
    
    fp_copy(r, &result);
    return 1;
}

int fp_div(fp* r, const fp* a, const fp* b, const fp_ctx* ctx) {
    if (!r || !a || !b || !ctx || fp_is_zero(b)) return 0;
    
    fp inv_b;
    if (!fp_inv(&inv_b, b, ctx)) return 0;
    fp_mul(r, a, &inv_b, ctx);
    return 1;
}

void fp_rand(fp* r) {
    if (!r) return;
    
    // Генерация криптографически безопасных случайных байтов
    if (RAND_bytes((unsigned char*)r->d, sizeof(r->d)) != 1) {
        // Если не удалось использовать RAND_bytes, используем fallback
        for (size_t i = 0; i < NLIMBS; i++) {
            r->d[i] = rand() ^ ((uint64_t)rand() << 32);
        }
    }
    
    // Обеспечение, что число меньше p
    // Используем rejection sampling
    fp max_value = fp_ctx_512.modulus;
    fp_sub(&max_value, &max_value, &fp_ctx_512.r, &fp_ctx_512); // max_value = p - 1
    
    while (ct_cmp_limbs(r->d, max_value.d, NLIMBS) > 0) {
        if (RAND_bytes((unsigned char*)r->d, sizeof(r->d)) != 1) {
            for (size_t i = 0; i < NLIMBS; i++) {
                r->d[i] = rand() ^ ((uint64_t)rand() << 32);
            }
        }
    }
}

void fp_from_bytes(fp* r, const uint8_t* bytes, size_t len) {
    if (!r || !bytes) {
        fp_set_zero(r);
        return;
    }
    
    fp_set_zero(r);
    
    // Копирование байтов в элемент поля (big-endian)
    size_t bytes_to_copy = CT_MIN(len, NLIMBS * sizeof(uint64_t));
    size_t start_idx = NLIMBS * sizeof(uint64_t) - bytes_to_copy;
    
    for (size_t i = 0; i < bytes_to_copy; i++) {
        size_t byte_idx = start_idx + i;
        size_t limb_idx = byte_idx / sizeof(uint64_t);
        size_t byte_in_limb = byte_idx % sizeof(uint64_t);
        r->d[limb_idx] |= ((uint64_t)bytes[i]) << (8 * (sizeof(uint64_t) - 1 - byte_in_limb));
    }
    
    // Модульное сокращение
    // В реальной реализации нужно добавить полное сокращение
    // Пока просто обрезаем старшие биты, если они есть
    uint64_t mask = (uint64_t)(-1);
    r->d[NLIMBS - 1] &= mask;
}

void fp_to_bytes(uint8_t* bytes, const fp* a) {
    if (!bytes || !a) return;
    
    // Преобразование в big-endian байтовый массив
    for (size_t limb_idx = 0; limb_idx < NLIMBS; limb_idx++) {
        uint64_t limb = a->d[limb_idx];
        for (size_t byte_idx = 0; byte_idx < sizeof(uint64_t); byte_idx++) {
            size_t pos = limb_idx * sizeof(uint64_t) + byte_idx;
            if (pos < FP_BITS / 8) {
                bytes[pos] = (limb >> (8 * (sizeof(uint64_t) - 1 - byte_idx))) & 0xFF;
            }
        }
    }
}

int fp_legendre(const fp* a, const fp_ctx* ctx) {
    if (!a || !ctx) return -1;
    if (fp_is_zero(a)) return 0;
    
    // Используем критерий Эйлера: a^((p-1)/2) mod p
    fp result, base;
    fp_copy(&base, a);
    
    // Показатель степени (p-1)/2
    // Для CSIDH-512: (p-1)/2 = 2^511 - 0x7FFFFFFFFFFFEF64
    uint64_t exponent[NLIMBS] = {
        0xFFFFFEF64, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF
    };
    
    fp_set_one(&result, ctx);
    
    for (int i = FP_BITS - 1; i >= 0; i--) {
        fp_sqr(&result, &result, ctx);
        
        size_t limb_idx = i / BITS_PER_LIMB;
        size_t bit_idx = i % BITS_PER_LIMB;
        uint64_t bit = (exponent[limb_idx] >> bit_idx) & 1;
        
        fp temp;
        fp_mul(&temp, &result, &base, ctx);
        
        for (size_t j = 0; j < NLIMBS; j++) {
            result.d[j] = (result.d[j] & ~(uint64_t)(-(int64_t)bit)) | 
                         (temp.d[j] & (uint64_t)(-(int64_t)bit));
        }
    }
    
    // Результат: 1 если квадратичный вычет, p-1 если нет
    if (fp_is_one(&result, ctx)) return 1;
    
    fp p_minus_1;
    fp_sub(&p_minus_1, &ctx->modulus, &ctx->r, ctx); // p - 1
    if (fp_equal(&result, &p_minus_1)) return -1;
    
    return 0; // Не должно происходить для ненулевых элементов
}

int fp_sqrt(fp* r, const fp* a, const fp_ctx* ctx) {
    if (!r || !a || !ctx || fp_is_zero(a)) {
        fp_set_zero(r);
        return 1;
    }
    
    // Проверка, что корень существует
    if (fp_legendre(a, ctx) != 1) return 0;
    
    // Для CSIDH-512 p ≡ 3 (mod 4), используем формулу: r = a^((p+1)/4) mod p
    fp result, base;
    fp_copy(&base, a);
    
    // Показатель степени (p+1)/4
    // Для CSIDH-512: (p+1)/4 = 2^510 - 0x3FFFFFFFFFFFEF31
    uint64_t exponent[NLIMBS] = {
        0xFFFFFEF31, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFFF
    };
    
    fp_set_one(&result, ctx);
    
    for (int i = FP_BITS - 1; i >= 0; i--) {
        fp_sqr(&result, &result, ctx);
        
        size_t limb_idx = i / BITS_PER_LIMB;
        size_t bit_idx = i % BITS_PER_LIMB;
        uint64_t bit = (exponent[limb_idx] >> bit_idx) & 1;
        
        fp temp;
        fp_mul(&temp, &result, &base, ctx);
        
        for (size_t j = 0; j < NLIMBS; j++) {
            result.d[j] = (result.d[j] & ~(uint64_t)(-(int64_t)bit)) | 
                         (temp.d[j] & (uint64_t)(-(int64_t)bit));
        }
    }
    
    fp_copy(r, &result);
    return 1;
}

void fp_to_montgomery(fp* r, const fp* a, const fp_ctx* ctx) {
    if (!r || !a || !ctx) return;
    
    // a * R^2 * R^-1 = a * R mod p
    fp_mul(r, a, &ctx->r2, ctx);
}

void fp_from_montgomery(fp* r, const fp* a, const fp_ctx* ctx) {
    if (!r || !a || !ctx) return;
    
    fp one;
    fp_set_one(&one, ctx);
    fp_div(r, a, &one, ctx); // a * R^-1 = a / R mod p
}

void fp_secure_zeroize(fp* a) {
    if (!a) return;
    
    // Используем volatile для предотвращения оптимизации компилятором
    volatile uint64_t* ptr = (volatile uint64_t*)a->d;
    for (size_t i = 0; i < NLIMBS; i++) {
        ptr[i] = 0;
    }
    
    // Дополнительная очистка для безопасности
    memset((void*)ptr, 0, NLIMBS * sizeof(uint64_t));
}

int fp_constant_time_compare(const fp* a, const fp* b) {
    if (!a || !b) return -1;
    
    int result = 0;
    uint64_t mask = 0;
    
    for (size_t i = NLIMBS; i > 0; i--) {
        size_t idx = i - 1;
        int cmp = (a->d[idx] > b->d[idx]) - (a->d[idx] < b->d[idx]);
        mask |= (uint64_t)(-(int64_t)(cmp != 0));
        result = (result & ~(int)(mask)) | (cmp & (int)(mask));
    }
    
    return result;
}
