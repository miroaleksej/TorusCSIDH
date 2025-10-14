#include "security_constants.h"
#include <iostream>
#include <vector>
#include <gmpxx.h>
#include <map>
#include <chrono>
#include "secure_audit_logger.h"

namespace toruscsidh {

// Инициализация констант времени
const std::chrono::microseconds SecurityConstants::SIGN_TARGET_TIME = std::chrono::microseconds(1500);
const std::chrono::microseconds SecurityConstants::VERIFY_TARGET_TIME = std::chrono::microseconds(1500);

// Статические переменные
std::map<SecurityConstants::SecurityLevel, SecurityConstants::SecurityParams> SecurityConstants::security_params_;
std::map<SecurityConstants::SecurityLevel, SecurityConstants::GeometricParams> SecurityConstants::geometric_params_;

void SecurityConstants::initialize_security_params() {
    // Инициализация для уровня 128 бит
    SecurityParams params_128;
    params_128.num_primes = 74; // 74 простых числа для 128-битной безопасности
    params_128.max_key_magnitude = 6; // Максимальная величина ключа (L∞ норма)
    params_128.max_key_sum = 300; // Максимальная сумма ключа (L1 норма)
    params_128.geometric_radius = 2; // Радиус подграфа для геометрической проверки
    
    // Генерация простых чисел
    params_128.primes.resize(params_128.num_primes);
    
    // Фиксированные простые числа для уровня 128 бит
    // Эти числа выбраны так, чтобы их произведение было близко к p+1
    // где p - характеристика поля
    static const unsigned long primes_128[] = {
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
        37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
        79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
        131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
        181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
        239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
        293, 307, 311, 313, 317, 331, 337, 347, 349, 353,
        359, 367, 373, 379
    };
    
    for (int i = 0; i < params_128.num_primes; i++) {
        params_128.primes[i] = GmpRaii(primes_128[i]);
    }
    
    security_params_[LEVEL_128] = params_128;
    
    // Инициализация для уровня 192 бит
    SecurityParams params_192;
    params_192.num_primes = 110; // 110 простых чисел для 192-битной безопасности
    params_192.max_key_magnitude = 8; // Максимальная величина ключа (L∞ норма)
    params_192.max_key_sum = 500; // Максимальная сумма ключа (L1 норма)
    params_192.geometric_radius = 2; // Радиус подграфа для геометрической проверки
    
    // Генерация простых чисел
    params_192.primes.resize(params_192.num_primes);
    
    // Фиксированные простые числа для уровня 192 бит
    static const unsigned long primes_192[] = {
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
        37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
        79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
        131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
        181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
        239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
        293, 307, 311, 313, 317, 331, 337, 347, 349, 353,
        359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
        421, 431, 433, 439, 443, 449, 457, 461, 463, 467,
        479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
        557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
        613, 617, 619, 631, 641, 643, 647, 653, 659, 661
    };
    
    for (int i = 0; i < params_192.num_primes; i++) {
        params_192.primes[i] = GmpRaii(primes_192[i]);
    }
    
    security_params_[LEVEL_192] = params_192;
    
    // Инициализация для уровня 256 бит
    SecurityParams params_256;
    params_256.num_primes = 150; // 150 простых чисел для 256-битной безопасности
    params_256.max_key_magnitude = 10; // Максимальная величина ключа (L∞ норма)
    params_256.max_key_sum = 750; // Максимальная сумма ключа (L1 норма)
    params_256.geometric_radius = 3; // Радиус подграфа для геометрической проверки
    
    // Генерация простых чисел
    params_256.primes.resize(params_256.num_primes);
    
    // Фиксированные простые числа для уровня 256 бит
    static const unsigned long primes_256[] = {
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
        37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
        79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
        131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
        181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
        239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
        293, 307, 311, 313, 317, 331, 337, 347, 349, 353,
        359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
        421, 431, 433, 439, 443, 449, 457, 461, 463, 467,
        479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
        557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
        613, 617, 619, 631, 641, 643, 647, 653, 659, 661,
        673, 677, 683, 691, 701, 709, 719, 727, 733, 739,
        743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
        821, 823, 827, 829, 839, 853, 857, 859, 863, 877,
        881, 883, 887, 907, 911, 919, 929, 937, 941, 947,
        953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019,
        1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087,
        1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153,
        1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229
    };
    
    for (int i = 0; i < params_256.num_primes; i++) {
        params_256.primes[i] = GmpRaii(primes_256[i]);
    }
    
    security_params_[LEVEL_256] = params_256;
}

void SecurityConstants::initialize_geometric_params() {
    // Инициализация параметров геометрической проверки для уровня 128 бит
    GeometricParams params_128;
    params_128.min_cyclomatic = 0.75; // Нормализованное значение для 2.0
    params_128.min_spectral_gap = 0.80; // Нормализованное значение для 1.5
    params_128.min_clustering_coeff = 0.40;
    params_128.min_degree_entropy = 0.70;
    params_128.min_distance_entropy = 0.60;
    params_128.geometric_radius = 2;
    geometric_params_[LEVEL_128] = params_128;
    
    // Инициализация параметров геометрической проверки для уровня 192 бит
    GeometricParams params_192;
    params_192.min_cyclomatic = 0.75; // Нормализованное значение для 2.0
    params_192.min_spectral_gap = 0.80; // Нормализованное значение для 1.5
    params_192.min_clustering_coeff = 0.40;
    params_192.min_degree_entropy = 0.70;
    params_192.min_distance_entropy = 0.60;
    params_192.geometric_radius = 2;
    geometric_params_[LEVEL_192] = params_192;
    
    // Инициализация параметров геометрической проверки для уровня 256 бит
    GeometricParams params_256;
    params_256.min_cyclomatic = 0.75; // Нормализованное значение для 2.0
    params_256.min_spectral_gap = 0.80; // Нормализованное значение для 1.5
    params_256.min_clustering_coeff = 0.40;
    params_256.min_degree_entropy = 0.70;
    params_256.min_distance_entropy = 0.60;
    params_256.geometric_radius = 3;
    geometric_params_[LEVEL_256] = params_256;
}

const SecurityConstants::SecurityParams& SecurityConstants::get_params(SecurityLevel level) {
    static bool initialized = false;
    
    if (!initialized) {
        initialize_security_params();
        initialize_geometric_params();
        initialized = true;
    }
    
    return security_params_[level];
}

const std::vector<GmpRaii>& SecurityConstants::get_primes(SecurityLevel level) {
    return get_params(level).primes;
}

int SecurityConstants::get_max_key_magnitude(SecurityLevel level) {
    return get_params(level).max_key_magnitude;
}

int SecurityConstants::get_max_key_sum(SecurityLevel level) {
    return get_params(level).max_key_sum;
}

MontgomeryCurve SecurityConstants::get_base_curve(SecurityLevel level) {
    // Получаем базовое простое число
    GmpRaii p = get_base_prime();
    
    // Для TorusCSIDH параметр A всегда равен 0
    return MontgomeryCurve(GmpRaii(0), p);
}

GmpRaii SecurityConstants::get_base_prime() {
    // Базовое простое число для суперсингулярных кривых
    // p = 2^384 - 2^128 - 2^96 + 2^32 - 1 (аналогично secp256k1, но для 384 бит)
    
    GmpRaii p;
    mpz_ui_pow_ui(p.get_mpz_t(), 2, 384);
    mpz_sub_ui(p.get_mpz_t(), p.get_mpz_t(), 1);
    
    mpz_ui_pow_ui(p.get_mpz_t(), 2, 128);
    mpz_sub(p.get_mpz_t(), p.get_mpz_t(), p.get_mpz_t());
    
    mpz_ui_pow_ui(p.get_mpz_t(), 2, 96);
    mpz_sub(p.get_mpz_t(), p.get_mpz_t(), p.get_mpz_t());
    
    mpz_ui_pow_ui(p.get_mpz_t(), 2, 32);
    mpz_add(p.get_mpz_t(), p.get_mpz_t(), p.get_mpz_t());
    
    return p;
}

void SecurityConstants::initialize_geometric_params(SecurityLevel level, GeometricParams& params) {
    static bool initialized = false;
    
    if (!initialized) {
        initialize_security_params();
        initialize_geometric_params();
        initialized = true;
    }
    
    params = geometric_params_[level];
}

const SecurityConstants::GeometricParams& SecurityConstants::get_geometric_params(SecurityLevel level) {
    static bool initialized = false;
    
    if (!initialized) {
        initialize_security_params();
        initialize_geometric_params();
        initialized = true;
    }
    
    return geometric_params_[level];
}

std::string SecurityConstants::security_level_to_string(SecurityLevel level) {
    switch (level) {
        case LEVEL_128:
            return "128-bit";
        case LEVEL_192:
            return "192-bit";
        case LEVEL_256:
            return "256-bit";
        default:
            return "Unknown";
    }
}

int SecurityConstants::get_num_primes(SecurityLevel level) {
    return get_params(level).num_primes;
}

} // namespace toruscsidh
