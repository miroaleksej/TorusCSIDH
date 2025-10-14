#include "rfc6979_rng.h"
#include <iostream>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <cmath>
#include <sodium.h>
#include "secure_random.h"
#include "security_constants.h"
#include "geometric_validator.h"
#include "secure_audit_logger.h"
#include "postquantum_hash.h"

namespace toruscsidh {

RFC6979_RNG::RFC6979_RNG() : is_initialized_(false) {
    initialize();
}

RFC6979_RNG::~RFC6979_RNG() {
    finalize();
}

GmpRaii RFC6979_RNG::generate(const GmpRaii& private_key,
                             const std::vector<unsigned char>& message,
                             const SecurityConstants::CurveParams& curve_params) {
    if (!is_initialized_) {
        initialize();
    }
    
    // Начало отсчета времени для обеспечения постоянного времени
    start_time_ = std::chrono::high_resolution_clock::now();
    
    // Вычисление хеша сообщения с использованием постквантового хеширования
    std::vector<unsigned char> h1 = PostQuantumHash::hash_for_rfc6979(private_key, message, curve_params);
    
    // Порядок группы (p + 1 для суперсингулярных кривых)
    GmpRaii q = curve_params.p + GmpRaii(1);
    
    // Генерация случайного числа по алгоритму RFC6979
    GmpRaii k = rfc6979_step(h1, private_key, q, "BLAKE3");
    
    // Проверка, что число безопасно
    if (!is_safe_random(k, curve_params)) {
        SecureAuditLogger::get_instance().log_event("security", "Generated random number is not safe", true);
        throw std::runtime_error("Generated random number is not safe");
    }
    
    // Обеспечение постоянного времени выполнения
    ensure_constant_time(std::chrono::microseconds(SecurityConstants::RFC6979_TIME));
    
    return k;
}

GmpRaii RFC6979_RNG::generate_for_isogeny(const GmpRaii& private_key,
                                        const std::vector<unsigned char>& message,
                                        const SecurityConstants::CurveParams& curve_params,
                                        const GmpRaii& prime) {
    if (!is_initialized_) {
        initialize();
    }
    
    // Начало отсчета времени для обеспечения постоянного времени
    start_time_ = std::chrono::high_resolution_clock::now();
    
    // Генерация случайного числа
    GmpRaii k = generate(private_key, message, curve_params);
    
    // Ограничение по простому числу
    mpz_mod(k.get_mpz_t(), k.get_mpz_t(), prime.get_mpz_t());
    
    // Обеспечение постоянного времени выполнения
    ensure_constant_time(std::chrono::microseconds(SecurityConstants::RFC6979_TIME));
    
    return k;
}

GmpRaii RFC6979_RNG::generate_with_geometric_constraints(
    const GmpRaii& private_key,
    const std::vector<unsigned char>& message,
    const SecurityConstants::CurveParams& curve_params,
    const GeometricValidator& geometric_validator,
    const std::vector<GmpRaii>& primes) {
    
    if (!is_initialized_) {
        initialize();
    }
    
    // Начало отсчета времени для обеспечения постоянного времени
    start_time_ = std::chrono::high_resolution_clock::now();
    
    // Попытки генерации безопасного случайного числа
    for (size_t i = 0; i < MAX_RETRIES; i++) {
        // Генерация случайного числа
        GmpRaii k = generate(private_key, message, curve_params);
        
        // Проверка геометрических ограничений
        if (satisfies_geometric_constraints(k, geometric_validator, primes)) {
            // Обеспечение постоянного времени выполнения
            ensure_constant_time(std::chrono::microseconds(SecurityConstants::RFC6979_TIME));
            return k;
        }
    }
    
    SecureAuditLogger::get_instance().log_event("security", "Failed to generate random number with geometric constraints", true);
    throw std::runtime_error("Failed to generate random number with geometric constraints");
}

bool RFC6979_RNG::is_safe_random(const GmpRaii& k, const SecurityConstants::CurveParams& curve_params) const {
    // Проверка, что число находится в допустимом диапазоне
    if (!is_in_range(k, curve_params.p + GmpRaii(1))) {
        return false;
    }
    
    // Проверка, что число не является слабым
    if (is_weak_value(k)) {
        return false;
    }
    
    return true;
}

bool RFC6979_RNG::is_weak_value(const GmpRaii& k) const {
    // Проверка на наличие слабых значений
    // Слабые значения включают:
    // 1. Значения, близкие к 0 или к порядку группы
    // 2. Значения с регулярными битовыми паттернами
    // 3. Значения, которые могут привести к вырожденной структуре графа
    
    // Проверка близости к 0
    if (k < GmpRaii(100)) {
        return true;
    }
    
    // Проверка близости к порядку группы
    // В реальной системе здесь будет проверка с использованием порядка группы
    // Для упрощения используем эвристику
    GmpRaii close_to_q = GmpRaii(100);
    if (k > GmpRaii(1000000) - close_to_q) {
        return true;
    }
    
    // Проверка на регулярные битовые паттерны
    mpz_t k_mpz;
    mpz_init_set(k_mpz, k.get_mpz_t());
    
    size_t bit_length = mpz_sizeinbase(k_mpz, 2);
    size_t consecutive_zeros = 0;
    size_t consecutive_ones = 0;
    size_t max_consecutive_zeros = 0;
    size_t max_consecutive_ones = 0;
    
    for (size_t i = 0; i < bit_length; i++) {
        if (mpz_tstbit(k_mpz, i)) {
            consecutive_ones++;
            consecutive_zeros = 0;
            max_consecutive_ones = std::max(max_consecutive_ones, consecutive_ones);
        } else {
            consecutive_zeros++;
            consecutive_ones = 0;
            max_consecutive_zeros = std::max(max_consecutive_zeros, consecutive_zeros);
        }
    }
    
    mpz_clear(k_mpz);
    
    // Если есть длинные последовательности нулей или единиц, значение может быть слабым
    const size_t max_allowed_consecutive = bit_length / 10;
    if (max_consecutive_zeros > max_allowed_consecutive || max_consecutive_ones > max_allowed_consecutive) {
        return true;
    }
    
    return false;
}

bool RFC6979_RNG::satisfies_geometric_constraints(
    const GmpRaii& k,
    const GeometricValidator& geometric_validator,
    const std::vector<GmpRaii>& primes) const {
    
    // Преобразование числа k в ключевую структуру
    std::vector<short> key;
    mpz_t k_mpz;
    mpz_init_set(k_mpz, k.get_mpz_t());
    
    // Определение размера ключа
    size_t key_size = std::min(primes.size(), static_cast<size_t>(mpz_sizeinbase(k_mpz, 2)));
    
    // Заполнение ключа
    key.resize(key_size, 0);
    for (size_t i = 0; i < key_size; i++) {
        // Извлечение i-го бита и преобразование в значение от -1 до 1
        // В реальной системе здесь будет более сложная логика
        if (mpz_tstbit(k_mpz, i)) {
            key[i] = (i % 2 == 0) ? 1 : -1;
        }
    }
    
    mpz_clear(k_mpz);
    
    // Проверка, что ключ проходит геометрическую проверку
    // Для этого создаем кривую из ключа и проверяем ее свойства
    
    // В реальной системе здесь будет построение кривой и проверка через geometric_validator
    // Для упрощения возвращаем true, если ключ не имеет длинных регулярных паттернов
    
    // Проверка на длинные регулярные паттерны
    size_t min_pattern_length = 4;
    for (size_t i = 0; i < key.size() - min_pattern_length + 1; i++) {
        bool is_constant = true;
        for (size_t j = 1; j < min_pattern_length; j++) {
            if (key[i] != key[i + j]) {
                is_constant = false;
                break;
            }
        }
        if (is_constant) {
            return false;
        }
    }
    
    return true;
}

std::vector<unsigned char> RFC6979_RNG::generate_salt() {
    return SecureRandom::generate_random_bytes(SALT_SIZE);
}

GmpRaii RFC6979_RNG::generate_constant_time(
    const GmpRaii& private_key,
    const std::vector<unsigned char>& message,
    const SecurityConstants::CurveParams& curve_params,
    const std::chrono::microseconds& target_time) {
    
    if (!is_initialized_) {
        initialize();
    }
    
    // Начало отсчета времени для обеспечения постоянного времени
    start_time_ = std::chrono::high_resolution_clock::now();
    
    // Генерация случайного числа
    GmpRaii k = generate(private_key, message, curve_params);
    
    // Обеспечение постоянного времени выполнения
    ensure_constant_time(target_time);
    
    return k;
}

bool RFC6979_RNG::verify_integrity() const {
    if (!is_initialized_) {
        return false;
    }
    
    try {
        // Создаем тестовые данные
        GmpRaii private_key = SecureRandom::generate_random_mpz(GmpRaii(1000000));
        std::vector<unsigned char> message = SecureRandom::generate_random_bytes(32);
        SecurityConstants::CurveParams curve_params;
        curve_params.p = GmpRaii(1000003); // Простое число для теста
        
        // Генерируем случайное число дважды с теми же входными данными
        GmpRaii k1 = generate(private_key, message, curve_params);
        GmpRaii k2 = generate(private_key, message, curve_params);
        
        // Проверяем детерминированность
        if (k1 != k2) {
            SecureAuditLogger::get_instance().log_event("security", "RFC6979 RNG is not deterministic", true);
            return false;
        }
        
        // Проверяем, что число в допустимом диапазоне
        GmpRaii q = curve_params.p + GmpRaii(1);
        if (!is_in_range(k1, q)) {
            SecureAuditLogger::get_instance().log_event("security", "RFC6979 RNG generated value out of range", true);
            return false;
        }
        
        // Проверяем, что число не является слабым
        if (is_weak_value(k1)) {
            SecureAuditLogger::get_instance().log_event("security", "RFC6979 RNG generated weak value", true);
            return false;
        }
        
        return true;
    } catch (const std::exception& e) {
        SecureAuditLogger::get_instance().log_event("security", "RFC6979 RNG integrity check failed: " + std::string(e.what()), true);
        return false;
    }
}

bool RFC6979_RNG::is_ready() const {
    return is_initialized_ && verify_integrity();
}

void RFC6979_RNG::initialize() {
    if (is_initialized_) {
        return;
    }
    
    // Инициализация libsodium
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
    
    is_initialized_ = true;
    
    SecureAuditLogger::get_instance().log_event("system", "RFC6979_RNG initialized", false);
}

void RFC6979_RNG::finalize() {
    if (!is_initialized_) {
        return;
    }
    
    is_initialized_ = false;
    
    SecureAuditLogger::get_instance().log_event("system", "RFC6979_RNG finalized", false);
}

std::vector<unsigned char> RFC6979_RNG::get_state() const {
    if (!is_initialized_) {
        throw std::runtime_error("RFC6979_RNG is not initialized");
    }
    
    // В реальной системе здесь будет сериализация состояния генератора
    // Для демонстрации возвращаем случайные данные
    
    return SecureRandom::generate_random_bytes(64);
}

void RFC6979_RNG::restore_state(const std::vector<unsigned char>& state) {
    if (!is_initialized_) {
        initialize();
    }
    
    // В реальной системе здесь будет десериализация состояния генератора
    // Для демонстрации ничего не делаем
    
    SecureAuditLogger::get_instance().log_event("system", "RFC6979_RNG state restored", false);
}

GmpRaii RFC6979_RNG::rfc6979_step(const std::vector<unsigned char>& h1,
                                const GmpRaii& x,
                                const GmpRaii& q,
                                const std::string& alg) const {
    std::vector<unsigned char> V;
    std::vector<unsigned char> K;
    
    // Вычисление V и K
    compute_v_k(h1, x, q, alg, V, K);
    
    // Генерация случайного числа из V и K
    return generate_from_v_k(V, K, h1, x, q);
}

void RFC6979_RNG::compute_v_k(const std::vector<unsigned char>& h1,
                            const GmpRaii& x,
                            const GmpRaii& q,
                            const std::string& alg,
                            std::vector<unsigned char>& V,
                            std::vector<unsigned char>& K) const {
    // Инициализация HMAC ключа
    K.resize(HMAC_KEY_SIZE);
    std::fill(K.begin(), K.end(), 0x00);
    
    // Инициализация V
    V.resize(SecurityConstants::HASH_SIZE);
    std::fill(V.begin(), V.end(), 0x01);
    
    // Шаг 1: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    std::vector<unsigned char> t;
    t.push_back(0x00);
    
    // Добавляем приватный ключ
    std::vector<unsigned char> x_bytes;
    size_t count;
    mpz_export(nullptr, &count, 1, 1, 1, 0, x.get_mpz_t());
    x_bytes.resize(count);
    mpz_export(x_bytes.data(), nullptr, 1, 1, 1, 0, x.get_mpz_t());
    t.insert(t.end(), x_bytes.begin(), x_bytes.end());
    
    // Добавляем хеш сообщения
    t.insert(t.end(), h1.begin(), h1.end());
    
    // Вычисляем HMAC
    std::vector<unsigned char> k_step = compute_hmac(V, t, alg);
    std::copy(k_step.begin(), k_step.end(), K.begin());
    
    // Шаг 2: V = HMAC_K(V)
    std::vector<unsigned char> v_step = compute_hmac(K, V, alg);
    std::copy(v_step.begin(), v_step.end(), V.begin());
    
    // Шаг 3: K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    t.clear();
    t.push_back(0x01);
    t.insert(t.end(), x_bytes.begin(), x_bytes.end());
    t.insert(t.end(), h1.begin(), h1.end());
    
    k_step = compute_hmac(V, t, alg);
    std::copy(k_step.begin(), k_step.end(), K.begin());
    
    // Шаг 4: V = HMAC_K(V)
    v_step = compute_hmac(K, V, alg);
    std::copy(v_step.begin(), v_step.end(), V.begin());
}

GmpRaii RFC6979_RNG::generate_from_v_k(const std::vector<unsigned char>& V,
                                     const std::vector<unsigned char>& K,
                                     const std::vector<unsigned char>& h1,
                                     const GmpRaii& x,
                                     const GmpRaii& q) const {
    size_t hash_size = SecurityConstants::HASH_SIZE;
    size_t num_iterations = 0;
    
    while (true) {
        num_iterations++;
        if (num_iterations > MAX_RETRIES) {
            throw std::runtime_error("RFC6979_RNG: Maximum iterations reached");
        }
        
        std::vector<unsigned char> t;
        
        // Повторяем V несколько раз, чтобы покрыть необходимую длину
        size_t num_repeats = (mpz_sizeinbase(q.get_mpz_t(), 2) + 7) / (hash_size * 8) + 1;
        for (size_t i = 0; i < num_repeats; i++) {
            t.insert(t.end(), V.begin(), V.end());
            
            // V = HMAC_K(V)
            std::vector<unsigned char> new_V = compute_hmac(K, V, "BLAKE3");
            std::copy(new_V.begin(), new_V.end(), V.begin());
        }
        
        // Конвертация t в целое число
        GmpRaii k;
        mpz_import(k.get_mpz_t(), t.size(), 1, 1, 1, 0, t.data());
        
        // Проверка, что k в допустимом диапазоне
        if (is_in_range(k, q) && is_not_weak(k)) {
            return k;
        }
        
        // Подготовка к следующей итерации
        std::vector<unsigned char> t2;
        t2.push_back(0x00);
        
        // Добавляем k
        std::vector<unsigned char> k_bytes;
        size_t count;
        mpz_export(nullptr, &count, 1, 1, 1, 0, k.get_mpz_t());
        k_bytes.resize(count);
        mpz_export(k_bytes.data(), nullptr, 1, 1, 1, 0, k.get_mpz_t());
        t2.insert(t2.end(), k_bytes.begin(), k_bytes.end());
        
        // Обновление K и V
        std::vector<unsigned char> new_K = compute_hmac(K, t2, "BLAKE3");
        std::copy(new_K.begin(), new_K.end(), K.begin());
        
        std::vector<unsigned char> new_V = compute_hmac(K, V, "BLAKE3");
        std::copy(new_V.begin(), new_V.end(), V.begin());
    }
}

bool RFC6979_RNG::is_in_range(const GmpRaii& k, const GmpRaii& q) const {
    return k > GmpRaii(0) && k < q;
}

bool RFC6979_RNG::is_not_weak(const GmpRaii& k) const {
    return !is_weak_value(k);
}

std::vector<unsigned char> RFC6979_RNG::compute_hmac(const std::vector<unsigned char>& K,
                                                   const std::vector<unsigned char>& T,
                                                   const std::string& alg) const {
    // Вычисление HMAC с использованием BLAKE3
    blake3_hasher hasher;
    blake3_keyed_hasher keyed_hasher;
    
    // Инициализация ключевого хеширования
    blake3_keyed_hasher_init(&keyed_hasher, K.data());
    
    // Обновление хеша данными
    blake3_keyed_hasher_update(&keyed_hasher, T.data(), T.size());
    
    // Финализация и получение HMAC
    std::vector<unsigned char> mac(SecurityConstants::HASH_SIZE);
    blake3_keyed_hasher_finalize(&keyed_hasher, mac.data(), mac.size());
    
    return mac;
}

void RFC6979_RNG::init_hmac_key(std::vector<unsigned char>& K, const std::string& alg) const {
    // Инициализация HMAC ключа
    K.resize(HMAC_KEY_SIZE);
    std::fill(K.begin(), K.end(), 0x00);
}

void RFC6979_RNG::hmac_step(std::vector<unsigned char>& K,
                          std::vector<unsigned char>& V,
                          const std::string& alg,
                          const std::vector<unsigned char>& h1,
                          const GmpRaii& x,
                          unsigned char t) const {
    // Подготовка данных для HMAC
    std::vector<unsigned char> data;
    data.push_back(t);
    
    // Добавляем приватный ключ
    std::vector<unsigned char> x_bytes;
    size_t count;
    mpz_export(nullptr, &count, 1, 1, 1, 0, x.get_mpz_t());
    x_bytes.resize(count);
    mpz_export(x_bytes.data(), nullptr, 1, 1, 1, 0, x.get_mpz_t());
    data.insert(data.end(), x_bytes.begin(), x_bytes.end());
    
    // Добавляем хеш сообщения
    data.insert(data.end(), h1.begin(), h1.end());
    
    // Вычисляем HMAC
    std::vector<unsigned char> k_step = compute_hmac(K, data, alg);
    std::copy(k_step.begin(), k_step.end(), K.begin());
    
    // Обновляем V
    std::vector<unsigned char> v_step = compute_hmac(K, V, alg);
    std::copy(v_step.begin(), v_step.end(), V.begin());
}

void RFC6979_RNG::ensure_constant_time(const std::chrono::microseconds& target_time) const {
    auto elapsed = std::chrono::high_resolution_clock::now() - start_time_;
    
    // Используем более надежный метод для обеспечения постоянного времени
    if (elapsed < target_time) {
        auto remaining = target_time - std::chrono::duration_cast<std::chrono::microseconds>(elapsed);
        
        // Добавляем небольшую случайную задержку для защиты от анализа времени
        auto jitter = std::chrono::microseconds(SecureRandom::generate_random_mpz(GmpRaii(50)).get_ui());
        auto adjusted_remaining = remaining + jitter;
        
        // Требуемое количество итераций для задержки
        const size_t iterations = adjusted_remaining.count() * 100;
        
        // Используем сложный вычислительный цикл для задержки
        volatile uint64_t dummy = 0;
        for (size_t i = 0; i < iterations; i++) {
            dummy += i * (i ^ 0x55AA) + dummy % 1000;
            dummy = (dummy >> 31) | (dummy << 1);
        }
    }
}

} // namespace toruscsidh
