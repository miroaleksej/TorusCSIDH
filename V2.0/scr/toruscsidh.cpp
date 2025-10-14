#include "toruscsidh.h"
#include <iostream>
#include <chrono>
#include <stdexcept>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <sodium.h>
#include "secure_random.h"
#include "security_constants.h"
#include "secure_audit_logger.h"
#include "geometric_validator.h"
#include "postquantum_hash.h"
#include "bech32m.h"
#include "rfc6979_rng.h"

namespace toruscsidh {

TorusCSIDH::TorusCSIDH(SecurityConstants::SecurityLevel security_level)
    : security_level_(security_level),
      geometric_validator(static_cast<int>(security_level)),
      base_curve(SecurityConstants::get_base_curve(security_level)) {
    
    // Инициализация системы
    initialize();
}

TorusCSIDH::~TorusCSIDH() {
    // Очистка секретных данных из памяти
    SecureRandom::secure_clean_memory(private_key.data(), private_key.size() * sizeof(short));
}

void TorusCSIDH::initialize() {
    // Проверка целостности системы
    if (!code_integrity.system_integrity_check()) {
        throw std::runtime_error("System integrity check failed during initialization");
    }
    
    // Инициализация параметров безопасности
    initialize_security_params();
    
    // Проверка базовых параметров
    if (!validate_base_parameters()) {
        throw std::runtime_error("Base parameters validation failed");
    }
    
    // Генерация ключевой пары
    generate_key_pair();
    
    // Проверка сгенерированного ключа
    if (!is_secure_key()) {
        throw std::runtime_error("Generated key is not secure");
    }
    
    SecureAuditLogger::get_instance().log_event("system", "TorusCSIDH initialized successfully", false);
}

void TorusCSIDH::generate_key_pair() {
    // Генерация приватного ключа
    private_key = SecureRandom::generate_csidh_key(security_level_, params);
    
    // Начальная кривая
    MontgomeryCurve current_curve = base_curve;
    
    // Применение изогений в соответствии с приватным ключом
    for (size_t i = 0; i < params.primes.size(); i++) {
        int exponent = private_key[i];
        
        if (exponent != 0) {
            unsigned int order = static_cast<unsigned int>(mpz_get_ui(params.primes[i].get_mpz_t()));
            EllipticCurvePoint kernel_point = current_curve.find_point_of_order(order);
            
            // Применение изогении |exponent| раз
            for (int j = 0; j < std::abs(exponent); j++) {
                current_curve = current_curve.compute_isogeny(kernel_point, order);
                
                // Для отрицательных экспонент используем обратную изогению
                if (exponent < 0) {
                    kernel_point = kernel_point.scalar_multiply(GmpRaii(order - 1), current_curve);
                }
            }
        }
    }
    
    // Установка публичной кривой
    public_curve = current_curve;
    
    SecureAuditLogger::get_instance().log_event("key", "Key pair generated successfully", false);
}

std::vector<unsigned char> TorusCSIDH::sign(const std::vector<unsigned char>& message) {
    // Проверка целостности системы перед подписью
    if (!code_integrity.system_integrity_check()) {
        throw std::runtime_error("System integrity check failed before signing");
    }
    
    // Начало отсчета времени для обеспечения постоянного времени
    start_time = std::chrono::high_resolution_clock::now();
    
    // Генерация эфемерного ключа
    std::vector<short> ephemeral_key = SecureRandom::generate_ephemeral_key(security_level_, params);
    
    // Вычисление эфемерной кривой
    MontgomeryCurve ephemeral_curve = base_curve;
    for (size_t i = 0; i < params.primes.size(); i++) {
        int exponent = ephemeral_key[i];
        
        if (exponent != 0) {
            unsigned int order = static_cast<unsigned int>(mpz_get_ui(params.primes[i].get_mpz_t()));
            EllipticCurvePoint kernel_point = ephemeral_curve.find_point_of_order(order);
            
            // Применение изогении |exponent| раз
            for (int j = 0; j < std::abs(exponent); j++) {
                ephemeral_curve = ephemeral_curve.compute_isogeny(kernel_point, order);
                
                // Для отрицательных экспонент используем обратную изогению
                if (exponent < 0) {
                    kernel_point = kernel_point.scalar_multiply(GmpRaii(order - 1), ephemeral_curve);
                }
            }
        }
    }
    
    // Геометрическая проверка эфемерной кривой
    if (!validate_geometric_properties(ephemeral_curve)) {
        throw std::runtime_error("Ephemeral curve failed geometric validation");
    }
    
    // Вычисление общего секрета: [d_A]E_eph
    MontgomeryCurve shared_secret_curve = ephemeral_curve;
    for (size_t i = 0; i < params.primes.size(); i++) {
        int exponent = private_key[i];
        
        if (exponent != 0) {
            unsigned int order = static_cast<unsigned int>(mpz_get_ui(params.primes[i].get_mpz_t()));
            EllipticCurvePoint kernel_point = shared_secret_curve.find_point_of_order(order);
            
            // Применение изогении |exponent| раз
            for (int j = 0; j < std::abs(exponent); j++) {
                shared_secret_curve = shared_secret_curve.compute_isogeny(kernel_point, order);
                
                // Для отрицательных экспонент используем обратную изогению
                if (exponent < 0) {
                    kernel_point = kernel_point.scalar_multiply(GmpRaii(order - 1), shared_secret_curve);
                }
            }
        }
    }
    
    // Вычисление j-инварианта общего секрета
    GmpRaii j_invariant = shared_secret_curve.compute_j_invariant();
    
    // Хеширование сообщения и j-инварианта
    std::vector<unsigned char> message_hash = PostQuantumHash::hash(message);
    std::vector<unsigned char> j_bytes;
    mpz_export(j_bytes.data(), nullptr, 1, 1, 1, 0, j_invariant.get_mpz_t());
    
    // Добавляем j-инвариант к хешу сообщения
    message_hash.insert(message_hash.end(), j_bytes.begin(), j_bytes.end());
    
    // Хеширование для получения финальной подписи
    std::vector<unsigned char> signature = PostQuantumHash::hash(message_hash);
    
    // Добавляем эфемерную кривую к подписи
    std::vector<unsigned char> ephemeral_curve_bytes;
    mpz_export(ephemeral_curve_bytes.data(), nullptr, 1, 1, 1, 0, ephemeral_curve.compute_j_invariant().get_mpz_t());
    
    signature.insert(signature.end(), ephemeral_curve_bytes.begin(), ephemeral_curve_bytes.end());
    
    // Обеспечение постоянного времени выполнения
    ensure_constant_time(std::chrono::microseconds(SecurityConstants::SIGNING_TIME));
    
    SecureAuditLogger::get_instance().log_event("signature", "Message signed successfully", false);
    
    return signature;
}

bool TorusCSIDH::verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature) {
    // Проверка целостности системы перед верификацией
    if (!code_integrity.system_integrity_check()) {
        SecureAuditLogger::get_instance().log_event("security", "System integrity check failed during verification", true);
        return false;
    }
    
    // Начало отсчета времени для обеспечения постоянного времени
    start_time = std::chrono::high_resolution_clock::now();
    
    // Проверка размера подписи
    if (signature.size() < SecurityConstants::MIN_SIGNATURE_SIZE) {
        SecureAuditLogger::get_instance().log_event("security", "Invalid signature size", true);
        return false;
    }
    
    // Извлечение хеша подписи и эфемерной кривой
    size_t hash_size = SecurityConstants::HASH_SIZE;
    std::vector<unsigned char> signature_hash(signature.begin(), signature.begin() + hash_size);
    std::vector<unsigned char> ephemeral_curve_bytes(signature.begin() + hash_size, signature.end());
    
    // Восстановление j-инварианта эфемерной кривой
    GmpRaii ephemeral_j;
    mpz_import(ephemeral_j.get_mpz_t(), ephemeral_curve_bytes.size(), 1, 1, 1, 0, ephemeral_curve_bytes.data());
    
    // Создание эфемерной кривой
    MontgomeryCurve ephemeral_curve = base_curve;
    
    // Геометрическая проверка эфемерной кривой
    if (!validate_geometric_properties(ephemeral_curve)) {
        SecureAuditLogger::get_instance().log_event("security", "Ephemeral curve failed geometric validation during verification", true);
        return false;
    }
    
    // Вычисление общего секрета: [d_B]E_eph
    MontgomeryCurve shared_secret_curve = ephemeral_curve;
    for (size_t i = 0; i < params.primes.size(); i++) {
        int exponent = private_key[i];
        
        if (exponent != 0) {
            unsigned int order = static_cast<unsigned int>(mpz_get_ui(params.primes[i].get_mpz_t()));
            EllipticCurvePoint kernel_point = shared_secret_curve.find_point_of_order(order);
            
            // Применение изогении |exponent| раз
            for (int j = 0; j < std::abs(exponent); j++) {
                shared_secret_curve = shared_secret_curve.compute_isogeny(kernel_point, order);
                
                // Для отрицательных экспонент используем обратную изогению
                if (exponent < 0) {
                    kernel_point = kernel_point.scalar_multiply(GmpRaii(order - 1), shared_secret_curve);
                }
            }
        }
    }
    
    // Вычисление j-инварианта общего секрета
    GmpRaii j_invariant = shared_secret_curve.compute_j_invariant();
    
    // Хеширование сообщения и j-инварианта
    std::vector<unsigned char> message_hash = PostQuantumHash::hash(message);
    std::vector<unsigned char> j_bytes;
    mpz_export(j_bytes.data(), nullptr, 1, 1, 1, 0, j_invariant.get_mpz_t());
    
    // Добавляем j-инвариант к хешу сообщения
    message_hash.insert(message_hash.end(), j_bytes.begin(), j_bytes.end());
    
    // Хеширование для получения финальной подписи
    std::vector<unsigned char> computed_signature = PostQuantumHash::hash(message_hash);
    
    // Постоянное время сравнение
    bool signature_valid = true;
    for (size_t i = 0; i < hash_size; i++) {
        signature_valid &= (signature_hash[i] == computed_signature[i]);
    }
    
    // Обеспечение постоянного времени выполнения
    ensure_constant_time(std::chrono::microseconds(SecurityConstants::VERIFICATION_TIME));
    
    if (signature_valid) {
        SecureAuditLogger::get_instance().log_event("signature", "Signature verified successfully", false);
    } else {
        SecureAuditLogger::get_instance().log_event("security", "Signature verification failed", true);
    }
    
    return signature_valid;
}

std::string TorusCSIDH::generate_address() {
    // Получение j-инварианта публичной кривой
    GmpRaii j_invariant = public_curve.compute_j_invariant();
    
    // Конвертация j-инварианта в байты
    std::vector<unsigned char> j_bytes;
    size_t count;
    mpz_export(nullptr, &count, 1, 1, 1, 0, j_invariant.get_mpz_t());
    j_bytes.resize(count);
    mpz_export(j_bytes.data(), nullptr, 1, 1, 1, 0, j_invariant.get_mpz_t());
    
    // Генерация адреса в формате Bech32m
    return Bech32m::encode("tcidh", j_bytes);
}

void TorusCSIDH::print_info() const {
    std::cout << "TorusCSIDH System Information:" << std::endl;
    std::cout << "  Security Level: " << static_cast<int>(security_level_) << " bits" << std::endl;
    std::cout << "  Base Curve: j-invariant = " << base_curve.compute_j_invariant() << std::endl;
    std::cout << "  Public Curve: j-invariant = " << public_curve.compute_j_invariant() << std::endl;
    std::cout << "  Prime Count: " << params.primes.size() << std::endl;
    std::cout << "  Max Linf: " << SecurityConstants::get_max_linf(security_level_) << std::endl;
    std::cout << "  Max L1: " << SecurityConstants::get_max_l1(security_level_) << std::endl;
    std::cout << "  Geometric Radius: " << GEOMETRIC_RADIUS << std::endl;
    
    // Проверка ключа
    std::cout << "  Key Status: " << (is_secure_key() ? "SECURE" : "INSECURE") << std::endl;
    if (!is_small_key()) {
        std::cout << "    - Key is not small" << std::endl;
    }
    if (is_weak_key()) {
        std::cout << "    - Key has weak patterns" << std::endl;
    }
    if (is_vulnerable_to_long_path_attack()) {
        std::cout << "    - Key is vulnerable to long path attack" << std::endl;
    }
    if (is_vulnerable_to_degenerate_topology_attack()) {
        std::cout << "    - Key is vulnerable to degenerate topology attack" << std::endl;
    }
}

bool TorusCSIDH::is_system_ready() const {
    return code_integrity.is_system_ready() && is_secure_key();
}

const MontgomeryCurve& TorusCSIDH::get_public_curve() const {
    return public_curve;
}

const std::vector<short>& TorusCSIDH::get_private_key() const {
    return private_key;
}

const CodeIntegrityProtection& TorusCSIDH::get_code_integrity() const {
    return code_integrity;
}

const GeometricValidator& TorusCSIDH::get_geometric_validator() const {
    return geometric_validator;
}

bool TorusCSIDH::is_small_key() const {
    // Проверка нормы L∞ (максимальное значение коэффициентов)
    int max_abs = 0;
    for (const auto& val : private_key) {
        if (std::abs(val) > max_abs) {
            max_abs = std::abs(val);
        }
    }
    
    // Проверка нормы L1 (сумма абсолютных значений)
    int sum_abs = 0;
    for (const auto& val : private_key) {
        sum_abs += std::abs(val);
    }
    
    // Проверяем оба критерия в зависимости от уровня безопасности
    int max_Linf = SecurityConstants::get_max_linf(security_level_);
    int max_L1 = SecurityConstants::get_max_l1(security_level_);
    
    return (max_abs <= max_Linf) && (sum_abs <= max_L1);
}

bool TorusCSIDH::is_weak_key() const {
    // Проверка на наличие регулярных паттернов в ключе
    // Основано на исследованиях атак через вырожденную топологию
    const size_t min_pattern_length = SecurityConstants::MIN_KEY_PATTERN_LEN;
    
    // Проверка на постоянные последовательности
    for (size_t i = 0; i < private_key.size() - min_pattern_length + 1; i++) {
        bool is_constant = true;
        for (size_t j = 1; j < min_pattern_length; j++) {
            if (private_key[i] != private_key[i + j]) {
                is_constant = false;
                break;
            }
        }
        if (is_constant) {
            return true;
        }
    }
    
    // Проверка на арифметические прогрессии
    for (size_t i = 0; i < private_key.size() - min_pattern_length + 1; i++) {
        if (private_key.size() - i < min_pattern_length) break;
        
        int diff = private_key[i + 1] - private_key[i];
        bool is_arithmetic = true;
        for (size_t j = 2; j < min_pattern_length; j++) {
            if (private_key[i + j] - private_key[i + j - 1] != diff) {
                is_arithmetic = false;
                break;
            }
        }
        if (is_arithmetic) {
            return true;
        }
    }
    
    // Проверка на геометрические прогрессии
    for (size_t i = 0; i < private_key.size() - min_pattern_length + 1; i++) {
        if (private_key.size() - i < min_pattern_length) break;
        
        if (private_key[i] == 0 || private_key[i + 1] == 0) continue;
        
        double ratio = static_cast<double>(private_key[i + 1]) / private_key[i];
        bool is_geometric = true;
        for (size_t j = 2; j < min_pattern_length; j++) {
            if (private_key[i + j - 1] == 0) {
                is_geometric = false;
                break;
            }
            
            double current_ratio = static_cast<double>(private_key[i + j]) / private_key[i + j - 1];
            if (std::abs(current_ratio - ratio) > 0.001) {
                is_geometric = false;
                break;
            }
        }
        if (is_geometric) {
            return true;
        }
    }
    
    return false;
}

bool TorusCSIDH::is_secure_key() const {
    // Проверка, что ключ соответствует всем критериям безопасности
    return is_small_key() && 
           !is_weak_key() && 
           !is_vulnerable_to_long_path_attack() && 
           !is_vulnerable_to_degenerate_topology_attack();
}

bool TorusCSIDH::is_vulnerable_to_long_path_attack() const {
    // Проверка уязвимости к атаке через длинный путь
    // В атаке через длинный путь злоумышленник использует кривые,
    // где последовательность изогений одного типа слишком длинная
    
    int max_consecutive_same_sign = 0;
    int current_consecutive = 0;
    int last_sign = 0;
    
    for (const auto& val : private_key) {
        int sign = (val > 0) ? 1 : (val < 0) ? -1 : 0;
        
        if (sign == last_sign && sign != 0) {
            current_consecutive++;
        } else {
            max_consecutive_same_sign = std::max(max_consecutive_same_sign, current_consecutive);
            current_consecutive = (sign != 0) ? 1 : 0;
            last_sign = sign;
        }
    }
    
    max_consecutive_same_sign = std::max(max_consecutive_same_sign, current_consecutive);
    
    // Порог для уязвимости зависит от уровня безопасности
    int vulnerability_threshold;
    switch (security_level_) {
        case SecurityConstants::SecurityLevel::LEVEL_128:
            vulnerability_threshold = SecurityConstants::MAX_CONSECUTIVE_128;
            break;
        case SecurityConstants::SecurityLevel::LEVEL_192:
            vulnerability_threshold = SecurityConstants::MAX_CONSECUTIVE_192;
            break;
        case SecurityConstants::SecurityLevel::LEVEL_256:
            vulnerability_threshold = SecurityConstants::MAX_CONSECUTIVE_256;
            break;
        default:
            vulnerability_threshold = SecurityConstants::MAX_CONSECUTIVE_128;
    }
    
    return max_consecutive_same_sign > vulnerability_threshold;
}

bool TorusCSIDH::is_vulnerable_to_degenerate_topology_attack() const {
    // Проверка уязвимости к атаке через вырожденную топологию
    // Такая атака использует кривые с неестественной структурой графа изогений
    
    // Создаем кривую из ключа
    MontgomeryCurve test_curve = base_curve;
    for (size_t i = 0; i < params.primes.size(); i++) {
        int exponent = private_key[i];
        
        if (exponent != 0) {
            unsigned int order = static_cast<unsigned int>(mpz_get_ui(params.primes[i].get_mpz_t()));
            EllipticCurvePoint kernel_point = test_curve.find_point_of_order(order);
            
            // Применение изогении |exponent| раз
            for (int j = 0; j < std::abs(exponent); j++) {
                test_curve = test_curve.compute_isogeny(kernel_point, order);
                
                // Для отрицательных экспонент используем обратную изогению
                if (exponent < 0) {
                    kernel_point = kernel_point.scalar_multiply(GmpRaii(order - 1), test_curve);
                }
            }
        }
    }
    
    // Проверяем геометрические свойства полученной кривой
    return !validate_geometric_properties(test_curve);
}

void TorusCSIDH::ensure_constant_time(const std::chrono::microseconds& target_time) {
    auto elapsed = std::chrono::high_resolution_clock::now() - start_time;
    
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

bool TorusCSIDH::is_curve_in_isogeny_graph(const MontgomeryCurve& curve) const {
    // Проверка, что кривая действительно принадлежит графу изогений
    // 1. Проверка, что j-инварианты связаны модулярными уравнениями для данного набора простых чисел
    GmpRaii base_j = base_curve.compute_j_invariant();
    GmpRaii curve_j = curve.compute_j_invariant();
    GmpRaii p = base_curve.get_p();
    
    // 2. Проверка, что кривые имеют одинаковый порядок
    GmpRaii base_order = base_curve.compute_order();
    GmpRaii curve_order = curve.compute_order();
    if (base_order != curve_order) {
        return false;
    }
    
    // 3. Проверка, что кривые суперсингулярны
    if (!base_curve.is_supersingular() || !curve.is_supersingular()) {
        return false;
    }
    
    // 4. Проверка модулярных уравнений для всех простых в наборе
    bool connected = false;
    for (const auto& prime : params.primes) {
        unsigned long degree = mpz_get_ui(prime.get_mpz_t());
        
        // Проверяем, связаны ли кривые изогенией этой степени
        if (geometric_validator.verify_modular_connection(base_curve, curve, prime)) {
            connected = true;
            break;
        }
    }
    
    return connected;
}

bool TorusCSIDH::validate_geometric_properties(const MontgomeryCurve& curve) const {
    // Вычисляем подграф изогений радиуса GEOMETRIC_RADIUS вокруг кривой
    GeometricValidator::Graph subgraph = build_isogeny_graph(curve, GEOMETRIC_RADIUS);
    
    // Проверка всех семи геометрических критериев
    double cyclomatic_score, spectral_gap_score, clustering_score, degree_entropy_score, distance_score;
    
    bool cyclomatic_valid = geometric_validator.check_cyclomatic_number(curve, params.primes, GEOMETRIC_RADIUS);
    bool spectral_valid = geometric_validator.check_spectral_gap(curve, params.primes, GEOMETRIC_RADIUS);
    bool connectivity_valid = geometric_validator.check_local_connectivity(curve, params.primes, GEOMETRIC_RADIUS);
    bool long_paths_valid = geometric_validator.check_long_paths(curve, params.primes, GEOMETRIC_RADIUS + 1);
    bool degenerate_valid = geometric_validator.check_degenerate_topology(curve, params.primes, GEOMETRIC_RADIUS);
    bool symmetry_valid = geometric_validator.check_graph_symmetry(curve, params.primes, GEOMETRIC_RADIUS);
    bool metric_valid = geometric_validator.check_metric_consistency(curve, params.primes, GEOMETRIC_RADIUS + 1);
    
    // Вычисляем общий балл безопасности
    double total_score = 0.20 * (cyclomatic_valid ? 1.0 : 0.0) + 
                         0.20 * (spectral_valid ? 1.0 : 0.0) + 
                         0.15 * (connectivity_valid ? 1.0 : 0.0) + 
                         0.10 * (long_paths_valid ? 1.0 : 0.0) + 
                         0.10 * (degenerate_valid ? 1.0 : 0.0) + 
                         0.15 * (symmetry_valid ? 1.0 : 0.0) + 
                         0.10 * (metric_valid ? 1.0 : 0.0);
    
    // Проверка, что кривая действительно принадлежит графу изогений
    bool in_isogeny_graph = is_curve_in_isogeny_graph(curve);
    
    // Логирование результатов для диагностики
    std::cout << "Геометрическая проверка: " 
              << (total_score >= 0.85 && in_isogeny_graph ? "УСПЕШНА" : "НЕУДАЧНА") << std::endl;
    std::cout << "  Цикломатическое число: " << (cyclomatic_valid ? "OK" : "FAIL") << std::endl;
    std::cout << "  Спектральный зазор: " << (spectral_valid ? "OK" : "FAIL") << std::endl;
    std::cout << "  Локальная связность: " << (connectivity_valid ? "OK" : "FAIL") << std::endl;
    std::cout << "  Длинные пути: " << (long_paths_valid ? "OK" : "FAIL") << std::endl;
    std::cout << "  Вырожденная топология: " << (degenerate_valid ? "OK" : "FAIL") << std::endl;
    std::cout << "  Симметрия графа: " << (symmetry_valid ? "OK" : "FAIL") << std::endl;
    std::cout << "  Метрическая согласованность: " << (metric_valid ? "OK" : "FAIL") << std::endl;
    std::cout << "  Принадлежность графу изогений: " << (in_isogeny_graph ? "OK" : "FAIL") << std::endl;
    std::cout << "  Общий балл: " << total_score * 100.0 << "%" << std::endl;
    
    return (total_score >= 0.85) && in_isogeny_graph;
}

const SecurityConstants::CSIDHParams& TorusCSIDH::get_security_params() const {
    return params;
}

const std::vector<GmpRaii>& TorusCSIDH::get_primes() const {
    return params.primes;
}

void TorusCSIDH::initialize_security_params() {
    // Инициализация параметров безопасности в зависимости от уровня
    params = SecurityConstants::get_csidh_params(security_level_);
}

bool TorusCSIDH::validate_base_parameters() const {
    // Проверка, что базовая кривая суперсингулярна
    if (!base_curve.is_supersingular()) {
        return false;
    }
    
    // Проверка, что базовая кривая имеет правильную структуру для TorusCSIDH
    if (!base_curve.has_valid_torus_structure()) {
        return false;
    }
    
    // Проверка, что простые числа подходят для CSIDH
    for (const auto& prime : params.primes) {
        unsigned long p_val = mpz_get_ui(prime.get_mpz_t());
        if (p_val < 3 || p_val > 100) {
            return false; // Простые числа должны быть в разумном диапазоне
        }
    }
    
    return true;
}

GeometricValidator::Graph TorusCSIDH::build_isogeny_graph(const MontgomeryCurve& center_curve, int radius) const {
    return geometric_validator.build_local_isogeny_graph(center_curve, params.primes, radius);
}

GmpRaii TorusCSIDH::convert_to_gmp_key() const {
    // Конвертация ключа в GmpRaii для некоторых проверок
    GmpRaii key;
    mpz_set_ui(key.get_mpz_t(), 0);
    
    for (size_t i = 0; i < private_key.size(); i++) {
        if (private_key[i] != 0) {
            mpz_setbit(key.get_mpz_t(), i);
        }
    }
    
    return key;
}

bool TorusCSIDH::is_equivalent_to_base_curve(const MontgomeryCurve& curve) const {
    // Две кривые Монтгомери эквивалентны, если их j-инварианты совпадают
    return curve.compute_j_invariant() == base_curve.compute_j_invariant();
}

// Дополнительные методы для усиления безопасности

bool TorusCSIDH::is_key_well_distributed() const {
    // Проверка равномерности распределения ключа
    // В легитимном ключе коэффициенты должны быть распределены относительно равномерно
    
    // Подсчитываем количество положительных, отрицательных и нулевых коэффициентов
    int positive_count = 0;
    int negative_count = 0;
    int zero_count = 0;
    
    for (const auto& val : private_key) {
        if (val > 0) positive_count++;
        else if (val < 0) negative_count++;
        else zero_count++;
    }
    
    // Вычисляем энтропию распределения знаков
    double total = private_key.size();
    double entropy = 0.0;
    
    if (positive_count > 0) {
        double p = positive_count / total;
        entropy -= p * std::log2(p);
    }
    
    if (negative_count > 0) {
        double p = negative_count / total;
        entropy -= p * std::log2(p);
    }
    
    if (zero_count > 0) {
        double p = zero_count / total;
        entropy -= p * std::log2(p);
    }
    
    // Минимальная энтропия для легитимного ключа
    const double min_entropy = 1.5;
    
    return entropy >= min_entropy;
}

bool TorusCSIDH::is_key_resistant_to_topological_analysis() const {
    // Проверка устойчивости к топологическому анализу
    // В легитимном ключе не должно быть явных паттернов в последовательности изогений
    
    // Проверка на периодичность
    const size_t max_period = private_key.size() / 2;
    for (size_t period = 1; period <= max_period; period++) {
        bool is_periodic = true;
        for (size_t i = 0; i < private_key.size() - period; i++) {
            if (private_key[i] != private_key[i + period]) {
                is_periodic = false;
                break;
            }
        }
        
        if (is_periodic) {
            return false; // Ключ уязвим к топологическому анализу
        }
    }
    
    // Проверка на корреляцию между соседними коэффициентами
    double correlation = 0.0;
    for (size_t i = 0; i < private_key.size() - 1; i++) {
        correlation += private_key[i] * private_key[i + 1];
    }
    
    // Нормализация корреляции
    correlation = std::abs(correlation) / private_key.size();
    
    // Максимально допустимая корреляция
    const double max_correlation = 5.0;
    
    return correlation <= max_correlation;
}

bool TorusCSIDH::has_sufficient_key_entropy() const {
    // Проверка энтропии ключа
    // В легитимном ключе должно быть достаточно высокое значение энтропии
    
    // Подсчитываем частоту встречаемости различных значений
    std::map<short, int> value_count;
    for (const auto& val : private_key) {
        value_count[val]++;
    }
    
    // Вычисляем энтропию
    double total = private_key.size();
    double entropy = 0.0;
    
    for (const auto& entry : value_count) {
        double p = entry.second / total;
        entropy -= p * std::log2(p);
    }
    
    // Минимальная энтропия для легитимного ключа
    const double min_entropy = 3.5;
    
    return entropy >= min_entropy;
}

bool TorusCSIDH::is_key_geometrically_sound() const {
    // Проверка, что ключ соответствует геометрическим свойствам графа изогений
    
    // Создаем кривую из ключа
    MontgomeryCurve test_curve = base_curve;
    for (size_t i = 0; i < params.primes.size(); i++) {
        int exponent = private_key[i];
        
        if (exponent != 0) {
            unsigned int order = static_cast<unsigned int>(mpz_get_ui(params.primes[i].get_mpz_t()));
            EllipticCurvePoint kernel_point = test_curve.find_point_of_order(order);
            
            // Применение изогении |exponent| раз
            for (int j = 0; j < std::abs(exponent); j++) {
                test_curve = test_curve.compute_isogeny(kernel_point, order);
                
                // Для отрицательных экспонент используем обратную изогению
                if (exponent < 0) {
                    kernel_point = kernel_point.scalar_multiply(GmpRaii(order - 1), test_curve);
                }
            }
        }
    }
    
    // Проверяем геометрические свойства полученной кривой
    return validate_geometric_properties(test_curve);
}

bool TorusCSIDH::is_key_resistant_to_entropy_attack() const {
    // Проверка устойчивости к атаке через низкую энтропию
    
    // Проверка на маленькие значения (могут указывать на вырожденную структуру)
    int small_value_count = 0;
    for (const auto& val : private_key) {
        if (std::abs(val) < 3) {
            small_value_count++;
        }
    }
    
    double small_value_ratio = static_cast<double>(small_value_count) / private_key.size();
    const double max_small_value_ratio = 0.7; // 70% - эмпирический предел
    
    return small_value_ratio <= max_small_value_ratio;
}

bool TorusCSIDH::is_key_resistant_to_long_path_attack() const {
    // Проверка уязвимости к атаке через длинный путь
    // В атаке через длинный путь злоумышленник использует кривые,
    // где последовательность изогений одного типа слишком длинная
    
    int max_consecutive_same_sign = 0;
    int current_consecutive = 0;
    int last_sign = 0;
    
    for (const auto& val : private_key) {
        int sign = (val > 0) ? 1 : (val < 0) ? -1 : 0;
        
        if (sign == last_sign && sign != 0) {
            current_consecutive++;
        } else {
            max_consecutive_same_sign = std::max(max_consecutive_same_sign, current_consecutive);
            current_consecutive = (sign != 0) ? 1 : 0;
            last_sign = sign;
        }
    }
    
    max_consecutive_same_sign = std::max(max_consecutive_same_sign, current_consecutive);
    
    // Порог для уязвимости зависит от уровня безопасности
    int vulnerability_threshold;
    switch (security_level_) {
        case SecurityConstants::SecurityLevel::LEVEL_128:
            vulnerability_threshold = SecurityConstants::MAX_CONSECUTIVE_128;
            break;
        case SecurityConstants::SecurityLevel::LEVEL_192:
            vulnerability_threshold = SecurityConstants::MAX_CONSECUTIVE_192;
            break;
        case SecurityConstants::SecurityLevel::LEVEL_256:
            vulnerability_threshold = SecurityConstants::MAX_CONSECUTIVE_256;
            break;
        default:
            vulnerability_threshold = SecurityConstants::MAX_CONSECUTIVE_128;
    }
    
    return max_consecutive_same_sign <= vulnerability_threshold;
}

bool TorusCSIDH::is_key_resistant_to_degenerate_topology_attack() const {
    // Проверка уязвимости к атаке через вырожденную топологию
    // Такая атака использует кривые с неестественной структурой графа изогений
    
    // Проверка на маленькие значения (могут указывать на вырожденную структуру)
    int small_value_count = 0;
    for (const auto& val : private_key) {
        if (std::abs(val) < 3) {
            small_value_count++;
        }
    }
    
    double small_value_ratio = static_cast<double>(small_value_count) / private_key.size();
    const double max_small_value_ratio = 0.7; // 70% - эмпирический предел
    
    return small_value_ratio <= max_small_value_ratio;
}

bool TorusCSIDH::is_key_resistant_to_regular_pattern_attack() const {
    // Проверка на наличие регулярных паттернов в ключе
    // Основано на исследованиях атак через вырожденную топологию
    const size_t min_pattern_length = SecurityConstants::MIN_KEY_PATTERN_LEN;
    
    // Проверка на постоянные последовательности
    for (size_t i = 0; i < private_key.size() - min_pattern_length + 1; i++) {
        bool is_constant = true;
        for (size_t j = 1; j < min_pattern_length; j++) {
            if (private_key[i] != private_key[i + j]) {
                is_constant = false;
                break;
            }
        }
        if (is_constant) {
            return false;
        }
    }
    
    // Проверка на арифметические прогрессии
    for (size_t i = 0; i < private_key.size() - min_pattern_length + 1; i++) {
        if (private_key.size() - i < min_pattern_length) break;
        
        int diff = private_key[i + 1] - private_key[i];
        bool is_arithmetic = true;
        for (size_t j = 2; j < min_pattern_length; j++) {
            if (private_key[i + j] - private_key[i + j - 1] != diff) {
                is_arithmetic = false;
                break;
            }
        }
        if (is_arithmetic) {
            return false;
        }
    }
    
    // Проверка на геометрические прогрессии
    for (size_t i = 0; i < private_key.size() - min_pattern_length + 1; i++) {
        if (private_key.size() - i < min_pattern_length) break;
        
        if (private_key[i] == 0 || private_key[i + 1] == 0) continue;
        
        double ratio = static_cast<double>(private_key[i + 1]) / private_key[i];
        bool is_geometric = true;
        for (size_t j = 2; j < min_pattern_length; j++) {
            if (private_key[i + j - 1] == 0) {
                is_geometric = false;
                break;
            }
            
            double current_ratio = static_cast<double>(private_key[i + j]) / private_key[i + j - 1];
            if (std::abs(current_ratio - ratio) > 0.001) {
                is_geometric = false;
                break;
            }
        }
        if (is_geometric) {
            return false;
        }
    }
    
    return true;
}

} // namespace toruscsidh
