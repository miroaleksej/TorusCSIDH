#include "toruscsidh.h"
#include <iostream>
#include <vector>
#include <chrono>
#include "secure_audit_logger.h"
#include "code_integrity.h"

namespace toruscsidh {

TorusCSIDH::TorusCSIDH(SecurityConstants::SecurityLevel security_level)
    : security_level_(security_level),
      system_ready_(false),
      start_time_(std::chrono::high_resolution_clock::now()) {
    
    // Инициализация системы
    initialize();
    
    SecureAuditLogger::get_instance().log_event("system", 
        "TorusCSIDH initialized with security level: " + 
        SecurityConstants::security_level_to_string(security_level_), false);
}

TorusCSIDH::~TorusCSIDH() {
    // Очистка памяти
    SecureRandom::secure_clean_memory(private_key_.data(), private_key_.size() * sizeof(short));
    
    SecureAuditLogger::get_instance().log_event("system", 
        "TorusCSIDH destroyed", false);
}

void TorusCSIDH::initialize() {
    // Проверка целостности системы перед инициализацией
    if (!code_integrity_.system_integrity_check()) {
        if (!code_integrity_.self_recovery()) {
            throw std::runtime_error("System integrity check failed and recovery unsuccessful");
        }
    }
    
    // Инициализация базовой кривой
    base_curve_ = SecurityConstants::get_base_curve(security_level_);
    
    // Инициализация генератора RFC 6979
    rfc6979_rng_ = std::make_unique<Rfc6979Rng>(base_curve_.get_p(), private_key_, 
                                               SecurityConstants::get_max_key_magnitude(security_level_));
    
    system_ready_ = true;
    
    SecureAuditLogger::get_instance().log_event("system", 
        "TorusCSIDH initialized successfully", false);
}

void TorusCSIDH::generate_key_pair() {
    if (!is_system_ready()) {
        throw std::runtime_error("System is not ready for operation");
    }
    
    start_time_ = std::chrono::high_resolution_clock::now();
    
    // Проверка целостности системы перед генерацией ключа
    if (!code_integrity_.system_integrity_check()) {
        if (!code_integrity_.self_recovery()) {
            throw std::runtime_error("System integrity check failed and recovery unsuccessful");
        }
    }
    
    // Очистка предыдущего ключа
    SecureRandom::secure_clean_memory(private_key_.data(), private_key_.size() * sizeof(short));
    private_key_.clear();
    
    // Генерация "малого" ключа
    const auto& params = SecurityConstants::get_params(security_level_);
    private_key_.resize(params.num_primes);
    
    // Генерация ключа с ограниченной нормой L∞
    int max_abs = params.max_key_magnitude;
    for (short& val : private_key_) {
        val = static_cast<short>(SecureRandom::random_int(-max_abs, max_abs));
    }
    
    // Вычисление публичной кривой
    public_curve_ = base_curve_;
    for (size_t i = 0; i < private_key_.size(); i++) {
        int exp = private_key_[i];
        const GmpRaii& prime = SecurityConstants::get_primes(security_level_)[i];
        unsigned int degree = static_cast<unsigned int>(mpz_get_ui(prime.get_mpz_t()));
        
        for (int j = 0; j < std::abs(exp); j++) {
            EllipticCurvePoint kernel_point = public_curve_.find_point_of_order(degree);
            if (!kernel_point.is_infinity()) {
                public_curve_ = public_curve_.compute_isogeny(kernel_point, degree);
            }
        }
    }
    
    SecureAuditLogger::get_instance().log_event("crypto", 
        "Key pair generated successfully", false);
}

std::vector<unsigned char> TorusCSIDH::sign(const std::vector<unsigned char>& message) {
    if (!is_system_ready()) {
        throw std::runtime_error("System is not ready for operation");
    }
    
    start_time_ = std::chrono::high_resolution_clock::now();
    
    // Проверка целостности системы перед подписью
    if (!code_integrity_.system_integrity_check()) {
        if (!code_integrity_.self_recovery()) {
            throw std::runtime_error("System integrity check failed and recovery unsuccessful");
        }
    }
    
    // Проверка целостности ключа
    if (!verify_key_integrity()) {
        throw std::runtime_error("Key integrity check failed");
    }
    
    // Генерация эфемерного ключа
    std::vector<short> ephemeral_key = private_key_;
    for (short& val : ephemeral_key) {
        val += static_cast<short>(SecureRandom::random_int(-1, 1));
    }
    
    // Вычисление эфемерной кривой
    MontgomeryCurve ephemeral_curve = base_curve_;
    for (size_t i = 0; i < ephemeral_key.size(); i++) {
        int exp = ephemeral_key[i];
        const GmpRaii& prime = SecurityConstants::get_primes(security_level_)[i];
        unsigned int degree = static_cast<unsigned int>(mpz_get_ui(prime.get_mpz_t()));
        
        for (int j = 0; j < std::abs(exp); j++) {
            EllipticCurvePoint kernel_point = ephemeral_curve.find_point_of_order(degree);
            if (!kernel_point.is_infinity()) {
                ephemeral_curve = ephemeral_curve.compute_isogeny(kernel_point, degree);
            }
        }
    }
    
    // Геометрическая проверка эфемерной кривой
    double cyclomatic_score, spectral_score, clustering_score, entropy_score, distance_score;
    if (!geometric_validator_.validate_curve(base_curve_, ephemeral_curve, cyclomatic_score, 
                                           spectral_score, clustering_score, entropy_score, distance_score)) {
        throw std::runtime_error("Ephemeral curve failed geometric validation");
    }
    
    // Вычисление общего секрета
    MontgomeryCurve shared_curve = public_curve_;
    for (size_t i = 0; i < ephemeral_key.size(); i++) {
        int exp = ephemeral_key[i];
        const GmpRaii& prime = SecurityConstants::get_primes(security_level_)[i];
        unsigned int degree = static_cast<unsigned int>(mpz_get_ui(prime.get_mpz_t()));
        
        for (int j = 0; j < std::abs(exp); j++) {
            EllipticCurvePoint kernel_point = shared_curve.find_point_of_order(degree);
            if (!kernel_point.is_infinity()) {
                shared_curve = shared_curve.compute_isogeny(kernel_point, degree);
            }
        }
    }
    
    // Хеширование для получения подписи
    std::vector<unsigned char> shared_j = PostQuantumHash::hash_string(shared_curve.compute_j_invariant().get_str());
    std::vector<unsigned char> signature = PostQuantumHash::hash(
        message + shared_j, 
        SecurityConstants::SIGNATURE_SIZE
    );
    
    // Обеспечение постоянного времени выполнения
    ensure_constant_time(SecurityConstants::SIGN_TARGET_TIME);
    
    return signature;
}

bool TorusCSIDH::verify(const std::vector<unsigned char>& message, 
                       const std::vector<unsigned char>& signature) {
    if (!is_system_ready()) {
        throw std::runtime_error("System is not ready for operation");
    }
    
    start_time_ = std::chrono::high_resolution_clock::now();
    
    // Проверка целостности системы перед верификацией
    if (!code_integrity_.system_integrity_check()) {
        if (!code_integrity_.self_recovery()) {
            throw std::runtime_error("System integrity check failed and recovery unsuccessful");
        }
    }
    
    // Проверка, что подпись имеет правильный размер
    if (signature.size() != SecurityConstants::SIGNATURE_SIZE) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Verification failed: signature size mismatch", true);
        return false;
    }
    
    // Проверка геометрической целостности публичной кривой
    double cyclomatic_score, spectral_score, clustering_score, entropy_score, distance_score;
    if (!geometric_validator_.validate_curve(base_curve_, public_curve_, cyclomatic_score, 
                                           spectral_score, clustering_score, entropy_score, distance_score)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Verification failed: public curve failed geometric validation", true);
        return false;
    }
    
    // Проверка подписи через коммутативность
    MontgomeryCurve shared_curve1 = public_curve_;
    for (size_t i = 0; i < SecurityConstants::get_primes(security_level_).size(); i++) {
        const GmpRaii& prime = SecurityConstants::get_primes(security_level_)[i];
        unsigned int degree = static_cast<unsigned int>(mpz_get_ui(prime.get_mpz_t()));
        
        EllipticCurvePoint kernel_point = shared_curve1.find_point_of_order(degree);
        if (!kernel_point.is_infinity()) {
            shared_curve1 = shared_curve1.compute_isogeny(kernel_point, degree);
        }
    }
    
    MontgomeryCurve shared_curve2 = base_curve_;
    for (size_t i = 0; i < SecurityConstants::get_primes(security_level_).size(); i++) {
        const GmpRaii& prime = SecurityConstants::get_primes(security_level_)[i];
        unsigned int degree = static_cast<unsigned int>(mpz_get_ui(prime.get_mpz_t()));
        
        EllipticCurvePoint kernel_point = public_curve_.find_point_of_order(degree);
        if (!kernel_point.is_infinity()) {
            shared_curve2 = shared_curve2.compute_isogeny(kernel_point, degree);
        }
    }
    
    // Проверка, что кривые эквивалентны
    if (!shared_curve1.is_equivalent_to(shared_curve2)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Verification failed: shared curves not equivalent", true);
        return false;
    }
    
    // Проверка подписи
    std::vector<unsigned char> shared_j = PostQuantumHash::hash_string(shared_curve1.compute_j_invariant().get_str());
    std::vector<unsigned char> expected_signature = PostQuantumHash::hash(
        message + shared_j, 
        SecurityConstants::SIGNATURE_SIZE
    );
    
    // Постоянное время сравнение
    bool is_valid = PostQuantumHash::verify_hmac_constant_time(
        expected_signature, 
        signature, 
        std::chrono::microseconds(100)
    );
    
    if (!is_valid) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Verification failed: signature mismatch", true);
    }
    
    // Обеспечение постоянного времени выполнения
    ensure_constant_time(SecurityConstants::VERIFY_TARGET_TIME);
    
    return is_valid;
}

std::string TorusCSIDH::generate_address() {
    if (!is_system_ready()) {
        throw std::runtime_error("System is not ready for operation");
    }
    
    start_time_ = std::chrono::high_resolution_clock::now();
    
    // Проверка целостности системы перед генерацией адреса
    if (!code_integrity_.system_integrity_check()) {
        if (!code_integrity_.self_recovery()) {
            throw std::runtime_error("System integrity check failed and recovery unsuccessful");
        }
    }
    
    // Проверка целостности ключа
    if (!verify_key_integrity()) {
        throw std::runtime_error("Key integrity check failed");
    }
    
    // Генерация адреса в формате Bech32m
    std::vector<unsigned char> public_key_hash = PostQuantumHash::hash_string(
        public_curve_.compute_j_invariant().get_str(),
        SecurityConstants::ADDRESS_SIZE
    );
    
    return bech32m::encode("tcidh", public_key_hash);
}

void TorusCSIDH::print_info() const {
    std::cout << "TorusCSIDH System Information:" << std::endl;
    std::cout << "  Security Level: " << SecurityConstants::security_level_to_string(security_level_) << std::endl;
    std::cout << "  System Ready: " << (system_ready_ ? "Yes" : "No") << std::endl;
    
    if (system_ready_) {
        std::cout << "  Key Pair Generated: " << (!private_key_.empty() ? "Yes" : "No") << std::endl;
        if (!private_key_.empty()) {
            std::cout << "  Key Integrity: " << (verify_key_integrity() ? "Valid" : "Invalid") << std::endl;
        }
    }
}

bool TorusCSIDH::is_system_ready() const {
    return system_ready_;
}

const MontgomeryCurve& TorusCSIDH::get_public_curve() const {
    return public_curve_;
}

const std::vector<short>& TorusCSIDH::get_private_key() const {
    return private_key_;
}

bool TorusCSIDH::verify_key_integrity() const {
    // Проверка "малости" ключа
    if (!is_small_key()) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Key integrity check failed: key is not small", true);
        return false;
    }
    
    // Геометрическая проверка публичной кривой
    double cyclomatic_score, spectral_score, clustering_score, entropy_score, distance_score;
    if (!geometric_validator_.validate_curve(base_curve_, public_curve_, cyclomatic_score, 
                                           spectral_score, clustering_score, entropy_score, distance_score)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Key integrity check failed: public curve failed geometric validation", true);
        return false;
    }
    
    return true;
}

bool TorusCSIDH::is_small_key() const {
    const auto& params = SecurityConstants::get_params(security_level_);
    
    // Проверка нормы L∞
    for (const short& val : private_key_) {
        if (std::abs(val) > params.max_key_magnitude) {
            return false;
        }
    }
    
    return true;
}

bool TorusCSIDH::is_weak_key() const {
    // Проверка на наличие регулярных паттернов в ключе
    if (has_regular_patterns()) {
        return true;
    }
    
    // Проверка на уязвимость к атаке через длинный путь
    if (is_vulnerable_to_long_path_attack()) {
        return true;
    }
    
    // Проверка на уязвимость к атаке через вырожденную топологию
    if (is_vulnerable_to_degenerate_topology_attack()) {
        return true;
    }
    
    return false;
}

bool TorusCSIDH::is_secure_key() const {
    // Проверка, что ключ соответствует всем критериям безопасности
    return is_small_key() && !is_weak_key();
}

void TorusCSIDH::ensure_constant_time(const std::chrono::microseconds& target_time) {
    auto elapsed = std::chrono::high_resolution_clock::now() - start_time_;
    
    // Используем более надежный метод для обеспечения постоянного времени
    if (elapsed < target_time) {
        // Дополнительные вычисления для достижения целевого времени
        std::chrono::microseconds sleep_time = target_time - elapsed;
        
        // Используем busy-wait для более точного контроля времени
        auto start = std::chrono::high_resolution_clock::now();
        while (std::chrono::high_resolution_clock::now() - start < sleep_time) {
            // Выполняем небольшие вычисления, чтобы занять процессор
            volatile int dummy = 0;
            for (int i = 0; i < 1000; i++) {
                dummy += i * i;
            }
        }
    }
}

bool TorusCSIDH::has_regular_patterns() const {
    const size_t min_pattern_length = SecurityConstants::MIN_KEY_PATTERN_LEN;
    
    // Проверка на постоянные последовательности
    for (size_t i = 0; i < private_key_.size(); i++) {
        for (size_t len = min_pattern_length; len <= private_key_.size() / 2; len++) {
            if (i + 2 * len > private_key_.size()) {
                break;
            }
            
            bool pattern_found = true;
            for (size_t j = 0; j < len; j++) {
                if (private_key_[i + j] != private_key_[i + j + len]) {
                    pattern_found = false;
                    break;
                }
            }
            
            if (pattern_found) {
                return true;
            }
        }
    }
    
    return false;
}

bool TorusCSIDH::is_vulnerable_to_long_path_attack() const {
    // Проверка, что ключ не содержит слишком длинных последовательностей
    // одного и того же значения, что может привести к длинному пути в графе
    
    const int max_consecutive_same = SecurityConstants::MAX_CONSECUTIVE_SAME;
    int consecutive_count = 1;
    
    for (size_t i = 1; i < private_key_.size(); i++) {
        if (private_key_[i] == private_key_[i-1]) {
            consecutive_count++;
            if (consecutive_count > max_consecutive_same) {
                return true;
            }
        } else {
            consecutive_count = 1;
        }
    }
    
    return false;
}

bool TorusCSIDH::is_vulnerable_to_degenerate_topology_attack() const {
    // Проверка на маленькие значения (могут указывать на вырожденную структуру)
    int small_value_count = 0;
    for (const auto& val : private_key_) {
        if (std::abs(val) < 3) {
            small_value_count++;
        }
    }
    
    double small_value_ratio = static_cast<double>(small_value_count) / private_key_.size();
    const double max_small_value_ratio = 0.7; // 70% - эмпирический предел
    
    return small_value_ratio > max_small_value_ratio;
}

} // namespace toruscsidh
