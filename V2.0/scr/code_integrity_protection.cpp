#include "code_integrity_protection.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <stdexcept>
#include <algorithm>
#include <cmath>
#include <sodium.h>
#include <gmp.h>
#include "secure_random.h"
#include "security_constants.h"
#include "elliptic_curve.h"
#include "geometric_validator.h"
#include "secure_audit_logger.h"
#include "postquantum_hash.h"
#include "bech32m.h"

namespace toruscsidh {

// Определение критических модулей для проверки
const std::vector<std::string> CodeIntegrityProtection::CRITICAL_MODULES = {
    "elliptic_curve",
    "geometric_validator",
    "postquantum_hash",
    "secure_random",
    "toruscsidh",
    "rfc6979_rng",
    "bech32m",
    "security_constants",
    "secure_audit_logger",
    "code_integrity_protection"
};

CodeIntegrityProtection::CodeIntegrityProtection()
    : is_blocked_(false),
      anomaly_count_(0),
      last_anomaly_time_(0),
      last_recovery_time_(0),
      last_backup_time_(0),
      criteria_major_version_(1),
      criteria_minor_version_(0),
      criteria_valid_from_(time(nullptr)),
      last_criteria_update_time_(time(nullptr)),
      modules_directory_(SecurityConstants::MODULES_DIR),
      backup_directory_(SecurityConstants::BACKUP_DIR) {
    
    // Инициализация libsodium
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
    
    // Инициализация ключей
    initialize_hmac_key();
    initialize_backup_key();
    
    // Создание системных каталогов
    create_system_directories();
    
    // Загрузка критериев геометрической проверки
    load_criteria();
    
    // Подпись критических модулей
    sign_critical_modules();
    
    SecureAuditLogger::get_instance().log_event("system", "CodeIntegrityProtection initialized", false);
}

CodeIntegrityProtection::~CodeIntegrityProtection() {
    // Очистка секретных данных из памяти
    SecureRandom::secure_clean_memory(hmac_key_.data(), hmac_key_.size());
    SecureRandom::secure_clean_memory(backup_key_.data(), backup_key_.size());
    
    SecureAuditLogger::get_instance().log_event("system", "CodeIntegrityProtection finalized", false);
}

bool CodeIntegrityProtection::system_integrity_check() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Проверка, не заблокирована ли система
    if (is_blocked_) {
        SecureAuditLogger::get_instance().log_event("security", 
            "System integrity check failed: system is blocked due to anomalies", true);
        return false;
    }
    
    // Проверка счетчика аномалий
    if (anomaly_count_ >= MAX_ANOMALY_COUNT) {
        // Система заблокирована из-за превышения количества аномалий
        is_blocked_ = true;
        SecureAuditLogger::get_instance().log_event("security", 
            "System integrity check failed: system blocked due to excessive anomalies", true);
        return false;
    }
    
    // Проверка времени последней аномалии
    if (anomaly_count_ > 0 && 
        time(nullptr) - last_anomaly_time_ < ANOMALY_RESET_INTERVAL) {
        // Аномалии все еще активны
        SecureAuditLogger::get_instance().log_event("security", 
            "System integrity check failed: recent anomalies detected", true);
        return false;
    }
    
    // Проверка критериев геометрической проверки
    if (!are_criteria_valid()) {
        // Критерии устарели или недействительны
        SecureAuditLogger::get_instance().log_event("security", 
            "System integrity check failed: geometric criteria are not valid", true);
        return false;
    }
    
    // Проверка целостности всех критических модулей
    bool all_modules_valid = true;
    for (const auto& module_name : CRITICAL_MODULES) {
        // Получаем данные модуля (в реальной системе здесь будет загрузка из памяти)
        std::vector<unsigned char> module_data;
        if (!load_module_from_secure_storage(module_name, module_data)) {
            SecureAuditLogger::get_instance().log_event("security", 
                "System integrity check failed: module not found - " + module_name, true);
            all_modules_valid = false;
            continue;
        }
        
        // Проверяем целостность модуля
        if (!verify_module(module_name, module_data.data(), module_data.size())) {
            SecureAuditLogger::get_instance().log_event("security", 
                "System integrity check failed: module integrity check failed - " + module_name, true);
            all_modules_valid = false;
        }
    }
    
    if (!all_modules_valid) {
        // Регистрируем аномалию
        handle_anomaly("integrity_failure", "One or more critical modules failed integrity check");
        
        // Проверяем, нужно ли восстановление
        if (is_recovery_needed()) {
            if (!self_recovery()) {
                // Если восстановление не удалось, блокируем систему
                is_blocked_ = true;
                SecureAuditLogger::get_instance().log_event("security", 
                    "System integrity check failed: recovery unsuccessful, system blocked", true);
                return false;
            }
        }
        
        return false;
    }
    
    // Проверка резервной копии
    if (time(nullptr) - last_backup_time_ > MAX_BACKUP_AGE) {
        // Резервная копия устарела
        create_backup();
        SecureAuditLogger::get_instance().log_event("system", 
            "System integrity check: backup created due to age", false);
    }
    
    // Система цела
    return true;
}

bool CodeIntegrityProtection::verify_module(const std::string& module_name, 
                                          const void* data, 
                                          size_t size) {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Получаем сохраненный HMAC для модуля
    std::vector<unsigned char> stored_mac;
    if (!load_module_from_secure_storage(module_name + ".mac", stored_mac)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Module integrity check failed: MAC not found for " + module_name, true);
        return false;
    }
    
    // Проверяем HMAC
    return verify_module_hmac(module_name, data, size, stored_mac);
}

void CodeIntegrityProtection::sign_module(const std::string& module_name, 
                                        const void* data, 
                                        size_t size) {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Создаем HMAC для модуля
    std::vector<unsigned char> mac = create_module_hmac(module_name, data, size);
    
    // Сохраняем HMAC в безопасное хранилище
    save_module_to_secure_storage(module_name + ".mac", mac);
}

bool CodeIntegrityProtection::load_module(const std::string& module_name, 
                                        std::vector<unsigned char>& data) {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Загружаем данные модуля
    if (!load_module_from_secure_storage(module_name, data)) {
        SecureAuditLogger::get_instance().log_event("system", 
            "Failed to load module: " + module_name, true);
        return false;
    }
    
    // Проверяем целостность модуля
    if (!verify_module(module_name, data.data(), data.size())) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Module integrity check failed during load: " + module_name, true);
        return false;
    }
    
    return true;
}

bool CodeIntegrityProtection::self_recovery() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Проверяем, требуется ли восстановление
    if (!is_recovery_needed()) {
        return false;
    }
    
    // Выполняем восстановление
    bool recovery_success = perform_recovery();
    
    if (recovery_success) {
        // Обновляем время восстановления
        last_recovery_time_ = time(nullptr);
        
        // Сбрасываем счетчик аномалий
        reset_anomaly_counter();
        
        // Создаем новую резервную копию
        create_backup();
        
        SecureAuditLogger::get_instance().log_event("system", 
            "System successfully recovered from backup", false);
    } else {
        SecureAuditLogger::get_instance().log_event("security", 
            "System recovery failed", true);
    }
    
    return recovery_success;
}

void CodeIntegrityProtection::save_recovery_state() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Сохраняем текущее состояние системы
    create_backup();
    
    SecureAuditLogger::get_instance().log_event("system", 
        "Recovery state saved", false);
}

bool CodeIntegrityProtection::update_criteria_version(int major_version, 
                                                    int minor_version, 
                                                    time_t valid_from) {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Проверяем, что обновление активно
    if (!is_criteria_update_active()) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Criteria update failed: update not active", true);
        return false;
    }
    
    // Проверяем, что новая версия выше текущей
    if (major_version < criteria_major_version_ || 
        (major_version == criteria_major_version_ && minor_version <= criteria_minor_version_)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Criteria update failed: version not higher than current", true);
        return false;
    }
    
    // Проверяем, что время начала действия в будущем
    if (valid_from <= time(nullptr)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Criteria update failed: valid_from time is not in future", true);
        return false;
    }
    
    // Сохраняем текущее состояние перед обновлением
    save_recovery_state();
    
    try {
        // Обновляем версию критериев
        criteria_major_version_ = major_version;
        criteria_minor_version_ = minor_version;
        criteria_valid_from_ = valid_from;
        last_criteria_update_time_ = time(nullptr);
        
        // Сохраняем обновленные критерии
        save_criteria();
        
        // Переподпись критических модулей
        sign_critical_modules();
        
        // Сброс счетчика аномалий
        anomaly_count_ = 0;
        is_blocked_ = false;
        
        SecureAuditLogger::get_instance().log_event("system", 
            "Geometric criteria updated to version " + 
            std::to_string(major_version) + "." + 
            std::to_string(minor_version), false);
        
        return true;
    } catch (const std::exception& e) {
        // Восстанавливаем предыдущее состояние в случае ошибки
        load_criteria();
        
        // Логируем ошибку
        SecureAuditLogger::get_instance().log_event("security", 
            "Failed to update geometric criteria: " + std::string(e.what()), true);
        
        return false;
    }
}

bool CodeIntegrityProtection::is_system_ready() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Система готова, если она не заблокирована и прошла проверку целостности
    return !is_blocked_ && system_integrity_check();
}

const std::vector<unsigned char>& CodeIntegrityProtection::get_hmac_key() const {
    return hmac_key_;
}

const std::vector<unsigned char>& CodeIntegrityProtection::get_backup_key() const {
    return backup_key_;
}

int CodeIntegrityProtection::get_anomaly_count() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    return anomaly_count_;
}

time_t CodeIntegrityProtection::get_last_anomaly_time() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    return last_anomaly_time_;
}

time_t CodeIntegrityProtection::get_last_recovery_time() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    return last_recovery_time_;
}

time_t CodeIntegrityProtection::get_last_backup_time() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    return last_backup_time_;
}

bool CodeIntegrityProtection::is_system_blocked() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    return is_blocked_;
}

void CodeIntegrityProtection::get_criteria_version(int& major_version, 
                                                  int& minor_version, 
                                                  time_t& valid_from) const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    major_version = criteria_major_version_;
    minor_version = criteria_minor_version_;
    valid_from = criteria_valid_from_;
}

bool CodeIntegrityProtection::are_criteria_valid() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Критерии действительны, если текущее время больше или равно времени начала действия
    return time(nullptr) >= criteria_valid_from_;
}

void CodeIntegrityProtection::sign_critical_modules() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    for (const auto& module_name : CRITICAL_MODULES) {
        // В реальной системе здесь будут получаться данные модуля
        // Для демонстрации создаем пустые данные
        std::vector<unsigned char> module_data;
        
        // Подписываем модуль
        sign_module(module_name, module_data.data(), module_data.size());
    }
}

bool CodeIntegrityProtection::verify_hmac(const std::vector<unsigned char>& data, 
                                        const std::vector<unsigned char>& mac) const {
    // Создаем HMAC с использованием BLAKE3
    blake3_hasher hasher;
    blake3_keyed_hasher keyed_hasher;
    
    // Инициализация ключевого хеширования
    blake3_keyed_hasher_init(&keyed_hasher, hmac_key_.data());
    
    // Обновление хеша данными
    blake3_keyed_hasher_update(&keyed_hasher, data.data(), data.size());
    
    // Финализация и получение HMAC
    std::vector<unsigned char> computed_mac(SecurityConstants::HMAC_SIZE);
    blake3_keyed_hasher_finalize(&keyed_hasher, computed_mac.data(), computed_mac.size());
    
    // Постоянное время сравнение
    return crypto_verify_32(mac.data(), computed_mac.data()) == 0;
}

std::vector<unsigned char> CodeIntegrityProtection::create_hmac(const std::vector<unsigned char>& data) const {
    // Создаем HMAC с использованием BLAKE3
    blake3_hasher hasher;
    blake3_keyed_hasher keyed_hasher;
    
    // Инициализация ключевого хеширования
    blake3_keyed_hasher_init(&keyed_hasher, hmac_key_.data());
    
    // Обновление хеша данными
    blake3_keyed_hasher_update(&keyed_hasher, data.data(), data.size());
    
    // Финализация и получение HMAC
    std::vector<unsigned char> mac(SecurityConstants::HMAC_SIZE);
    blake3_keyed_hasher_finalize(&keyed_hasher, mac.data(), mac.size());
    
    return mac;
}

void CodeIntegrityProtection::ensure_constant_time(const std::chrono::microseconds& target_time) const {
    auto start = std::chrono::high_resolution_clock::now();
    
    // Используем более сложный алгоритм для обеспечения постоянного времени
    // который не зависит от предыдущих операций
    
    // Вычисляем, сколько времени уже прошло
    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    
    // Если мы уже превысили целевое время, не делаем ничего
    if (elapsed >= target_time) {
        return;
    }
    
    // Вычисляем оставшееся время
    auto remaining = target_time - elapsed;
    
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

bool CodeIntegrityProtection::is_constant_time_operation() const {
    // Проверяем, что операция была выполнена за постоянное время
    // В реальной системе здесь будет сложная логика мониторинга
    return true;
}

void CodeIntegrityProtection::handle_anomaly(const std::string& anomaly_type, 
                                           const std::string& description) {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Увеличиваем счетчик аномалий
    anomaly_count_++;
    last_anomaly_time_ = time(nullptr);
    
    // Логируем аномалию
    SecureAuditLogger::get_instance().log_event("security", 
        "Anomaly detected: " + anomaly_type + " - " + description + 
        " (count: " + std::to_string(anomaly_count_) + ")", true);
    
    // Блокировка системы при превышении порога аномалий
    if (anomaly_count_ >= MAX_ANOMALY_COUNT) {
        is_blocked_ = true;
        SecureAuditLogger::get_instance().log_event("security", 
            "System blocked due to excessive anomalies", true);
    }
}

void CodeIntegrityProtection::reset_anomaly_counter() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    anomaly_count_ = 0;
    last_anomaly_time_ = 0;
}

bool CodeIntegrityProtection::is_system_normal() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Система в нормальном состоянии, если нет аномалий или они были сброшены
    return anomaly_count_ == 0 || 
           (anomaly_count_ > 0 && time(nullptr) - last_anomaly_time_ > ANOMALY_RESET_INTERVAL);
}

const std::string& CodeIntegrityProtection::get_modules_directory() const {
    return modules_directory_;
}

const std::string& CodeIntegrityProtection::get_backup_directory() const {
    return backup_directory_;
}

void CodeIntegrityProtection::create_system_directories() {
    try {
        // Создаем каталог для модулей
        if (!std::filesystem::exists(modules_directory_)) {
            std::filesystem::create_directories(modules_directory_);
        }
        
        // Создаем каталог для резервных копий
        if (!std::filesystem::exists(backup_directory_)) {
            std::filesystem::create_directories(backup_directory_);
        }
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to create system directories: " + std::string(e.what()));
    }
}

bool CodeIntegrityProtection::system_directories_exist() const {
    return std::filesystem::exists(modules_directory_) && 
           std::filesystem::is_directory(modules_directory_) &&
           std::filesystem::exists(backup_directory_) && 
           std::filesystem::is_directory(backup_directory_);
}

std::vector<unsigned char> CodeIntegrityProtection::encrypt_backup_data(const std::vector<unsigned char>& data) const {
    // Шифрование данных с использованием XChaCha20-Poly1305
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    
    std::vector<unsigned char> encrypted_data;
    encrypted_data.resize(data.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    
    unsigned long long ciphertext_len;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        encrypted_data.data(), &ciphertext_len,
        data.data(), data.size(),
        nullptr, 0, // additional data
        nullptr, nonce, backup_key_.data()
    );
    
    // Добавляем nonce к зашифрованным данным
    std::vector<unsigned char> result;
    result.insert(result.end(), nonce, nonce + sizeof(nonce));
    result.insert(result.end(), encrypted_data.begin(), encrypted_data.end());
    
    return result;
}

std::vector<unsigned char> CodeIntegrityProtection::decrypt_backup_data(const std::vector<unsigned char>& encrypted_data) const {
    // Проверка длины данных
    if (encrypted_data.size() < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 
        crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        return std::vector<unsigned char>();
    }
    
    // Извлечение nonce
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    std::memcpy(nonce, encrypted_data.data(), sizeof(nonce));
    
    // Расшифровка данных
    std::vector<unsigned char> decrypted_data;
    decrypted_data.resize(encrypted_data.size() - sizeof(nonce) - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    
    unsigned long long plaintext_len;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            decrypted_data.data(), &plaintext_len,
            nullptr,
            encrypted_data.data() + sizeof(nonce), 
            encrypted_data.size() - sizeof(nonce),
            nullptr, 0, // additional data
            nonce, backup_key_.data()) != 0) {
        return std::vector<unsigned char>(); // Ошибка расшифровки
    }
    
    return decrypted_data;
}

bool CodeIntegrityProtection::verify_backup_integrity(const std::string& backup_file) const {
    // Чтение содержимого резервной копии
    std::ifstream file(backup_file, std::ios::binary);
    if (!file) {
        return false;
    }
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<unsigned char> content(size);
    file.read(reinterpret_cast<char*>(content.data()), size);
    file.close();
    
    // Расшифровка содержимого
    std::vector<unsigned char> decrypted_content = decrypt_backup_data(content);
    if (decrypted_content.empty()) {
        return false;
    }
    
    // Проверка целостности расшифрованных данных
    return verify_backup_data_integrity(decrypted_content);
}

std::string CodeIntegrityProtection::get_current_datetime_str() const {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t_now), "%Y%m%d_%H%M%S");
    return ss.str();
}

bool CodeIntegrityProtection::is_criteria_update_required() const {
    // Проверка, требуется ли обновление критериев
    // В реальной системе здесь будет проверка через безопасное соединение
    return false;
}

void CodeIntegrityProtection::get_criteria_update_info(time_t& update_time, 
                                                     int& major_version, 
                                                     int& minor_version) const {
    update_time = last_criteria_update_time_;
    major_version = criteria_major_version_;
    minor_version = criteria_minor_version_;
}

void CodeIntegrityProtection::initialize_hmac_key() {
    hmac_key_.resize(HMAC_KEY_SIZE);
    randombytes_buf(hmac_key_.data(), hmac_key_.size());
}

void CodeIntegrityProtection::initialize_backup_key() {
    backup_key_.resize(BACKUP_KEY_SIZE);
    randombytes_buf(backup_key_.data(), backup_key_.size());
}

bool CodeIntegrityProtection::is_recovery_needed() const {
    // Проверка, требуется ли восстановление системы
    return anomaly_count_ >= MAX_ANOMALY_COUNT / 2;
}

bool CodeIntegrityProtection::perform_recovery() {
    // Поиск последней валидной резервной копии
    std::string latest_backup;
    time_t latest_backup_time = 0;
    
    for (const auto& entry : std::filesystem::directory_iterator(backup_directory_)) {
        if (entry.path().extension() == ".bak") {
            time_t backup_time = entry.last_write_time().time_since_epoch().count();
            if (backup_time > latest_backup_time) {
                latest_backup = entry.path().string();
                latest_backup_time = backup_time;
            }
        }
    }
    
    if (latest_backup.empty()) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Recovery failed: no valid backup found", true);
        return false;
    }
    
    // Проверка целостности резервной копии
    if (!verify_backup_integrity(latest_backup)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Recovery failed: backup integrity check failed", true);
        return false;
    }
    
    // Загрузка данных из резервной копии
    std::ifstream backup_file(latest_backup, std::ios::binary);
    if (!backup_file) {
        SecureAuditLogger::get_
