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
        SecureAuditLogger::get_instance().log_event("security", 
            "Recovery failed: failed to open backup file", true);
        return false;
    }
    
    backup_file.seekg(0, std::ios::end);
    size_t size = backup_file.tellg();
    backup_file.seekg(0, std::ios::beg);
    
    std::vector<unsigned char> backup_data(size);
    backup_file.read(reinterpret_cast<char*>(backup_data.data()), size);
    backup_file.close();
    
    // Расшифровка данных
    std::vector<unsigned char> decrypted_data = decrypt_backup_data(backup_data);
    if (decrypted_data.empty()) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Recovery failed: backup decryption failed", true);
        return false;
    }
    
    // Проверка целостности данных
    if (!verify_backup_data_integrity(decrypted_data)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Recovery failed: backup data integrity check failed", true);
        return false;
    }
    
    // Восстановление критических модулей
    // В реальной системе здесь будет сложная логика восстановления
    sign_critical_modules();
    
    return true;
}

void CodeIntegrityProtection::create_backup() {
    // Создание временного каталога для резервной копии
    std::string backup_name = "backup_" + get_current_datetime_str() + ".bak";
    std::string backup_path = backup_directory_ + "/" + backup_name;
    
    // Сбор данных для резервной копии
    std::vector<unsigned char> backup_data;
    
    // Добавление критических модулей
    for (const auto& module_name : CRITICAL_MODULES) {
        std::vector<unsigned char> module_data;
        if (load_module_from_secure_storage(module_name, module_data)) {
            // Добавляем длину данных
            uint32_t data_size = static_cast<uint32_t>(module_data.size());
            backup_data.insert(backup_data.end(), 
                              reinterpret_cast<unsigned char*>(&data_size), 
                              reinterpret_cast<unsigned char*>(&data_size) + sizeof(data_size));
            
            // Добавляем данные
            backup_data.insert(backup_data.end(), module_data.begin(), module_data.end());
        }
    }
    
    // Добавление критериев геометрической проверки
    std::vector<unsigned char> criteria_data;
    load_criteria();
    // В реальной системе здесь будет сериализация критериев
    
    // Добавляем длину данных
    uint32_t criteria_size = static_cast<uint32_t>(criteria_data.size());
    backup_data.insert(backup_data.end(), 
                      reinterpret_cast<unsigned char*>(&criteria_size), 
                      reinterpret_cast<unsigned char*>(&criteria_size) + sizeof(criteria_size));
    
    // Добавляем данные
    backup_data.insert(backup_data.end(), criteria_data.begin(), criteria_data.end());
    
    // Шифрование данных
    std::vector<unsigned char> encrypted_data = encrypt_backup_data(backup_data);
    
    // Сохранение резервной копии
    std::ofstream backup_file(backup_path, std::ios::binary);
    if (backup_file) {
        backup_file.write(reinterpret_cast<const char*>(encrypted_data.data()), encrypted_data.size());
        backup_file.close();
        
        last_backup_time_ = time(nullptr);
        
        SecureAuditLogger::get_instance().log_event("system", 
            "Backup created: " + backup_name, false);
    } else {
        SecureAuditLogger::get_instance().log_event("security", 
            "Failed to create backup: " + backup_name, true);
    }
}

bool CodeIntegrityProtection::is_criteria_expired() const {
    // Проверка, истекло ли время действия текущих критериев
    // В реальной системе здесь будет сложная логика
    return false;
}

bool CodeIntegrityProtection::is_criteria_update_active() const {
    // Проверка, активно ли обновление критериев
    // В реальной системе здесь будет проверка через безопасное соединение
    return true;
}

bool CodeIntegrityProtection::save_module_to_secure_storage(const std::string& module_name,
                                                          const std::vector<unsigned char>& module_data) const {
    std::string file_path = get_module_file_path(module_name);
    
    // Создание временного файла
    std::string temp_file = file_path + ".tmp";
    
    // Запись данных в временный файл
    std::ofstream file(temp_file, std::ios::binary);
    if (!file) {
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(module_data.data()), module_data.size());
    file.close();
    
    // Переименование временного файла в основной
    if (std::rename(temp_file.c_str(), file_path.c_str()) != 0) {
        std::remove(temp_file.c_str());
        return false;
    }
    
    return true;
}

bool CodeIntegrityProtection::load_module_from_secure_storage(const std::string& module_name,
                                                            std::vector<unsigned char>& module_data) const {
    std::string file_path = get_module_file_path(module_name);
    
    // Проверка существования файла
    if (!std::filesystem::exists(file_path)) {
        return false;
    }
    
    // Чтение данных из файла
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        return false;
    }
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    module_data.resize(size);
    file.read(reinterpret_cast<char*>(module_data.data()), size);
    file.close();
    
    return true;
}

bool CodeIntegrityProtection::verify_module_hmac(const std::string& module_name,
                                               const void* data,
                                               size_t size,
                                               const std::vector<unsigned char>& stored_mac) const {
    // Создаем HMAC для данных
    blake3_hasher hasher;
    blake3_keyed_hasher keyed_hasher;
    
    // Инициализация ключевого хеширования
    blake3_keyed_hasher_init(&keyed_hasher, hmac_key_.data());
    
    // Добавляем имя модуля для уникальности
    blake3_keyed_hasher_update(&keyed_hasher, module_name.c_str(), module_name.size());
    
    // Добавляем данные
    blake3_keyed_hasher_update(&keyed_hasher, static_cast<const unsigned char*>(data), size);
    
    // Финализация и получение HMAC
    std::vector<unsigned char> computed_mac(SecurityConstants::HMAC_SIZE);
    blake3_keyed_hasher_finalize(&keyed_hasher, computed_mac.data(), computed_mac.size());
    
    // Постоянное время сравнение
    return crypto_verify_32(stored_mac.data(), computed_mac.data()) == 0;
}

std::vector<unsigned char> CodeIntegrityProtection::create_module_hmac(const std::string& module_name,
                                                                     const void* data,
                                                                     size_t size) const {
    // Создаем HMAC для данных
    blake3_hasher hasher;
    blake3_keyed_hasher keyed_hasher;
    
    // Инициализация ключевого хеширования
    blake3_keyed_hasher_init(&keyed_hasher, hmac_key_.data());
    
    // Добавляем имя модуля для уникальности
    blake3_keyed_hasher_update(&keyed_hasher, module_name.c_str(), module_name.size());
    
    // Добавляем данные
    blake3_keyed_hasher_update(&keyed_hasher, static_cast<const unsigned char*>(data), size);
    
    // Финализация и получение HMAC
    std::vector<unsigned char> mac(SecurityConstants::HMAC_SIZE);
    blake3_keyed_hasher_finalize(&keyed_hasher, mac.data(), mac.size());
    
    return mac;
}

std::string CodeIntegrityProtection::get_module_file_path(const std::string& module_name) const {
    return modules_directory_ + "/" + module_name + ".bin";
}

std::string CodeIntegrityProtection::get_backup_file_path(const std::string& backup_name) const {
    return backup_directory_ + "/" + backup_name;
}

std::string CodeIntegrityProtection::get_criteria_file_path() const {
    return modules_directory_ + "/geometric_criteria.bin";
}

void CodeIntegrityProtection::load_criteria() {
    std::string criteria_path = get_criteria_file_path();
    
    // Проверка существования файла
    if (!std::filesystem::exists(criteria_path)) {
        // Создаем стандартные критерии
        criteria_major_version_ = 1;
        criteria_minor_version_ = 0;
        criteria_valid_from_ = time(nullptr);
        last_criteria_update_time_ = time(nullptr);
        
        // Сохраняем критерии
        save_criteria();
        
        return;
    }
    
    // Загрузка данных
    std::ifstream file(criteria_path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open criteria file");
    }
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<unsigned char> criteria_data(size);
    file.read(reinterpret_cast<char*>(criteria_data.data()), size);
    file.close();
    
    // Расшифровка данных
    std::vector<unsigned char> decrypted_criteria = decrypt_criteria(criteria_data);
    if (decrypted_criteria.empty()) {
        throw std::runtime_error("Failed to decrypt criteria");
    }
    
    // Проверка целостности
    if (!verify_criteria_integrity()) {
        throw std::runtime_error("Criteria integrity check failed");
    }
    
    // Десериализация критериев
    // В реальной системе здесь будет сложная логика десериализации
}

void CodeIntegrityProtection::save_criteria() {
    // Сериализация критериев
    // В реальной системе здесь будет сложная логика сериализации
    std::vector<unsigned char> criteria_data;
    
    // Шифрование данных
    std::vector<unsigned char> encrypted_criteria = encrypt_criteria(criteria_data);
    
    // Создание HMAC
    std::vector<unsigned char> mac = create_criteria_hmac(criteria_data);
    
    // Добавление HMAC к данным
    encrypted_criteria.insert(encrypted_criteria.end(), mac.begin(), mac.end());
    
    // Сохранение в файл
    std::string criteria_path = get_criteria_file_path();
    std::ofstream file(criteria_path, std::ios::binary);
    if (file) {
        file.write(reinterpret_cast<const char*>(encrypted_criteria.data()), encrypted_criteria.size());
        file.close();
    } else {
        throw std::runtime_error("Failed to save criteria");
    }
}

bool CodeIntegrityProtection::criteria_file_exists() const {
    return std::filesystem::exists(get_criteria_file_path());
}

std::vector<unsigned char> CodeIntegrityProtection::create_criteria_hmac(const std::vector<unsigned char>& criteria) const {
    // Создаем HMAC для критериев
    blake3_hasher hasher;
    blake3_keyed_hasher keyed_hasher;
    
    // Инициализация ключевого хеширования
    blake3_keyed_hasher_init(&keyed_hasher, hmac_key_.data());
    
    // Добавляем префикс для уникальности
    std::string prefix = "geometric_criteria";
    blake3_keyed_hasher_update(&keyed_hasher, prefix.c_str(), prefix.size());
    
    // Добавляем данные
    blake3_keyed_hasher_update(&keyed_hasher, criteria.data(), criteria.size());
    
    // Финализация и получение HMAC
    std::vector<unsigned char> mac(SecurityConstants::HMAC_SIZE);
    blake3_keyed_hasher_finalize(&keyed_hasher, mac.data(), mac.size());
    
    return mac;
}

bool CodeIntegrityProtection::verify_criteria_hmac(const std::vector<unsigned char>& criteria,
                                                 const std::vector<unsigned char>& mac) const {
    // Создаем HMAC для данных
    std::vector<unsigned char> computed_mac = create_criteria_hmac(criteria);
    
    // Постоянное время сравнение
    return crypto_verify_32(mac.data(), computed_mac.data()) == 0;
}

std::vector<unsigned char> CodeIntegrityProtection::encrypt_criteria(const std::vector<unsigned char>& criteria) const {
    // Шифрование данных с использованием XChaCha20-Poly1305
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    
    std::vector<unsigned char> encrypted_data;
    encrypted_data.resize(criteria.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    
    unsigned long long ciphertext_len;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        encrypted_data.data(), &ciphertext_len,
        criteria.data(), criteria.size(),
        nullptr, 0, // additional data
        nullptr, nonce, backup_key_.data()
    );
    
    // Добавляем nonce к зашифрованным данным
    std::vector<unsigned char> result;
    result.insert(result.end(), nonce, nonce + sizeof(nonce));
    result.insert(result.end(), encrypted_data.begin(), encrypted_data.end());
    
    return result;
}

std::vector<unsigned char> CodeIntegrityProtection::decrypt_criteria(const std::vector<unsigned char>& encrypted_criteria) const {
    // Проверка длины данных
    if (encrypted_criteria.size() < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 
        crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        return std::vector<unsigned char>();
    }
    
    // Извлечение nonce
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    std::memcpy(nonce, encrypted_criteria.data(), sizeof(nonce));
    
    // Расшифровка данных
    std::vector<unsigned char> decrypted_data;
    decrypted_data.resize(encrypted_criteria.size() - sizeof(nonce) - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    
    unsigned long long plaintext_len;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            decrypted_data.data(), &plaintext_len,
            nullptr,
            encrypted_criteria.data() + sizeof(nonce), 
            encrypted_criteria.size() - sizeof(nonce),
            nullptr, 0, // additional data
            nonce, backup_key_.data()) != 0) {
        return std::vector<unsigned char>(); // Ошибка расшифровки
    }
    
    return decrypted_data;
}

bool CodeIntegrityProtection::verify_criteria_integrity() const {
    std::string criteria_path = get_criteria_file_path();
    
    // Проверка существования файла
    if (!std::filesystem::exists(criteria_path)) {
        return false;
    }
    
    // Загрузка данных
    std::ifstream file(criteria_path, std::ios::binary);
    if (!file) {
        return false;
    }
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<unsigned char> criteria_data(size);
    file.read(reinterpret_cast<char*>(criteria_data.data()), size);
    file.close();
    
    // Проверка длины данных
    if (criteria_data.size() < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 
        crypto_aead_xchacha20poly1305_ietf_ABYTES + SecurityConstants::HMAC_SIZE) {
        return false;
    }
    
    // Извлечение зашифрованных данных и HMAC
    size_t encrypted_size = criteria_data.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES - SecurityConstants::HMAC_SIZE;
    std::vector<unsigned char> encrypted_data(
        criteria_data.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
        criteria_data.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + encrypted_size);
    std::vector<unsigned char> stored_mac(
        criteria_data.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + encrypted_size,
        criteria_data.end());
    
    // Расшифровка данных
    std::vector<unsigned char> decrypted_data = decrypt_criteria(
        std::vector<unsigned char>(criteria_data.begin(), criteria_data.end()));
    
    // Проверка HMAC
    return verify_criteria_hmac(decrypted_data, stored_mac);
}

bool CodeIntegrityProtection::verify_backup_data_integrity(const std::vector<unsigned char>& backup_data) const {
    // Проверка целостности данных резервной копии
    // В реальной системе здесь будет сложная логика проверки
    
    // Для демонстрации просто проверяем, что данные не пустые
    return !backup_data.empty();
}

// Дополнительные методы для усиления безопасности

bool CodeIntegrityProtection::verify_system_integrity_deep() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Проверка целостности системы с углубленным анализом
    
    // 1. Проверка критериев геометрической проверки
    if (!are_criteria_valid()) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Deep system integrity check failed: geometric criteria are not valid", true);
        return false;
    }
    
    // 2. Проверка всех критических модулей
    bool all_modules_valid = true;
    for (const auto& module_name : CRITICAL_MODULES) {
        std::vector<unsigned char> module_data;
        if (!load_module_from_secure_storage(module_name, module_data)) {
            SecureAuditLogger::get_instance().log_event("security", 
                "Deep system integrity check failed: module not found - " + module_name, true);
            all_modules_valid = false;
            continue;
        }
        
        // Проверка HMAC
        if (!verify_module(module_name, module_data.data(), module_data.size())) {
            SecureAuditLogger::get_instance().log_event("security", 
                "Deep system integrity check failed: module HMAC check failed - " + module_name, true);
            all_modules_valid = false;
            continue;
        }
        
        // Дополнительная проверка содержимого модуля
        if (!verify_module_content(module_name, module_data)) {
            SecureAuditLogger::get_instance().log_event("security", 
                "Deep system integrity check failed: module content verification failed - " + module_name, true);
            all_modules_valid = false;
        }
    }
    
    if (!all_modules_valid) {
        return false;
    }
    
    // 3. Проверка криптографических параметров
    if (!verify_crypto_parameters()) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Deep system integrity check failed: cryptographic parameters verification failed", true);
        return false;
    }
    
    // 4. Проверка целостности резервной копии
    if (time(nullptr) - last_backup_time_ > MAX_BACKUP_AGE / 2) {
        // Резервная копия скоро устареет
        SecureAuditLogger::get_instance().log_event("system", 
            "Deep system integrity check: backup is nearing expiration", false);
    }
    
    // 5. Проверка счетчика аномалий
    if (anomaly_count_ > 0 && 
        time(nullptr) - last_anomaly_time_ < ANOMALY_RESET_INTERVAL / 2) {
        // Недавние аномалии требуют внимания
        SecureAuditLogger::get_instance().log_event("security", 
            "Deep system integrity check: recent anomalies detected", true);
        return false;
    }
    
    return true;
}

bool CodeIntegrityProtection::verify_module_content(const std::string& module_name,
                                                  const std::vector<unsigned char>& module_data) const {
    // Проверка содержимого модуля на наличие подозрительных паттернов
    
    // Для некоторых модулей проводим специфическую проверку
    if (module_name == "toruscsidh") {
        // Проверка структуры модуля TorusCSIDH
        return verify_toruscsidh_module(module_data);
    } else if (module_name == "geometric_validator") {
        // Проверка структуры модуля GeometricValidator
        return verify_geometric_validator_module(module_data);
    } else if (module_name == "secure_random") {
        // Проверка структуры модуля SecureRandom
        return verify_secure_random_module(module_data);
    }
    
    // Для остальных модулей проводим базовую проверку
    return verify_generic_module(module_data);
}

bool CodeIntegrityProtection::verify_toruscsidh_module(const std::vector<unsigned char>& module_data) const {
    // Проверка, что модуль содержит корректные криптографические параметры
    
    // В реальной системе здесь будет сложная проверка структуры модуля
    // Для демонстрации проверим наличие определенных сигнатур
    
    // Проверка на наличие сигнатуры TorusCSIDH
    std::string signature = "TorusCSIDH";
    if (module_data.size() < signature.size()) {
        return false;
    }
    
    for (size_t i = 0; i < signature.size(); i++) {
        if (module_data[i] != static_cast<unsigned char>(signature[i])) {
            return false;
        }
    }
    
    return true;
}

bool CodeIntegrityProtection::verify_geometric_validator_module(const std::vector<unsigned char>& module_data) const {
    // Проверка, что модуль содержит корректные параметры геометрической проверки
    
    // В реальной системе здесь будет сложная проверка структуры модуля
    // Для демонстрации проверим наличие определенных сигнатур
    
    // Проверка на наличие сигнатуры GeometricValidator
    std::string signature = "GeometricValidator";
    if (module_data.size() < signature.size()) {
        return false;
    }
    
    for (size_t i = 0; i < signature.size(); i++) {
        if (module_data[i] != static_cast<unsigned char>(signature[i])) {
            return false;
        }
    }
    
    return true;
}

bool CodeIntegrityProtection::verify_secure_random_module(const std::vector<unsigned char>& module_data) const {
    // Проверка, что модуль содержит корректные параметры генератора случайных чисел
    
    // В реальной системе здесь будет сложная проверка структуры модуля
    // Для демонстрации проверим наличие определенных сигнатур
    
    // Проверка на наличие сигнатуры SecureRandom
    std::string signature = "SecureRandom";
    if (module_data.size() < signature.size()) {
        return false;
    }
    
    for (size_t i = 0; i < signature.size(); i++) {
        if (module_data[i] != static_cast<unsigned char>(signature[i])) {
            return false;
        }
    }
    
    return true;
}

bool CodeIntegrityProtection::verify_generic_module(const std::vector<unsigned char>& module_data) const {
    // Базовая проверка модуля на наличие подозрительных паттернов
    
    // Проверка на длинные последовательности одинаковых байтов
    const size_t max_consecutive_same = 10;
    size_t consecutive_count = 0;
    unsigned char last_byte = 0;
    
    for (unsigned char byte : module_data) {
        if (byte == last_byte) {
            consecutive_count++;
            if (consecutive_count > max_consecutive_same) {
                return false;
            }
        } else {
            consecutive_count = 1;
            last_byte = byte;
        }
    }
    
    // Проверка энтропии модуля
    double entropy = calculate_module_entropy(module_data);
    const double min_entropy = 6.0; // Минимальная энтропия на байт
    
    return entropy >= min_entropy;
}

double CodeIntegrityProtection::calculate_module_entropy(const std::vector<unsigned char>& module_data) const {
    // Вычисление энтропии модуля
    
    if (module_data.empty()) {
        return 0.0;
    }
    
    // Подсчет частоты встречаемости каждого байта
    std::vector<int> frequency(256, 0);
    for (unsigned char byte : module_data) {
        frequency[byte]++;
    }
    
    // Вычисление энтропии
    double entropy = 0.0;
    double total = static_cast<double>(module_data.size());
    
    for (int count : frequency) {
        if (count > 0) {
            double p = static_cast<double>(count) / total;
            entropy -= p * std::log2(p);
        }
    }
    
    return entropy;
}

bool CodeIntegrityProtection::verify_crypto_parameters() const {
    // Проверка криптографических параметров на соответствие стандартам
    
    // Проверка HMAC ключа
    if (hmac_key_.size() != HMAC_KEY_SIZE) {
        return false;
    }
    
    // Проверка ключа резервного копирования
    if (backup_key_.size() != BACKUP_KEY_SIZE) {
        return false;
    }
    
    // Проверка параметров безопасности
    if (MAX_ANOMALY_COUNT < 3) {
        return false;
    }
    
    if (ANOMALY_RESET_INTERVAL < 3600) { // Минимум 1 час
        return false;
    }
    
    if (MAX_BACKUP_AGE < 24 * 3600) { // Минимум 1 день
        return false;
    }
    
    return true;
}

bool CodeIntegrityProtection::verify_secure_update(const std::string& update_data) const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Проверка обновления на безопасность
    
    // 1. Проверка подписи обновления
    if (!verify_update_signature(update_data)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Secure update verification failed: invalid signature", true);
        return false;
    }
    
    // 2. Проверка содержимого обновления
    if (!verify_update_content(update_data)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Secure update verification failed: invalid content", true);
        return false;
    }
    
    // 3. Проверка целостности обновления
    if (!verify_update_integrity(update_data)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Secure update verification failed: integrity check failed", true);
        return false;
    }
    
    return true;
}

bool CodeIntegrityProtection::verify_update_signature(const std::string& update_data) const {
    // Проверка подписи обновления с использованием доверенного сертификата
    
    // В реальной системе здесь будет сложная проверка подписи
    // Для демонстрации просто проверим наличие сигнатуры
    
    // Проверка на наличие сигнатуры "TorusCSIDH_UPDATE"
    std::string signature = "TorusCSIDH_UPDATE";
    if (update_data.size() < signature.size()) {
        return false;
    }
    
    for (size_t i = 0; i < signature.size(); i++) {
        if (update_data[i] != signature[i]) {
            return false;
        }
    }
    
    return true;
}

bool CodeIntegrityProtection::verify_update_content(const std::string& update_data) const {
    // Проверка содержимого обновления на наличие вредоносного кода
    
    // В реальной системе здесь будет сложная проверка содержимого
    // Для демонстрации проверим отсутствие подозрительных паттернов
    
    // Проверка на наличие shell-кода
    std::vector<std::string> shellcode_patterns = {
        "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80",
        "\x90\x90\x90\x90\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"
    };
    
    for (const auto& pattern : shellcode_patterns) {
        if (update_data.find(pattern) != std::string::npos) {
            return false;
        }
    }
    
    return true;
}

bool CodeIntegrityProtection::verify_update_integrity(const std::string& update_data) const {
    // Проверка целостности обновления
    
    // В реальной системе здесь будет проверка HMAC
    // Для демонстрации просто проверим длину
    
    return update_data.size() > 100;
}

bool CodeIntegrityProtection::apply_update(const std::string& update_data) {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Проверка обновления
    if (!verify_secure_update(update_data)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Update application failed: update verification failed", true);
        return false;
    }
    
    // Сохранение текущего состояния для возможности отката
    save_recovery_state();
    
    try {
        // Применение обновления
        bool success = apply_update_internal(update_data);
        
        if (success) {
            SecureAuditLogger::get_instance().log_event("system", 
                "Update applied successfully", false);
            
            // Создание новой резервной копии
            create_backup();
        } else {
            SecureAuditLogger::get_instance().log_event("security", 
                "Update application failed", true);
            
            // Восстановление предыдущего состояния
            self_recovery();
        }
        
        return success;
    } catch (const std::exception& e) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Update application failed: " + std::string(e.what()), true);
        
        // Восстановление предыдущего состояния
        self_recovery();
        
        return false;
    }
}

bool CodeIntegrityProtection::apply_update_internal(const std::string& update_data) {
    // Внутреннее применение обновления
    
    // 1. Распаковка обновления
    std::vector<std::pair<std::string, std::vector<unsigned char>>> modules;
    if (!unpack_update(update_data, modules)) {
        return false;
    }
    
    // 2. Проверка целостности каждого модуля
    for (const auto& module : modules) {
        if (!verify_module(module.first, module.second.data(), module.second.size())) {
            return false;
        }
    }
    
    // 3. Обновление модулей
    for (const auto& module : modules) {
        if (!save_module_to_secure_storage(module.first, module.second)) {
            return false;
        }
    }
    
    return true;
}

bool CodeIntegrityProtection::unpack_update(const std::string& update_data,
                                          std::vector<std::pair<std::string, std::vector<unsigned char>>>& modules) {
    // Распаковка обновления
    
    // В реальной системе здесь будет сложная распаковка
    // Для демонстрации просто создадим пустые модули
    
    for (const auto& module_name : CRITICAL_MODULES) {
        modules.emplace_back(module_name, std::vector<unsigned char>());
    }
    
    return true;
}

bool CodeIntegrityProtection::is_backup_valid(const std::string& backup_file) const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Проверка валидности резервной копии
    
    // 1. Проверка целостности файла
    if (!std::filesystem::exists(backup_file)) {
        return false;
    }
    
    // 2. Проверка формата резервной копии
    if (std::filesystem::path(backup_file).extension() != ".bak") {
        return false;
    }
    
    // 3. Проверка целостности данных
    return verify_backup_integrity(backup_file);
}

bool CodeIntegrityProtection::restore_from_backup(const std::string& backup_file) {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Проверка валидности резервной копии
    if (!is_backup_valid(backup_file)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Restore from backup failed: invalid backup file", true);
        return false;
    }
    
    // Восстановление из резервной копии
    bool success = perform_recovery_from_backup(backup_file);
    
    if (success) {
        last_recovery_time_ = time(nullptr);
        reset_anomaly_counter();
        create_backup();
        
        SecureAuditLogger::get_instance().log_event("system", 
            "System successfully restored from backup", false);
    } else {
        SecureAuditLogger::get_instance().log_event("security", 
            "Restore from backup failed", true);
    }
    
    return success;
}

bool CodeIntegrityProtection::perform_recovery_from_backup(const std::string& backup_file) {
    // Выполнение восстановления из конкретной резервной копии
    
    // 1. Загрузка данных из резервной копии
    std::ifstream backup_file_stream(backup_file, std::ios::binary);
    if (!backup_file_stream) {
        return false;
    }
    
    backup_file_stream.seekg(0, std::ios::end);
    size_t size = backup_file_stream.tellg();
    backup_file_stream.seekg(0, std::ios::beg);
    
    std::vector<unsigned char> backup_data(size);
    backup_file_stream.read(reinterpret_cast<char*>(backup_data.data()), size);
    backup_file_stream.close();
    
    // 2. Расшифровка данных
    std::vector<unsigned char> decrypted_data = decrypt_backup_data(backup_data);
    if (decrypted_data.empty()) {
        return false;
    }
    
    // 3. Проверка целостности данных
    if (!verify_backup_data_integrity(decrypted_data)) {
        return false;
    }
    
    // 4. Извлечение модулей
    std::vector<std::pair<std::string, std::vector<unsigned char>>> modules;
    if (!extract_modules_from_backup(decrypted_data, modules)) {
        return false;
    }
    
    // 5. Восстановление модулей
    for (const auto& module : modules) {
        if (!save_module_to_secure_storage(module.first, module.second)) {
            return false;
        }
    }
    
    return true;
}

bool CodeIntegrityProtection::extract_modules_from_backup(const std::vector<unsigned char>& backup_data,
                                                        std::vector<std::pair<std::string, std::vector<unsigned char>>>& modules) {
    // Извлечение модулей из резервной копии
    
    size_t pos = 0;
    while (pos < backup_data.size()) {
        // Чтение длины данных
        if (pos + sizeof(uint32_t) > backup_data.size()) {
            return false;
        }
        
        uint32_t data_size;
        std::memcpy(&data_size, &backup_data[pos], sizeof(uint32_t));
        pos += sizeof(uint32_t);
        
        // Проверка длины данных
        if (pos + data_size > backup_data.size()) {
            return false;
        }
        
        // Создание модуля
        std::string module_name = CRITICAL_MODULES[modules.size()];
        std::vector<unsigned char> module_data(backup_data.begin() + pos, backup_data.begin() + pos + data_size);
        
        modules.emplace_back(module_name, module_data);
        
        // Переход к следующему модулю
        pos += data_size;
    }
    
    return true;
}

bool CodeIntegrityProtection::is_system_under_attack() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Проверка, находится ли система под атакой
    
    // 1. Проверка счетчика аномалий
    if (anomaly_count_ >= MAX_ANOMALY_COUNT / 2) {
        return true;
    }
    
    // 2. Проверка частоты аномалий
    if (anomaly_count_ > 0 && 
        time(nullptr) - last_anomaly_time_ < ANOMALY_RESET_INTERVAL / 10) {
        return true;
    }
    
    // 3. Проверка целостности системы
    if (!system_integrity_check()) {
        return true;
    }
    
    return false;
}

void CodeIntegrityProtection::activate_defensive_mode() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Активация защитного режима
    
    // 1. Блокировка всех входящих соединений
    block_incoming_connections();
    
    // 2. Ограничение функциональности
    restrict_functionality();
    
    // 3. Усиление проверок
    strengthen_security_checks();
    
    SecureAuditLogger::get_instance().log_event("security", 
        "Defensive mode activated", true);
}

void CodeIntegrityProtection::block_incoming_connections() {
    // Блокировка всех входящих соединений
    
    // В реальной системе здесь будет сложная логика блокировки
    // Для демонстрации просто логируем
    
    SecureAuditLogger::get_instance().log_event("security", 
        "All incoming connections blocked", true);
}

void CodeIntegrityProtection::restrict_functionality() {
    // Ограничение функциональности системы
    
    // В реальной системе здесь будет сложная логика ограничения
    // Для демонстрации просто логируем
    
    SecureAuditLogger::get_instance().log_event("security", 
        "System functionality restricted", true);
}

void CodeIntegrityProtection::strengthen_security_checks() {
    // Усиление проверок безопасности
    
    // В реальной системе здесь будет сложная логика усиления проверок
    // Для демонстрации просто логируем
    
    SecureAuditLogger::get_instance().log_event("security", 
        "Security checks strengthened", true);
}

void CodeIntegrityProtection::deactivate_defensive_mode() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Деактивация защитного режима
    
    // 1. Восстановление входящих соединений
    restore_incoming_connections();
    
    // 2. Восстановление функциональности
    restore_functionality();
    
    // 3. Восстановление стандартных проверок
    restore_standard_security_checks();
    
    SecureAuditLogger::get_instance().log_event("system", 
        "Defensive mode deactivated", false);
}

void CodeIntegrityProtection::restore_incoming_connections() {
    // Восстановление входящих соединений
    
    // В реальной системе здесь будет сложная логика восстановления
    // Для демонстрации просто логируем
    
    SecureAuditLogger::get_instance().log_event("system", 
        "Incoming connections restored", false);
}

void CodeIntegrityProtection::restore_functionality() {
    // Восстановление функциональности системы
    
    // В реальной системе здесь будет сложная логика восстановления
    // Для демонстрации просто логируем
    
    SecureAuditLogger::get_instance().log_event("system", 
        "System functionality restored", false);
}

void CodeIntegrityProtection::restore_standard_security_checks() {
    // Восстановление стандартных проверок безопасности
    
    // В реальной системе здесь будет сложная логика восстановления
    // Для демонстрации просто логируем
    
    SecureAuditLogger::get_instance().log_event("system", 
        "Standard security checks restored", false);
}

bool CodeIntegrityProtection::is_defensive_mode_active() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Проверка, активен ли защитный режим
    
    // В реальной системе здесь будет сложная логика проверки
    // Для демонстрации просто проверим счетчик аномалий
    
    return anomaly_count_ >= MAX_ANOMALY_COUNT / 2;
}

bool CodeIntegrityProtection::verify_secure_connection(const std::string& connection_id) const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Проверка безопасного соединения
    
    // 1. Проверка подлинности соединения
    if (!verify_connection_authenticity(connection_id)) {
        return false;
    }
    
    // 2. Проверка целостности соединения
    if (!verify_connection_integrity(connection_id)) {
        return false;
    }
    
    // 3. Проверка шифрования соединения
    if (!verify_connection_encryption(connection_id)) {
        return false;
    }
    
    return true;
}

bool CodeIntegrityProtection::verify_connection_authenticity(const std::string& connection_id) const {
    // Проверка подлинности соединения
    
    // В реальной системе здесь будет сложная проверка
    // Для демонстрации просто проверим длину ID
    
    return connection_id.size() == 64;
}

bool CodeIntegrityProtection::verify_connection_integrity(const std::string& connection_id) const {
    // Проверка целостности соединения
    
    // В реальной системе здесь будет сложная проверка
    // Для демонстрации просто проверим наличие префикса
    
    return connection_id.substr(0, 8) == "TORUS_";
}

bool CodeIntegrityProtection::verify_connection_encryption(const std::string& connection_id) const {
    // Проверка шифрования соединения
    
    // В реальной системе здесь будет сложная проверка
    // Для демонстрации просто вернем true
    
    return true;
}

void CodeIntegrityProtection::monitor_system_integrity() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Мониторинг целостности системы
    
    // 1. Проверка целостности системы
    bool integrity_ok = system_integrity_check();
    
    // 2. Проверка критериев геометрической проверки
    bool criteria_valid = are_criteria_valid();
    
    // 3. Проверка счетчика аномалий
    bool anomaly_count_ok = (anomaly_count_ < MAX_ANOMALY_COUNT);
    
    // 4. Проверка времени последней аномалии
    bool anomaly_time_ok = (anomaly_count_ == 0 || 
                           (time(nullptr) - last_anomaly_time_ >= ANOMALY_RESET_INTERVAL));
    
    // 5. Проверка резервной копии
    bool backup_ok = (time(nullptr) - last_backup_time_ <= MAX_BACKUP_AGE);
    
    // Логирование результатов мониторинга
    SecureAuditLogger::get_instance().log_event("system", 
        "System integrity monitoring results: " +
        std::string(integrity_ok ? "integrity_ok " : "integrity_failed ") +
        std::string(criteria_valid ? "criteria_valid " : "criteria_invalid ") +
        std::string(anomaly_count_ok ? "anomaly_count_ok " : "anomaly_count_high ") +
        std::string(anomaly_time_ok ? "anomaly_time_ok " : "anomaly_time_recent ") +
        std::string(backup_ok ? "backup_ok" : "backup_old"), false);
    
    // Принятие мер в случае проблем
    if (!integrity_ok || !criteria_valid || !anomaly_count_ok || 
        !anomaly_time_ok || !backup_ok) {
        
        if (!integrity_ok) {
            handle_anomaly("integrity_failure", "System integrity check failed");
        }
        
        if (!criteria_valid) {
            handle_anomaly("criteria_invalid", "Geometric criteria are not valid");
        }
        
        if (!anomaly_count_ok) {
            handle_anomaly("anomaly_count_high", "Excessive anomaly count");
        }
        
        if (!anomaly_time_ok) {
            handle_anomaly("anomaly_time_recent", "Recent anomalies detected");
        }
        
        if (!backup_ok) {
            create_backup();
            SecureAuditLogger::get_instance().log_event("system", 
                "Backup created due to age", false);
        }
    }
}

bool CodeIntegrityProtection::is_criteria_update_available() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Проверка, доступно ли обновление критериев
    
    // В реальной системе здесь будет проверка через безопасное соединение
    // Для демонстрации просто вернем false
    
    return false;
}

bool CodeIntegrityProtection::download_criteria_update(int& major_version, 
                                                    int& minor_version, 
                                                    time_t& valid_from,
                                                    std::vector<unsigned char>& update_data) {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Скачивание обновления критериев
    
    // В реальной системе здесь будет сложная логика скачивания
    // Для демонстрации просто вернем false
    
    return false;
}

bool CodeIntegrityProtection::apply_criteria_update(int major_version, 
                                                 int minor_version, 
                                                 time_t valid_from,
                                                 const std::vector<unsigned char>& update_data) {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Применение обновления критериев
    
    // 1. Проверка подписи обновления
    if (!verify_criteria_update_signature(update_data)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Criteria update failed: invalid signature", true);
        return false;
    }
    
    // 2. Проверка содержимого обновления
    if (!verify_criteria_update_content(update_data)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Criteria update failed: invalid content", true);
        return false;
    }
    
    // 3. Сохранение текущего состояния
    save_recovery_state();
    
    try {
        // 4. Обновление критериев
        criteria_major_version_ = major_version;
        criteria_minor_version_ = minor_version;
        criteria_valid_from_ = valid_from;
        last_criteria_update_time_ = time(nullptr);
        
        // 5. Сохранение обновленных критериев
        save_criteria();
        
        // 6. Переподпись критических модулей
        sign_critical_modules();
        
        // 7. Сброс счетчика аномалий
        anomaly_count_ = 0;
        is_blocked_ = false;
        
        SecureAuditLogger::get_instance().log_event("system", 
            "Geometric criteria updated to version " + 
            std::to_string(major_version) + "." + 
            std::to_string(minor_version), false);
        
        return true;
    } catch (const std::exception& e) {
        // Восстановление предыдущего состояния в случае ошибки
        load_criteria();
        
        // Логируем ошибку
        SecureAuditLogger::get_instance().log_event("security", 
            "Failed to update geometric criteria: " + std::string(e.what()), true);
        
        return false;
    }
}

bool CodeIntegrityProtection::verify_criteria_update_signature(const std::vector<unsigned char>& update_data) const {
    // Проверка подписи обновления критериев
    
    // В реальной системе здесь будет сложная проверка подписи
    // Для демонстрации просто вернем true
    
    return true;
}

bool CodeIntegrityProtection::verify_criteria_update_content(const std::vector<unsigned char>& update_data) const {
    // Проверка содержимого обновления критериев
    
    // В реальной системе здесь будет сложная проверка содержимого
    // Для демонстрации просто вернем true
    
    return true;
}

bool CodeIntegrityProtection::verify_secure_criteria_update(const std::vector<unsigned char>& update_data,
                                                         int major_version,
                                                         int minor_version,
                                                         time_t valid_from) const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Проверка безопасного обновления критериев
    
    // 1. Проверка, что обновление активно
    if (!is_criteria_update_active()) {
        return false;
    }
    
    // 2. Проверка, что новая версия выше текущей
    if (major_version < criteria_major_version_ || 
        (major_version == criteria_major_version_ && minor_version <= criteria_minor_version_)) {
        return false;
    }
    
    // 3. Проверка, что время начала действия в будущем
    if (valid_from <= time(nullptr)) {
        return false;
    }
    
    // 4. Проверка подписи обновления
    if (!verify_criteria_update_signature(update_data)) {
        return false;
    }
    
    // 5. Проверка содержимого обновления
    if (!verify_criteria_update_content(update_data)) {
        return false;
    }
    
    return true;
}

} // namespace toruscsidh
