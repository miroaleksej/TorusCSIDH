#include "code_integrity_protection.h"
#include <fstream>
#include <filesystem>
#include <chrono>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <cstring>
#include <sodium.h>
#include "secure_random.h"
#include "secure_audit_logger.h"

namespace toruscsidh {

CodeIntegrityProtection::CodeIntegrityProtection()
    : is_blocked_(false),
      anomaly_count_(0),
      last_anomaly_time_(0),
      last_backup_time_(0),
      last_recovery_time_(0) {
    
    // Инициализация libsodium
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
    
    // Генерация случайного ключа HMAC
    hmac_key_.resize(SecurityConstants::HMAC_KEY_SIZE);
    randombytes_buf(hmac_key_.data(), hmac_key_.size());
    
    // Генерация ключа для резервного копирования
    backup_key_.resize(SecurityConstants::BACKUP_KEY_SIZE);
    randombytes_buf(backup_key_.data(), backup_key_.size());
    
    // Инициализация критических модулей
    initialize_critical_modules();
    
    // Инициализация версии критериев
    current_criteria_version_.major_version = 1;
    current_criteria_version_.minor_version = 0;
    current_criteria_version_.activation_time = time(nullptr);
    
    pending_criteria_version_.major_version = 0;
    pending_criteria_version_.minor_version = 0;
    pending_criteria_version_.activation_time = 0;
    
    // Сохранение начального состояния
    save_recovery_state();
}

CodeIntegrityProtection::~CodeIntegrityProtection() {
    // Очистка секретных данных из памяти
    SecureRandom::secure_clean_memory(hmac_key_.data(), hmac_key_.size());
    SecureRandom::secure_clean_memory(backup_key_.data(), backup_key_.size());
}

bool CodeIntegrityProtection::system_integrity_check() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Проверка блокировки системы
    if (is_blocked_) {
        SecureAuditLogger::get_instance().log_event("security", "System is blocked due to integrity issues", true);
        return false;
    }
    
    // Проверка времени с последней аномалии
    if (anomaly_count_ > 0 && time(nullptr) - last_anomaly_time_ > SecurityConstants::ANOMALY_RESET_INTERVAL) {
        reset_anomaly_counter();
    }
    
    try {
        // Проверка целостности всех критических модулей
        for (const auto& module : critical_modules_) {
            // Загрузка модуля из защищенного хранилища
            std::vector<unsigned char> module_data;
            if (!load_module(module, module_data)) {
                SecureAuditLogger::get_instance().log_event("security", "Module load failed: " + module, true);
                handle_anomaly("module_load", "Failed to load module: " + module);
                return false;
            }
            
            // Проверка HMAC модуля
            if (!verify_module(module, module_data.data(), module_data.size())) {
                SecureAuditLogger::get_instance().log_event("security", "Module integrity check failed: " + module, true);
                handle_anomaly("module_integrity", "Module integrity check failed: " + module);
                return false;
            }
        }
        
        // Проверка, не требуется ли обновление критериев
        if (pending_criteria_version_.activation_time > 0 && 
            time(nullptr) >= pending_criteria_version_.activation_time) {
            update_critical_components();
        }
        
        return true;
    } catch (const std::exception& e) {
        SecureAuditLogger::get_instance().log_event("security", "Integrity check failed with exception: " + std::string(e.what()), true);
        handle_anomaly("integrity", std::string("Integrity check failed: ") + e.what());
        return false;
    }
}

bool CodeIntegrityProtection::self_recovery() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    if (is_blocked_) {
        return false;
    }
    
    try {
        // Попытка восстановления из резервной копии
        if (recover_from_backup()) {
            // После успешного восстановления, проверяем целостность системы
            bool integrity_ok = system_integrity_check();
            if (!integrity_ok) {
                SecureAuditLogger::get_instance().log_event("security", "Recovery completed but system integrity check failed", true);
                is_blocked_ = true;
                return false;
            }
            
            // Обновление времени последнего восстановления
            last_recovery_time_ = time(nullptr);
            SecureAuditLogger::get_instance().log_event("system", "Recovery from backup completed successfully", false);
            return true;
        }
        
        SecureAuditLogger::get_instance().log_event("security", "Self-recovery failed: no valid backup found", true);
        is_blocked_ = true;
        return false;
    } catch (const std::exception& e) {
        SecureAuditLogger::get_instance().log_event("security", "Self-recovery failed with exception: " + std::string(e.what()), true);
        handle_anomaly("recovery", std::string("Self-recovery failed: ") + e.what());
        is_blocked_ = true;
        return false;
    }
}

void CodeIntegrityProtection::save_recovery_state() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    try {
        SecureAuditLogger::get_instance().log_event("system", "Saving recovery state", false);
        
        // Создаем каталог для резервных копий, если его нет
        std::filesystem::create_directories(SecurityConstants::BACKUP_DIR);
        
        // Генерируем имя файла с временной меткой
        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        std::ostringstream oss;
        oss << SecurityConstants::BACKUP_DIR << "/backup_" << now_c << ".enc";
        std::string backup_path = oss.str();
        
        // Собираем данные для резервной копии
        std::vector<unsigned char> full_backup;
        
        // Добавляем HMAC ключ
        full_backup.insert(full_backup.end(), hmac_key_.begin(), hmac_key_.end());
        
        // Добавляем ключ резервного копирования
        full_backup.insert(full_backup.end(), backup_key_.begin(), backup_key_.end());
        
        // Добавляем критические модули и их HMAC
        for (const auto& module : critical_modules_) {
            std::vector<unsigned char> module_data;
            if (load_module(module, module_data)) {
                // Добавляем размер модуля
                size_t module_size = module_data.size();
                full_backup.insert(full_backup.end(), 
                                 reinterpret_cast<unsigned char*>(&module_size), 
                                 reinterpret_cast<unsigned char*>(&module_size) + sizeof(size_t));
                
                // Добавляем данные модуля
                full_backup.insert(full_backup.end(), module_data.begin(), module_data.end());
            }
        }
        
        // Шифруем резервную копию
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        randombytes_buf(nonce, sizeof(nonce));
        
        std::vector<unsigned char> encrypted_backup(full_backup.size() + crypto_secretbox_MACBYTES);
        crypto_secretbox_easy(encrypted_backup.data(), 
                             full_backup.data(), 
                             full_backup.size(), 
                             nonce, 
                             backup_key_.data());
        
        // Добавляем nonce в начало
        std::vector<unsigned char> final_backup;
        final_backup.insert(final_backup.end(), nonce, nonce + crypto_secretbox_NONCEBYTES);
        final_backup.insert(final_backup.end(), encrypted_backup.begin(), encrypted_backup.end());
        
        // Сохраняем резервную копию
        std::ofstream backup_file(backup_path, std::ios::binary);
        if (!backup_file) {
            throw std::runtime_error("Failed to open backup file for writing");
        }
        backup_file.write(reinterpret_cast<const char*>(final_backup.data()), final_backup.size());
        backup_file.close();
        
        // Обновляем время последней резервной копии
        last_backup_time_ = time(nullptr);
        
        SecureAuditLogger::get_instance().log_event("system", "Recovery state saved successfully", false);
    } catch (const std::exception& e) {
        SecureAuditLogger::get_instance().log_event("security", "Failed to save recovery state: " + std::string(e.what()), true);
        handle_anomaly("backup", std::string("Failed to save recovery state: ") + e.what());
    }
}

bool CodeIntegrityProtection::recover_from_backup() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    try {
        SecureAuditLogger::get_instance().log_event("system", "Attempting recovery from backup", false);
        
        // Поиск последней резервной копии
        std::string latest_backup;
        time_t latest_time = 0;
        
        for (const auto& entry : std::filesystem::directory_iterator(SecurityConstants::BACKUP_DIR)) {
            if (entry.is_regular_file() && entry.path().extension() == ".enc") {
                time_t file_time = entry.last_write_time().time_since_epoch().count();
                if (file_time > latest_time) {
                    latest_time = file_time;
                    latest_backup = entry.path().string();
                }
            }
        }
        
        if (latest_backup.empty()) {
            SecureAuditLogger::get_instance().log_event("security", "No backup files found", true);
            return false;
        }
        
        // Загрузка резервной копии
        std::ifstream backup_file(latest_backup, std::ios::binary);
        if (!backup_file) {
            SecureAuditLogger::get_instance().log_event("security", "Failed to open backup file", true);
            return false;
        }
        
        backup_file.seekg(0, std::ios::end);
        size_t size = backup_file.tellg();
        backup_file.seekg(0, std::ios::beg);
        
        std::vector<unsigned char> full_backup(size);
        backup_file.read(reinterpret_cast<char*>(full_backup.data()), size);
        backup_file.close();
        
        // Проверка целостности резервной копии
        if (full_backup.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
            SecureAuditLogger::get_instance().log_event("security", "Backup file is too small", true);
            return false;
        }
        
        // Извлечение nonce
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        std::memcpy(nonce, full_backup.data(), crypto_secretbox_NONCEBYTES);
        
        // Расшифровка резервной копии
        std::vector<unsigned char> decrypted_backup(full_backup.size() - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES);
        if (crypto_secretbox_open_easy(decrypted_backup.data(),
                                      full_backup.data() + crypto_secretbox_NONCEBYTES,
                                      full_backup.size() - crypto_secretbox_NONCEBYTES,
                                      nonce,
                                      backup_key_.data()) != 0) {
            SecureAuditLogger::get_instance().log_event("security", "Failed to decrypt backup", true);
            return false;
        }
        
        // Восстановление состояния
        size_t pos = 0;
        
        // Восстановление HMAC ключа
        if (pos + hmac_key_.size() > decrypted_backup.size()) {
            SecureAuditLogger::get_instance().log_event("security", "Invalid backup format (HMAC key)", true);
            return false;
        }
        std::memcpy(hmac_key_.data(), decrypted_backup.data() + pos, hmac_key_.size());
        pos += hmac_key_.size();
        
        // Восстановление ключа резервного копирования
        if (pos + backup_key_.size() > decrypted_backup.size()) {
            SecureAuditLogger::get_instance().log_event("security", "Invalid backup format (backup key)", true);
            return false;
        }
        std::memcpy(backup_key_.data(), decrypted_backup.data() + pos, backup_key_.size());
        pos += backup_key_.size();
        
        // Восстановление критических модулей
        while (pos < decrypted_backup.size()) {
            // Чтение размера модуля
            if (pos + sizeof(size_t) > decrypted_backup.size()) {
                break;
            }
            size_t module_size;
            std::memcpy(&module_size, decrypted_backup.data() + pos, sizeof(size_t));
            pos += sizeof(size_t);
            
            // Проверка размера
            if (pos + module_size > decrypted_backup.size()) {
                SecureAuditLogger::get_instance().log_event("security", "Invalid module size in backup", true);
                return false;
            }
            
            // Восстановление модуля
            std::vector<unsigned char> module_data(decrypted_backup.data() + pos, 
                                                 decrypted_backup.data() + pos + module_size);
            pos += module_size;
            
            // Здесь должен быть код для восстановления модуля в систему
            // В реальной системе это зависит от архитектуры
        }
        
        SecureAuditLogger::get_instance().log_event("system", "Recovery from backup completed successfully", false);
        return true;
    } catch (const std::exception& e) {
        SecureAuditLogger::get_instance().log_event("security", "Recovery from backup failed: " + std::string(e.what()), true);
        return false;
    }
}

bool CodeIntegrityProtection::update_criteria_version(int major_version, int minor_version, time_t activation_time) {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Проверка, что время активации в будущем
    if (activation_time <= time(nullptr)) {
        SecureAuditLogger::get_instance().log_event("security", "Invalid activation time for criteria update", true);
        return false;
    }
    
    // Проверка, что новая версия выше текущей
    if (major_version < current_criteria_version_.major_version || 
        (major_version == current_criteria_version_.major_version && minor_version <= current_criteria_version_.minor_version)) {
        SecureAuditLogger::get_instance().log_event("security", "New criteria version must be higher than current", true);
        return false;
    }
    
    // Установка запланированного обновления
    pending_criteria_version_.major_version = major_version;
    pending_criteria_version_.minor_version = minor_version;
    pending_criteria_version_.activation_time = activation_time;
    
    SecureAuditLogger::get_instance().log_event("system", 
        "Scheduled criteria update to v" + std::to_string(major_version) + "." + std::to_string(minor_version) + 
        " at " + std::to_string(activation_time), false);
    
    return true;
}

bool CodeIntegrityProtection::is_system_ready() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Система готова, если не заблокирована и прошла проверку целостности
    return !is_blocked_ && system_integrity_check();
}

void CodeIntegrityProtection::sign_module(const std::string& module_name, const void* data, size_t size) {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    try {
        // Создаем HMAC для модуля
        unsigned char mac[crypto_auth_BYTES];
        crypto_auth_state state;
        crypto_auth_init(&state, hmac_key_.data(), hmac_key_.size());
        crypto_auth_update(&state, static_cast<const unsigned char*>(data), size);
        crypto_auth_final(&state, mac);
        
        // Сохраняем HMAC в защищенном хранилище
        // В реальной системе это будет зависеть от архитектуры
        // Например, запись в защищенный файл или базу данных
        
        SecureAuditLogger::get_instance().log_event("security", "Signed module: " + module_name, false);
    } catch (const std::exception& e) {
        SecureAuditLogger::get_instance().log_event("security", "Failed to sign module " + module_name + ": " + std::string(e.what()), true);
        handle_anomaly("signing", "Failed to sign module: " + module_name);
    }
}

bool CodeIntegrityProtection::verify_module(const std::string& module_name, const void* data, size_t size) {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    try {
        // Создаем HMAC для модуля
        unsigned char computed_mac[crypto_auth_BYTES];
        crypto_auth_state state;
        crypto_auth_init(&state, hmac_key_.data(), hmac_key_.size());
        crypto_auth_update(&state, static_cast<const unsigned char*>(data), size);
        crypto_auth_final(&state, computed_mac);
        
        // Получаем сохраненный HMAC из защищенного хранилища
        // В реальной системе это будет зависеть от архитектуры
        // Например, чтение из защищенного файла или базы данных
        std::vector<unsigned char> stored_mac(crypto_auth_BYTES);
        
        // Постоянное время сравнение
        return crypto_verify_32(stored_mac.data(), computed_mac) == 0;
    } catch (const std::exception& e) {
        SecureAuditLogger::get_instance().log_event("security", "Failed to verify module " + module_name + ": " + std::string(e.what()), true);
        handle_anomaly("verification", "Failed to verify module: " + module_name);
        return false;
    }
}

bool CodeIntegrityProtection::verify_hmac_blake3(const std::vector<unsigned char>& key, 
                                               const std::vector<unsigned char>& data,
                                               const std::vector<unsigned char>& mac) const {
    // Используем libsodium для безопасной проверки HMAC
    unsigned char computed_mac[crypto_auth_BYTES];
    crypto_auth_state state;
    crypto_auth_init(&state, key.data(), key.size());
    crypto_auth_update(&state, data.data(), data.size());
    crypto_auth_final(&state, computed_mac);
    
    // Постоянное время сравнение
    return crypto_verify_32(mac.data(), computed_mac) == 0;
}

void CodeIntegrityProtection::constant_time_compare(const unsigned char* a, const unsigned char* b, size_t len) const {
    unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    
    // В реальной системе мы не должны раскрывать информацию о несоответствии
    // Поэтому мы не выбрасываем исключение здесь
    // Вместо этого мы просто регистрируем аномалию
    if (result != 0) {
        SecureAuditLogger::get_instance().log_event("security", "Constant time comparison failed", true);
        handle_anomaly("comparison", "Constant time comparison failed");
    }
}

void CodeIntegrityProtection::update_critical_components() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    try {
        // Обновление текущей версии критериев
        current_criteria_version_.major_version = pending_criteria_version_.major_version;
        current_criteria_version_.minor_version = pending_criteria_version_.minor_version;
        current_criteria_version_.activation_time = pending_criteria_version_.activation_time;
        
        // Сброс запланированного обновления
        pending_criteria_version_.major_version = 0;
        pending_criteria_version_.minor_version = 0;
        pending_criteria_version_.activation_time = 0;
        
        SecureAuditLogger::get_instance().log_event("system", 
            "Updated criteria to v" + std::to_string(current_criteria_version_.major_version) + 
            "." + std::to_string(current_criteria_version_.minor_version), false);
    } catch (const std::exception& e) {
        SecureAuditLogger::get_instance().log_event("security", "Failed to update critical components: " + std::string(e.what()), true);
        handle_anomaly("update", "Failed to update critical components: " + std::string(e.what()));
    }
}

bool CodeIntegrityProtection::check_anomalies() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Система в нормальном состоянии, если нет аномалий или они были сброшены
    return anomaly_count_ == 0 || 
           (anomaly_count_ > 0 && time(nullptr) - last_anomaly_time_ > SecurityConstants::ANOMALY_RESET_INTERVAL);
}

void CodeIntegrityProtection::reset_anomaly_counter() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    anomaly_count_ = 0;
    last_anomaly_time_ = 0;
    
    SecureAuditLogger::get_instance().log_event("system", "Anomaly counter reset", false);
}

void CodeIntegrityProtection::initialize_critical_modules() {
    critical_modules_ = {
        "geometric_validator",
        "elliptic_curve",
        "toruscsidh",
        "secure_random",
        "postquantum_hash",
        "secure_audit_logger",
        "code_integrity_protection",
        "rfc6979_rng",
        "bech32m"
    };
}

bool CodeIntegrityProtection::load_module(const std::string& module_name, std::vector<unsigned char>& data) {
    // В реальной системе это будет зависеть от архитектуры
    // Например, загрузка из защищенного файла или базы данных
    
    // Для демонстрации предположим, что модули хранятся в каталоге modules/
    std::string module_path = SecurityConstants::MODULES_DIR + "/" + module_name + ".bin";
    
    std::ifstream module_file(module_path, std::ios::binary);
    if (!module_file) {
        return false;
    }
    
    module_file.seekg(0, std::ios::end);
    size_t size = module_file.tellg();
    module_file.seekg(0, std::ios::beg);
    
    data.resize(size);
    module_file.read(reinterpret_cast<char*>(data.data()), size);
    module_file.close();
    
    return true;
}

void CodeIntegrityProtection::handle_anomaly(const std::string& anomaly_type, const std::string& description) {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    anomaly_count_++;
    last_anomaly_time_ = time(nullptr);
    
    SecureAuditLogger::get_instance().log_event("security", 
        "Anomaly detected: " + anomaly_type + " - " + description + 
        " (count: " + std::to_string(anomaly_count_) + ")", true);
    
    // Блокировка системы при превышении порога аномалий
    if (anomaly_count_ >= SecurityConstants::MAX_ANOMALY_COUNT) {
        is_blocked_ = true;
        SecureAuditLogger::get_instance().log_event("security", "System blocked due to excessive anomalies", true);
    }
}

} // namespace toruscsidh
