#include "code_integrity.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <sodium.h>
#include "secure_audit_logger.h"
#include "secure_random.h"

namespace toruscsidh {

CodeIntegrityProtection::CodeIntegrityProtection()
    : is_blocked_(false),
      anomaly_count_(0),
      last_anomaly_time_(0),
      last_recovery_time_(0),
      current_criteria_major_version_(1),
      current_criteria_minor_version_(0),
      scheduled_criteria_major_version_(-1),
      scheduled_criteria_minor_version_(-1),
      criteria_activation_time_(0) {
    
    // Определение критических модулей
    critical_modules_ = {
        "toruscsidh_core",
        "secure_random",
        "postquantum_hash",
        "rfc6979_rng",
        "elliptic_curve",
        "geometric_validator",
        "code_integrity",
        "secure_audit_logger"
    };
    
    // Инициализация ключа HMAC
    initialize_hmac_key();
    
    // Генерация ключа для резервного копирования
    backup_key_ = SecureRandom::generate_random_bytes(SecurityConstants::BACKUP_KEY_SIZE);
    
    // Генерация публичного ключа системы
    system_public_key_ = SecureRandom::generate_random_bytes(SecurityConstants::SYSTEM_PUBLIC_KEY_SIZE);
    
    // Подпись критических модулей
    sign_critical_modules();
    
    // Сохранение состояния для восстановления
    save_recovery_state();
    
    SecureAuditLogger::get_instance().log_event("system", 
        "CodeIntegrityProtection initialized successfully", false);
}

CodeIntegrityProtection::~CodeIntegrityProtection() {
    // Очистка памяти
    SecureRandom::secure_clean_memory(hmac_key_.data(), hmac_key_.size());
    SecureRandom::secure_clean_memory(backup_key_.data(), backup_key_.size());
    SecureRandom::secure_clean_memory(system_public_key_.data(), system_public_key_.size());
    
    // Очистка HMAC модулей
    for (auto& [module, hmac] : module_hmacs_) {
        SecureRandom::secure_clean_memory(hmac.data(), hmac.size());
    }
    
    SecureAuditLogger::get_instance().log_event("system", 
        "CodeIntegrityProtection destroyed", false);
}

bool CodeIntegrityProtection::system_integrity_check() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Проверка, заблокирована ли система из-за аномалий
    if (is_blocked_) {
        SecureAuditLogger::get_instance().log_event("security",
            "System integrity check failed: system is blocked due to anomalies", true);
        return false;
    }
    
    // Проверка счетчика аномалий
    if (anomaly_count_ > SecurityConstants::MAX_ANOMALY_COUNT) {
        SecureAuditLogger::get_instance().log_event("security",
            "System integrity check failed: anomaly count exceeded", true);
        is_blocked_ = true;
        return false;
    }
    
    // Проверка времени с последней аномалии
    if (anomaly_count_ > 0 && 
        time(nullptr) - last_anomaly_time_ > SecurityConstants::ANOMALY_RESET_INTERVAL) {
        reset_anomaly_counter();
    }
    
    // Проверка целостности системы
    bool integrity_ok = verify_system_integrity();
    
    if (!integrity_ok) {
        handle_anomaly("system_integrity", "System integrity check failed");
    }
    
    return integrity_ok;
}

bool CodeIntegrityProtection::self_recovery() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Проверка, заблокирована ли система из-за аномалий
    if (is_blocked_) {
        SecureAuditLogger::get_instance().log_event("security",
            "Self-recovery failed: system is blocked due to anomalies", true);
        return false;
    }
    
    try {
        // Попытка восстановления из резервной копии
        if (recover_from_backup()) {
            // После успешного восстановления, проверяем целостность системы
            bool integrity_ok = system_integrity_check();
            
            if (integrity_ok) {
                last_recovery_time_ = time(nullptr);
                SecureAuditLogger::get_instance().log_event("system",
                    "System recovered successfully from backup", false);
                return true;
            } else {
                SecureAuditLogger::get_instance().log_event("security",
                    "System recovery failed: integrity check failed after recovery", true);
                return false;
            }
        } else {
            SecureAuditLogger::get_instance().log_event("security",
                "System recovery failed: no valid backup found", true);
            return false;
        }
    } catch (const std::exception& e) {
        SecureAuditLogger::get_instance().log_event("security",
            "System recovery failed: " + std::string(e.what()), true);
        return false;
    }
}

void CodeIntegrityProtection::handle_anomaly(const std::string& anomaly_type, 
                                          const std::string& description) {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Логирование аномалии
    SecureAuditLogger::get_instance().log_event("security",
        "Anomaly detected: " + anomaly_type + " - " + description, true);
    
    // Увеличение счетчика аномалий
    anomaly_count_++;
    last_anomaly_time_ = time(nullptr);
    
    // Проверка, нужно ли блокировать систему
    if (anomaly_count_ > SecurityConstants::MAX_ANOMALY_COUNT) {
        is_blocked_ = true;
        SecureAuditLogger::get_instance().log_event("security",
            "System blocked due to excessive anomalies", true);
    }
}

bool CodeIntegrityProtection::is_blocked() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    return is_blocked_;
}

void CodeIntegrityProtection::reset_anomaly_counter() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    anomaly_count_ = 0;
    last_anomaly_time_ = 0;
}

void CodeIntegrityProtection::save_recovery_state() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    try {
        // Создание директории для резервных копий
        std::filesystem::create_directories("secure_storage/backups");
        
        // Сбор данных для резервной копии
        std::vector<unsigned char> backup_data;
        std::map<std::string, std::vector<unsigned char>> module_hmacs;
        
        // Сначала собираем все модули и вычисляем их HMAC
        for (const auto& module : critical_modules_) {
            // Загрузка модуля
            std::vector<unsigned char> module_data;
            if (!load_module(module, module_data)) {
                throw std::runtime_error("Failed to load module: " + module);
            }
            
            // Вычисляем HMAC для модуля
            module_hmacs[module] = create_hmac(module_data);
            
            // Добавление размера модуля
            size_t module_size = module_data.size();
            backup_data.insert(backup_data.end(), 
                              reinterpret_cast<unsigned char*>(&module_size), 
                              reinterpret_cast<unsigned char*>(&module_size) + sizeof(size_t));
            
            // Добавление данных модуля
            backup_data.insert(backup_data.end(), module_data.begin(), module_data.end());
            
            // Добавление HMAC модуля
            backup_data.insert(backup_data.end(), module_hmacs[module].begin(), module_hmacs[module].end());
        }
        
        // Добавление версии критериев
        backup_data.insert(backup_data.end(), 
                          reinterpret_cast<unsigned char*>(&current_criteria_major_version_), 
                          reinterpret_cast<unsigned char*>(&current_criteria_major_version_) + sizeof(int));
        backup_data.insert(backup_data.end(), 
                          reinterpret_cast<unsigned char*>(&current_criteria_minor_version_), 
                          reinterpret_cast<unsigned char*>(&current_criteria_minor_version_) + sizeof(int));
        
        // Добавление времени
        time_t current_time = time(nullptr);
        backup_data.insert(backup_data.end(), 
                          reinterpret_cast<unsigned char*>(&current_time), 
                          reinterpret_cast<unsigned char*>(&current_time) + sizeof(time_t));
        
        // Шифрование резервной копии
        std::vector<unsigned char> encrypted_backup;
        if (!create_encrypted_backup(backup_data, encrypted_backup)) {
            throw std::runtime_error("Failed to encrypt backup");
        }
        
        // Сохранение резервной копии
        std::string backup_filename = "secure_storage/backups/backup_" + 
                                     std::to_string(current_time) + ".enc";
        std::ofstream backup_file(backup_filename, std::ios::binary);
        if (!backup_file) {
            throw std::runtime_error("Failed to open backup file");
        }
        backup_file.write(reinterpret_cast<const char*>(encrypted_backup.data()), 
                         encrypted_backup.size());
        backup_file.close();
        
        SecureAuditLogger::get_instance().log_event("system",
            "Recovery state saved successfully", false);
    } catch (const std::exception& e) {
        SecureAuditLogger::get_instance().log_event("security",
            "Failed to save recovery state: " + std::string(e.what()), true);
        throw;
    }
}

bool CodeIntegrityProtection::update_criteria_version(int major_version, 
                                                   int minor_version, 
                                                   time_t activation_time) {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    try {
        // Проверка, что время активации в будущем
        if (activation_time <= time(nullptr)) {
            SecureAuditLogger::get_instance().log_event("security",
                "Criteria update failed: activation time in the past", true);
            return false;
        }
        
        // Сохранение состояния перед обновлением
        save_recovery_state();
        
        // Установка запланированной версии
        scheduled_criteria_major_version_ = major_version;
        scheduled_criteria_minor_version_ = minor_version;
        criteria_activation_time_ = activation_time;
        
        // Переподпись критических модулей
        sign_critical_modules();
        
        // Сброс счетчика аномалий
        anomaly_count_ = 0;
        is_blocked_ = false;
        
        SecureAuditLogger::get_instance().log_event("system",
            "Criteria version updated successfully: " + std::to_string(major_version) + "." + 
            std::to_string(minor_version) + " (activation time: " + std::to_string(activation_time) + ")", false);
        
        return true;
    } catch (const std::exception& e) {
        // Логирование ошибки
        SecureAuditLogger::get_instance().log_event("security",
            "Failed to update criteria version: " + std::string(e.what()), true);
        throw;
    }
}

bool CodeIntegrityProtection::is_criteria_version_active() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    // Проверка, что есть запланированная версия
    if (scheduled_criteria_major_version_ == -1 || 
        scheduled_criteria_minor_version_ == -1 || 
        criteria_activation_time_ == 0) {
        return false;
    }
    
    // Проверка, наступило ли время активации
    return time(nullptr) >= criteria_activation_time_;
}

void CodeIntegrityProtection::get_current_criteria_version(int& major_version, 
                                                        int& minor_version) const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    major_version = current_criteria_major_version_;
    minor_version = current_criteria_minor_version_;
}

void CodeIntegrityProtection::get_scheduled_criteria_version(int& major_version, 
                                                          int& minor_version, 
                                                          time_t& activation_time) const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    major_version = scheduled_criteria_major_version_;
    minor_version = scheduled_criteria_minor_version_;
    activation_time = criteria_activation_time_;
}

bool CodeIntegrityProtection::is_blocked_due_to_anomalies() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    return is_blocked_;
}

bool CodeIntegrityProtection::verify_system_integrity() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    try {
        // Проверка целостности всех критических модулей
        for (const auto& module : critical_modules_) {
            // Загрузка модуля
            std::vector<unsigned char> module_data;
            if (!load_module(module, module_data)) {
                SecureAuditLogger::get_instance().log_event("security",
                    "Module load failed: " + module, true);
                handle_anomaly("module_load", "Failed to load module: " + module);
                return false;
            }
            
            // Вычисляем HMAC для модуля
            std::vector<unsigned char> computed_hmac = create_hmac(module_data);
            
            // Получаем оригинальный HMAC
            std::vector<unsigned char> original_hmac = get_original_module_hmac(module);
            
            // Проверяем HMAC с постоянным временем
            if (!PostQuantumHash::verify_hmac_constant_time(computed_hmac, original_hmac, 
                                                          std::chrono::microseconds(100))) {
                SecureAuditLogger::get_instance().log_event("security",
                    "Module integrity check failed: " + module, true);
                handle_anomaly("module_integrity", "Module integrity check failed: " + module);
                return false;
            }
        }
        
        // Проверка, требуется ли обновление критериев
        if (is_criteria_update_required()) {
            apply_scheduled_criteria_update();
        }
        
        return true;
    } catch (const std::exception& e) {
        SecureAuditLogger::get_instance().log_event("security",
            "System integrity check failed: " + std::string(e.what()), true);
        handle_anomaly("system_integrity", std::string("System integrity check failed: ") + e.what());
        return false;
    }
}

bool CodeIntegrityProtection::recover_from_backup() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    try {
        // Поиск последней резервной копии
        std::string latest_backup;
        time_t latest_time = 0;
        
        for (const auto& entry : std::filesystem::directory_iterator("secure_storage/backups")) {
            if (entry.is_regular_file() && entry.path().extension() == ".enc") {
                time_t file_time = std::filesystem::last_write_time(entry.path());
                if (file_time > latest_time) {
                    latest_time = file_time;
                    latest_backup = entry.path().string();
                }
            }
        }
        
        // Если резервная копия не найдена
        if (latest_backup.empty()) {
            SecureAuditLogger::get_instance().log_event("security",
                "Recovery failed: no backup found", true);
            return false;
        }
        
        // Загрузка резервной копии
        std::ifstream backup_file(latest_backup, std::ios::binary);
        if (!backup_file) {
            SecureAuditLogger::get_instance().log_event("security",
                "Recovery failed: cannot open backup file", true);
            return false;
        }
        
        backup_file.seekg(0, std::ios::end);
        size_t file_size = backup_file.tellg();
        backup_file.seekg(0, std::ios::beg);
        
        std::vector<unsigned char> encrypted_backup(file_size);
        backup_file.read(reinterpret_cast<char*>(encrypted_backup.data()), file_size);
        backup_file.close();
        
        // Расшифровка резервной копии
        std::vector<unsigned char> backup_data;
        if (!decrypt_backup(encrypted_backup, backup_data)) {
            SecureAuditLogger::get_instance().log_event("security",
                "Recovery failed: cannot decrypt backup", true);
            return false;
        }
        
        // Восстановление модулей
        size_t offset = 0;
        std::map<std::string, std::vector<unsigned char>> module_hmacs;
        
        for (const auto& module : critical_modules_) {
            // Чтение размера модуля
            size_t module_size;
            std::memcpy(&module_size, backup_data.data() + offset, sizeof(size_t));
            offset += sizeof(size_t);
            
            // Чтение данных модуля
            std::vector<unsigned char> module_data(backup_data.begin() + offset,
                                                 backup_data.begin() + offset + module_size);
            offset += module_size;
            
            // Чтение HMAC модуля
            std::vector<unsigned char> stored_hmac(backup_data.begin() + offset,
                                                 backup_data.begin() + offset + crypto_auth_BYTES);
            offset += crypto_auth_BYTES;
            
            // Проверка HMAC
            std::vector<unsigned char> computed_hmac = create_hmac(module_data);
            if (!PostQuantumHash::verify_hmac_constant_time(computed_hmac, stored_hmac, 
                                                          std::chrono::microseconds(100))) {
                SecureAuditLogger::get_instance().log_event("security",
                    "Module integrity check failed during recovery: " + module, true);
                throw std::runtime_error("Module integrity check failed: " + module);
            }
            
            // Сохранение модуля в защищенное хранилище
            if (!save_module_to_secure_storage(module, module_data)) {
                throw std::runtime_error("Failed to save module: " + module);
            }
            
            // Сохранение HMAC
            module_hmacs_[module] = stored_hmac;
            if (!save_hmac_to_secure_storage(module, stored_hmac)) {
                throw std::runtime_error("Failed to save HMAC: " + module);
            }
        }
        
        // Чтение версии критериев
        if (offset + 2 * sizeof(int) + sizeof(time_t) > backup_data.size()) {
            throw std::runtime_error("Invalid backup format: criteria version");
        }
        
        int major_version, minor_version;
        std::memcpy(&major_version, backup_data.data() + offset, sizeof(int));
        offset += sizeof(int);
        std::memcpy(&minor_version, backup_data.data() + offset, sizeof(int));
        offset += sizeof(int);
        
        // Чтение времени
        time_t backup_time;
        std::memcpy(&backup_time, backup_data.data() + offset, sizeof(time_t));
        
        // Установка версии критериев
        current_criteria_major_version_ = major_version;
        current_criteria_minor_version_ = minor_version;
        
        SecureAuditLogger::get_instance().log_event("system",
            "System recovered successfully from backup: " + latest_backup, false);
        
        return true;
    } catch (const std::exception& e) {
        SecureAuditLogger::get_instance().log_event("security",
            "Recovery failed: " + std::string(e.what()), true);
        return false;
    }
}

void CodeIntegrityProtection::initialize_hmac_key() {
    hmac_key_ = SecureRandom::generate_random_bytes(SecurityConstants::HMAC_KEY_SIZE);
}

void CodeIntegrityProtection::sign_critical_modules() {
    for (const auto& module : critical_modules_) {
        std::vector<unsigned char> module_data;
        if (load_module(module, module_data)) {
            sign_module(module, module_data.data(), module_data.size());
        }
    }
}

bool CodeIntegrityProtection::verify_module(const std::string& module_name, 
                                          const void* data, 
                                          size_t size) {
    // Создаем данные для HMAC
    std::vector<unsigned char> hmac_input;
    hmac_input.insert(hmac_input.end(), module_name.begin(), module_name.end());
    hmac_input.push_back(0x00);
    hmac_input.insert(hmac_input.end(), static_cast<const unsigned char*>(data), 
                     static_cast<const unsigned char*>(data) + size);
    
    // Создаем HMAC
    std::vector<unsigned char> computed_hmac(crypto_auth_BYTES);
    crypto_auth(computed_hmac.data(), hmac_input.data(), hmac_input.size(), hmac_key_.data());
    
    // Получаем оригинальный HMAC
    std::vector<unsigned char> original_hmac = get_original_module_hmac(module_name);
    
    // Проверяем HMAC с постоянным временем
    return PostQuantumHash::verify_hmac_constant_time(computed_hmac, original_hmac, 
                                                   std::chrono::microseconds(100));
}

void CodeIntegrityProtection::sign_module(const std::string& module_name, 
                                        const void* data, 
                                        size_t size) {
    // Создаем данные для HMAC
    std::vector<unsigned char> hmac_input;
    hmac_input.insert(hmac_input.end(), module_name.begin(), module_name.end());
    hmac_input.push_back(0x00);
    hmac_input.insert(hmac_input.end(), static_cast<const unsigned char*>(data), 
                     static_cast<const unsigned char*>(data) + size);
    
    // Создаем HMAC
    std::vector<unsigned char> hmac(crypto_auth_BYTES);
    crypto_auth(hmac.data(), hmac_input.data(), hmac_input.size(), hmac_key_.data());
    
    // Сохраняем HMAC
    module_hmacs_[module_name] = hmac;
    
    // Сохраняем HMAC в защищенное хранилище
    save_hmac_to_secure_storage(module_name, hmac);
}

bool CodeIntegrityProtection::load_module(const std::string& module_name, 
                                       std::vector<unsigned char>& data) {
    // Загрузка модуля из защищенного хранилища
    std::string module_path = "secure_storage/" + module_name;
    
    // Проверяем существование файла
    if (!std::filesystem::exists(module_path)) {
        SecureAuditLogger::get_instance().log_event("security",
            "Module file not found: " + module_path, true);
        return false;
    }
    
    // Читаем файл
    std::ifstream module_file(module_path, std::ios::binary | std::ios::ate);
    if (!module_file) {
        SecureAuditLogger::get_instance().log_event("security",
            "Failed to open module file: " + module_path, true);
        return false;
    }
    
    std::streamsize size = module_file.tellg();
    module_file.seekg(0, std::ios::beg);
    
    data.resize(size);
    if (!module_file.read(reinterpret_cast<char*>(data.data()), size)) {
        SecureAuditLogger::get_instance().log_event("security",
            "Failed to read module file: " + module_path, true);
        return false;
    }
    
    return true;
}

bool CodeIntegrityProtection::save_module_to_secure_storage(const std::string& module_name,
                                                         const std::vector<unsigned char>& module_data) const {
    // Создание директории для защищенного хранилища
    std::filesystem::create_directories("secure_storage");
    
    // Сохранение модуля
    std::string module_path = "secure_storage/" + module_name;
    std::ofstream module_file(module_path, std::ios::binary);
    if (!module_file) {
        return false;
    }
    
    module_file.write(reinterpret_cast<const char*>(module_data.data()), module_data.size());
    module_file.close();
    
    return true;
}

std::vector<unsigned char> CodeIntegrityProtection::create_hmac(const std::vector<unsigned char>& data) const {
    std::vector<unsigned char> hmac(crypto_auth_BYTES);
    crypto_auth(hmac.data(), data.data(), data.size(), hmac_key_.data());
    return hmac;
}

std::vector<unsigned char> CodeIntegrityProtection::get_original_module_hmac(const std::string& module_name) const {
    // Получение оригинального HMAC из защищенного хранилища
    return get_original_hmac_from_secure_storage(module_name);
}

bool CodeIntegrityProtection::create_encrypted_backup(const std::vector<unsigned char>& backup_data,
                                                    std::vector<unsigned char>& encrypted_backup) const {
    // Генерация соли
    std::vector<unsigned char> salt = generate_hmac_salt();
    
    // Получение ключа шифрования из соли и ключа резервного копирования
    std::vector<unsigned char> encryption_key = PostQuantumHash::hkdf_sha3(
        backup_key_, salt, "backup_encryption", SecurityConstants::ENCRYPTION_KEY_SIZE);
    
    // Генерация nonce
    std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    
    // Шифрование данных
    std::vector<unsigned char> ciphertext(backup_data.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(ciphertext.data(), backup_data.data(), backup_data.size(), 
                         nonce.data(), encryption_key.data());
    
    // Формирование зашифрованной резервной копии
    encrypted_backup.clear();
    encrypted_backup.insert(encrypted_backup.end(), salt.begin(), salt.end());
    encrypted_backup.insert(encrypted_backup.end(), nonce.begin(), nonce.end());
    encrypted_backup.insert(encrypted_backup.end(), ciphertext.begin(), ciphertext.end());
    
    return true;
}

bool CodeIntegrityProtection::decrypt_backup(const std::vector<unsigned char>& encrypted_backup,
                                          std::vector<unsigned char>& backup_data) const {
    // Проверка размера
    if (encrypted_backup.size() < SecurityConstants::SALT_SIZE + 
        crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        return false;
    }
    
    // Извлечение соли
    size_t offset = 0;
    std::vector<unsigned char> salt(encrypted_backup.begin(), 
                                  encrypted_backup.begin() + SecurityConstants::SALT_SIZE);
    offset += SecurityConstants::SALT_SIZE;
    
    // Извлечение nonce
    std::vector<unsigned char> nonce(encrypted_backup.begin() + offset, 
                                  encrypted_backup.begin() + offset + crypto_secretbox_NONCEBYTES);
    offset += crypto_secretbox_NONCEBYTES;
    
    // Извлечение ciphertext
    std::vector<unsigned char> ciphertext(encrypted_backup.begin() + offset, 
                                       encrypted_backup.end());
    
    // Получение ключа шифрования
    std::vector<unsigned char> encryption_key = PostQuantumHash::hkdf_sha3(
        backup_key_, salt, "backup_encryption", SecurityConstants::ENCRYPTION_KEY_SIZE);
    
    // Расшифровка данных
    backup_data.resize(ciphertext.size() - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(backup_data.data(), ciphertext.data(), ciphertext.size(), 
                                  nonce.data(), encryption_key.data()) != 0) {
        return false;
    }
    
    return true;
}

std::vector<unsigned char> CodeIntegrityProtection::generate_hmac_salt() const {
    return SecureRandom::generate_random_bytes(SecurityConstants::SALT_SIZE);
}

time_t CodeIntegrityProtection::get_last_anomaly_time() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    return last_anomaly_time_;
}

size_t CodeIntegrityProtection::get_anomaly_count() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    return anomaly_count_;
}

time_t CodeIntegrityProtection::get_last_recovery_time() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    return last_recovery_time_;
}

std::vector<unsigned char> CodeIntegrityProtection::get_hmac_key() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    return hmac_key_;
}

std::vector<unsigned char> CodeIntegrityProtection::get_backup_key() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    return backup_key_;
}

std::vector<unsigned char> CodeIntegrityProtection::get_system_public_key() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    return system_public_key_;
}

bool CodeIntegrityProtection::is_criteria_update_required() const {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    return (scheduled_criteria_major_version_ != -1 && 
            scheduled_criteria_minor_version_ != -1 && 
            criteria_activation_time_ != 0 &&
            time(nullptr) >= criteria_activation_time_);
}

void CodeIntegrityProtection::apply_scheduled_criteria_update() {
    std::lock_guard<std::mutex> lock(integrity_mutex_);
    
    if (is_criteria_update_required()) {
        current_criteria_major_version_ = scheduled_criteria_major_version_;
        current_criteria_minor_version_ = scheduled_criteria_minor_version_;
        scheduled_criteria_major_version_ = -1;
        scheduled_criteria_minor_version_ = -1;
        criteria_activation_time_ = 0;
        
        SecureAuditLogger::get_instance().log_event("system",
            "Criteria version updated to: " + std::to_string(current_criteria_major_version_) + "." + 
            std::to_string(current_criteria_minor_version_), false);
    }
}

std::vector<unsigned char> CodeIntegrityProtection::get_original_hmac_from_secure_storage(const std::string& module_name) const {
    // Получение оригинального HMAC из защищенного хранилища
    std::string hmac_path = "secure_storage/hmac_" + module_name;
    
    // Проверяем существование файла
    if (!std::filesystem::exists(hmac_path)) {
        // Если HMAC не найден, возвращаем пустой вектор
        return std::vector<unsigned char>();
    }
    
    // Читаем файл
    std::ifstream hmac_file(hmac_path, std::ios::binary | std::ios::ate);
    if (!hmac_file) {
        return std::vector<unsigned char>();
    }
    
    std::streamsize size = hmac_file.tellg();
    hmac_file.seekg(0, std::ios::beg);
    
    std::vector<unsigned char> hmac(size);
    if (!hmac_file.read(reinterpret_cast<char*>(hmac.data()), size)) {
        return std::vector<unsigned char>();
    }
    
    return hmac;
}

bool CodeIntegrityProtection::save_hmac_to_secure_storage(const std::string& module_name,
                                                       const std::vector<unsigned char>& hmac) const {
    // Создание директории для защищенного хранилища
    std::filesystem::create_directories("secure_storage");
    
    // Сохранение HMAC
    std::string hmac_path = "secure_storage/hmac_" + module_name;
    std::ofstream hmac_file(hmac_path, std::ios::binary);
    if (!hmac_file) {
        return false;
    }
    
    hmac_file.write(reinterpret_cast<const char*>(hmac.data()), hmac.size());
    hmac_file.close();
    
    return true;
}

} // namespace toruscsidh
