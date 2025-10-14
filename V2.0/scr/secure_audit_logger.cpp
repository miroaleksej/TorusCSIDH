#include "secure_audit_logger.h"
#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <sodium.h>
#include "postquantum_hash.h"
#include "secure_random.h"
#include "code_integrity.h"

namespace toruscsidh {

SecureAuditLogger::SecureAuditLogger()
    : initialized_(false),
      closed_(false),
      log_entry_count_(0),
      last_anomaly_time_(0),
      anomaly_count_(0),
      last_recovery_time_(0),
      last_integrity_check_time_(0),
      integrity_check_count_(0),
      successful_integrity_checks_(0),
      failed_integrity_checks_(0),
      last_criteria_update_time_(0),
      current_criteria_major_version_(1),
      current_criteria_minor_version_(0),
      scheduled_criteria_major_version_(-1),
      scheduled_criteria_minor_version_(-1),
      criteria_activation_time_(0),
      security_level_(SecurityConstants::LEVEL_128),
      code_integrity_(nullptr) {
    
    // Инициализация уровней безопасности
    security_level_ = SecurityConstants::LEVEL_128;
    
    // Инициализация ключей
    encryption_key_ = SecureRandom::generate_random_bytes(SecurityConstants::ENCRYPTION_KEY_SIZE);
    hmac_key_ = SecureRandom::generate_random_bytes(SecurityConstants::HMAC_KEY_SIZE);
    
    // Получение указателя на систему целостности
    code_integrity_ = &CodeIntegrityProtection::get_instance();
    
    // Инициализация логгера
    initialized_ = initialize();
    
    if (initialized_) {
        log_event("system", "SecureAuditLogger initialized successfully", false);
    } else {
        // Если инициализация не удалась, попытаемся восстановиться
        if (load_log()) {
            log_event("system", "SecureAuditLogger recovered from backup", false);
            initialized_ = true;
        } else {
            throw std::runtime_error("Failed to initialize SecureAuditLogger");
        }
    }
}

SecureAuditLogger::~SecureAuditLogger() {
    if (!closed_) {
        close();
    }
    
    // Очистка памяти
    secure_wipe(encryption_key_);
    secure_wipe(hmac_key_);
    
    log_event("system", "SecureAuditLogger destroyed", false);
}

SecureAuditLogger& SecureAuditLogger::get_instance() {
    static SecureAuditLogger instance;
    return instance;
}

void SecureAuditLogger::log_event(const std::string& category,
                                const std::string& message,
                                bool security_event) {
    std::lock_guard<std::mutex> lock(logger_mutex_);
    
    if (closed_ || !initialized_) {
        return;
    }
    
    // Форматирование сообщения
    std::string formatted_message = format_log_message(category, message, security_event);
    
    // Запись в файл
    if (log_file_.is_open()) {
        log_file_ << formatted_message << std::endl;
        log_file_.flush();
        
        // Обновление счетчиков
        log_entry_count_++;
        last_log_time_ = std::chrono::system_clock::now();
        
        // Логирование событий безопасности
        if (security_event) {
            anomaly_count_++;
            last_anomaly_time_ = time(nullptr);
            
            // Проверка, нужно ли блокировать систему
            if (anomaly_count_ > SecurityConstants::MAX_ANOMALY_COUNT) {
                code_integrity_->handle_anomaly("security_event", message);
            }
        }
    } else {
        // Если файл не открыт, попытаемся пересоздать его
        if (initialize()) {
            log_file_ << formatted_message << std::endl;
            log_file_.flush();
            
            log_entry_count_++;
            last_log_time_ = std::chrono::system_clock::now();
        }
    }
}

bool SecureAuditLogger::is_initialized() const {
    return initialized_;
}

std::chrono::system_clock::time_point SecureAuditLogger::get_last_log_time() const {
    return last_log_time_;
}

size_t SecureAuditLogger::get_log_entry_count() const {
    return log_entry_count_;
}

void SecureAuditLogger::clear_log() {
    std::lock_guard<std::mutex> lock(logger_mutex_);
    
    if (closed_ || !initialized_) {
        return;
    }
    
    // Закрываем текущий файл
    if (log_file_.is_open()) {
        log_file_.close();
    }
    
    // Удаляем файл лога
    std::filesystem::remove(log_file_path_);
    
    // Пересоздаем файл
    initialize();
    
    log_event("system", "Log cleared successfully", false);
}

bool SecureAuditLogger::save_log() {
    std::lock_guard<std::mutex> lock(logger_mutex_);
    
    if (closed_ || !initialized_) {
        return false;
    }
    
    try {
        // Закрываем текущий файл
        if (log_file_.is_open()) {
            log_file_.close();
        }
        
        // Читаем содержимое файла
        std::ifstream input_file(log_file_path_, std::ios::binary);
        if (!input_file) {
            return false;
        }
        
        input_file.seekg(0, std::ios::end);
        size_t file_size = input_file.tellg();
        input_file.seekg(0, std::ios::beg);
        
        std::vector<unsigned char> log_data(file_size);
        input_file.read(reinterpret_cast<char*>(log_data.data()), file_size);
        input_file.close();
        
        // Шифруем данные
        std::vector<unsigned char> encrypted_log;
        if (!encrypt_log(log_data, encrypted_log)) {
            return false;
        }
        
        // Создаем HMAC
        std::vector<unsigned char> hmac = create_log_hmac(encrypted_log);
        
        // Формируем полные данные
        std::vector<unsigned char> full_data;
        full_data.insert(full_data.end(), hmac.begin(), hmac.end());
        full_data.insert(full_data.end(), encrypted_log.begin(), encrypted_log.end());
        
        // Сохраняем зашифрованный лог
        std::string backup_path = "secure_storage/log_backup_" + 
                                 std::to_string(time(nullptr)) + ".enc";
        std::ofstream backup_file(backup_path, std::ios::binary);
        if (!backup_file) {
            return false;
        }
        backup_file.write(reinterpret_cast<const char*>(full_data.data()), full_data.size());
        backup_file.close();
        
        // Пересоздаем текущий файл
        initialize();
        
        return true;
    } catch (const std::exception& e) {
        log_event("security", "Failed to save log: " + std::string(e.what()), true);
        return false;
    }
}

bool SecureAuditLogger::load_log() {
    std::lock_guard<std::mutex> lock(logger_mutex_);
    
    try {
        // Поиск последней резервной копии
        std::string latest_backup;
        time_t latest_time = 0;
        
        for (const auto& entry : std::filesystem::directory_iterator("secure_storage")) {
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
            return false;
        }
        
        // Загрузка резервной копии
        std::ifstream backup_file(latest_backup, std::ios::binary);
        if (!backup_file) {
            return false;
        }
        
        backup_file.seekg(0, std::ios::end);
        size_t file_size = backup_file.tellg();
        backup_file.seekg(0, std::ios::beg);
        
        std::vector<unsigned char> full_data(file_size);
        backup_file.read(reinterpret_cast<char*>(full_data.data()), file_size);
        backup_file.close();
        
        // Проверка HMAC
        if (file_size < crypto_auth_BYTES) {
            return false;
        }
        
        std::vector<unsigned char> stored_hmac(full_data.begin(), 
                                             full_data.begin() + crypto_auth_BYTES);
        std::vector<unsigned char> encrypted_log(full_data.begin() + crypto_auth_BYTES, 
                                               full_data.end());
        
        if (!verify_log_hmac(encrypted_log, stored_hmac)) {
            return false;
        }
        
        // Расшифровка данных
        std::vector<unsigned char> log_data;
        if (!decrypt_log(encrypted_log, log_data)) {
            return false;
        }
        
        // Перезаписываем текущий файл
        if (std::filesystem::exists(log_file_path_)) {
            std::filesystem::remove(log_file_path_);
        }
        
        std::ofstream output_file(log_file_path_, std::ios::binary);
        if (!output_file) {
            return false;
        }
        output_file.write(reinterpret_cast<const char*>(log_data.data()), log_data.size());
        output_file.close();
        
        // Пересоздаем файл лога
        initialize();
        
        log_event("system", "Log loaded successfully from backup: " + latest_backup, false);
        
        return true;
    } catch (const std::exception& e) {
        log_event("security", "Failed to load log: " + std::string(e.what()), true);
        return false;
    }
}

bool SecureAuditLogger::verify_log_integrity() {
    std::lock_guard<std::mutex> lock(logger_mutex_);
    
    if (closed_ || !initialized_) {
        return false;
    }
    
    try {
        // Читаем содержимое файла
        std::ifstream input_file(log_file_path_, std::ios::binary);
        if (!input_file) {
            return false;
        }
        
        input_file.seekg(0, std::ios::end);
        size_t file_size = input_file.tellg();
        input_file.seekg(0, std::ios::beg);
        
        std::vector<unsigned char> log_data(file_size);
        input_file.read(reinterpret_cast<char*>(log_data.data()), file_size);
        input_file.close();
        
        // Проверяем HMAC
        std::vector<unsigned char> hmac = create_log_hmac(log_data);
        
        // Сравниваем HMAC
        return verify_log_hmac(log_data, hmac);
    } catch (const std::exception& e) {
        log_event("security", "Log integrity verification failed: " + std::string(e.what()), true);
        return false;
    }
}

bool SecureAuditLogger::encrypt_log(const std::vector<unsigned char>& log_data,
                                  std::vector<unsigned char>& encrypted_log) {
    // Генерация соли
    std::vector<unsigned char> salt = SecureRandom::generate_random_bytes(SecurityConstants::SALT_SIZE);
    
    // Получение ключа шифрования из соли и ключа лога
    std::vector<unsigned char> encryption_key = PostQuantumHash::hkdf_blake3(
        encryption_key_, salt, "log_encryption", SecurityConstants::ENCRYPTION_KEY_SIZE);
    
    // Генерация nonce
    std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    
    // Шифрование данных
    std::vector<unsigned char> ciphertext(log_data.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(ciphertext.data(), log_data.data(), log_data.size(), 
                         nonce.data(), encryption_key.data());
    
    // Формирование зашифрованного лога
    encrypted_log.clear();
    encrypted_log.insert(encrypted_log.end(), salt.begin(), salt.end());
    encrypted_log.insert(encrypted_log.end(), nonce.begin(), nonce.end());
    encrypted_log.insert(encrypted_log.end(), ciphertext.begin(), ciphertext.end());
    
    return true;
}

bool SecureAuditLogger::decrypt_log(const std::vector<unsigned char>& encrypted_log,
                                  std::vector<unsigned char>& log_data) {
    // Проверка размера
    if (encrypted_log.size() < SecurityConstants::SALT_SIZE + 
        crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        return false;
    }
    
    // Извлечение соли
    size_t offset = 0;
    std::vector<unsigned char> salt(encrypted_log.begin(), 
                                  encrypted_log.begin() + SecurityConstants::SALT_SIZE);
    offset += SecurityConstants::SALT_SIZE;
    
    // Извлечение nonce
    std::vector<unsigned char> nonce(encrypted_log.begin() + offset, 
                                  encrypted_log.begin() + offset + crypto_secretbox_NONCEBYTES);
    offset += crypto_secretbox_NONCEBYTES;
    
    // Извлечение ciphertext
    std::vector<unsigned char> ciphertext(encrypted_log.begin() + offset, 
                                       encrypted_log.end());
    
    // Получение ключа шифрования
    std::vector<unsigned char> encryption_key = PostQuantumHash::hkdf_blake3(
        encryption_key_, salt, "log_encryption", SecurityConstants::ENCRYPTION_KEY_SIZE);
    
    // Расшифровка данных
    log_data.resize(ciphertext.size() - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(log_data.data(), ciphertext.data(), ciphertext.size(), 
                                  nonce.data(), encryption_key.data()) != 0) {
        return false;
    }
    
    return true;
}

std::vector<unsigned char> SecureAuditLogger::create_log_hmac(const std::vector<unsigned char>& log_data) {
    std::vector<unsigned char> hmac(crypto_auth_BYTES);
    crypto_auth(hmac.data(), log_data.data(), log_data.size(), hmac_key_.data());
    return hmac;
}

bool SecureAuditLogger::verify_log_hmac(const std::vector<unsigned char>& log_data,
                                      const std::vector<unsigned char>& hmac) {
    std::vector<unsigned char> computed_hmac = create_log_hmac(log_data);
    return PostQuantumHash::verify_hmac_constant_time(computed_hmac, hmac, 
                                                    std::chrono::microseconds(100));
}

std::vector<unsigned char> SecureAuditLogger::get_log_encryption_key() const {
    return encryption_key_;
}

std::vector<unsigned char> SecureAuditLogger::get_log_hmac_key() const {
    return hmac_key_;
}

time_t SecureAuditLogger::get_last_anomaly_time() const {
    return last_anomaly_time_;
}

size_t SecureAuditLogger::get_anomaly_count() const {
    return anomaly_count_;
}

time_t SecureAuditLogger::get_last_recovery_time() const {
    return last_recovery_time_;
}

time_t SecureAuditLogger::get_last_integrity_check_time() const {
    return last_integrity_check_time_;
}

size_t SecureAuditLogger::get_integrity_check_count() const {
    return integrity_check_count_;
}

size_t SecureAuditLogger::get_successful_integrity_checks() const {
    return successful_integrity_checks_;
}

size_t SecureAuditLogger::get_failed_integrity_checks() const {
    return failed_integrity_checks_;
}

time_t SecureAuditLogger::get_last_criteria_update_time() const {
    return last_criteria_update_time_;
}

void SecureAuditLogger::get_current_criteria_version(int& major_version, int& minor_version) const {
    major_version = current_criteria_major_version_;
    minor_version = current_criteria_minor_version_;
}

void SecureAuditLogger::get_scheduled_criteria_version(int& major_version, 
                                                     int& minor_version, 
                                                     time_t& activation_time) const {
    major_version = scheduled_criteria_major_version_;
    minor_version = scheduled_criteria_minor_version_;
    activation_time = criteria_activation_time_;
}

SecurityConstants::SecurityLevel SecureAuditLogger::get_security_level() const {
    return security_level_;
}

bool SecureAuditLogger::is_ready() const {
    return initialized_ && !closed_;
}

std::string SecureAuditLogger::get_system_status() const {
    std::stringstream ss;
    
    ss << "System Status:" << std::endl;
    ss << "  Initialized: " << (initialized_ ? "Yes" : "No") << std::endl;
    ss << "  Closed: " << (closed_ ? "Yes" : "No") << std::endl;
    ss << "  Log Entries: " << log_entry_count_ << std::endl;
    ss << "  Last Log Time: " << format_time(last_log_time_) << std::endl;
    ss << "  Anomaly Count: " << anomaly_count_ << std::endl;
    ss << "  Last Anomaly Time: " << (last_anomaly_time_ > 0 ? std::to_string(last_anomaly_time_) : "N/A") << std::endl;
    ss << "  Last Recovery Time: " << (last_recovery_time_ > 0 ? std::to_string(last_recovery_time_) : "N/A") << std::endl;
    
    return ss.str();
}

std::string SecureAuditLogger::get_security_info() const {
    std::stringstream ss;
    
    ss << "Security Information:" << std::endl;
    ss << "  Security Level: " << SecurityConstants::security_level_to_string(security_level_) << std::endl;
    ss << "  Integrity Checks: " << integrity_check_count_ << std::endl;
    ss << "  Successful Integrity Checks: " << successful_integrity_checks_ << std::endl;
    ss << "  Failed Integrity Checks: " << failed_integrity_checks_ << std::endl;
    ss << "  Last Integrity Check Time: " << (last_integrity_check_time_ > 0 ? std::to_string(last_integrity_check_time_) : "N/A") << std::endl;
    ss << "  Current Criteria Version: " << current_criteria_major_version_ << "." << current_criteria_minor_version_ << std::endl;
    
    if (scheduled_criteria_major_version_ != -1 && scheduled_criteria_minor_version_ != -1 && criteria_activation_time_ != 0) {
        ss << "  Scheduled Criteria Version: " << scheduled_criteria_major_version_ << "." 
           << scheduled_criteria_minor_version_ << " (Activation Time: " << criteria_activation_time_ << ")" << std::endl;
    }
    
    return ss.str();
}

std::string SecureAuditLogger::get_security_statistics() const {
    std::stringstream ss;
    
    ss << "Security Statistics:" << std::endl;
    
    // Статистика по аномалиям
    ss << "  Anomalies:" << std::endl;
    ss << "    Total: " << anomaly_count_ << std::endl;
    
    // Статистика по проверкам целостности
    ss << "  Integrity Checks:" << std::endl;
    ss << "    Total: " << integrity_check_count_ << std::endl;
    ss << "    Successful: " << successful_integrity_checks_ << std::endl;
    ss << "    Failed: " << failed_integrity_checks_ << std::endl;
    
    // Статистика по критериям
    ss << "  Criteria:" << std::endl;
    ss << "    Current Version: " << current_criteria_major_version_ << "." << current_criteria_minor_version_ << std::endl;
    
    if (scheduled_criteria_major_version_ != -1 && scheduled_criteria_minor_version_ != -1 && criteria_activation_time_ != 0) {
        ss << "    Scheduled Version: " << scheduled_criteria_major_version_ << "." 
           << scheduled_criteria_minor_version_ << " (Activation Time: " << criteria_activation_time_ << ")" << std::endl;
    }
    
    return ss.str();
}

bool SecureAuditLogger::initialize() {
    try {
        // Создание директории для защищенного хранилища
        std::filesystem::create_directories("secure_storage");
        
        // Генерация имени файла
        std::string base_name = "audit_log_" + std::to_string(time(nullptr));
        log_file_path_ = "secure_storage/" + encrypt_filename(base_name);
        
        // Открытие файла
        log_file_.open(log_file_path_, std::ios::app);
        if (!log_file_) {
            return false;
        }
        
        // Добавление заголовка
        log_file_ << "TorusCSIDH Audit Log - " << format_time(std::chrono::system_clock::now()) << std::endl;
        log_file_ << "===================================" << std::endl;
        log_file_.flush();
        
        return true;
    } catch (const std::exception& e) {
        // В случае ошибки, пытаемся загрузить лог из резервной копии
        return load_log();
    }
}

void SecureAuditLogger::close() {
    std::lock_guard<std::mutex> lock(logger_mutex_);
    
    if (closed_ || !initialized_) {
        return;
    }
    
    // Сохранение лога перед закрытием
    save_log();
    
    // Закрытие файла
    if (log_file_.is_open()) {
        log_file_.close();
    }
    
    closed_ = true;
}

std::string SecureAuditLogger::format_time(const std::chrono::system_clock::time_point& time_point) const {
    std::time_t time = std::chrono::system_clock::to_time_t(time_point);
    std::tm tm = *std::localtime(&time);
    
    std::stringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string SecureAuditLogger::format_log_message(const std::string& category,
                                                const std::string& message,
                                                bool security_event) const {
    auto now = std::chrono::system_clock::now();
    std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::localtime(&time);
    
    std::stringstream ss;
    ss << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "] ";
    ss << "[" << category << "] ";
    ss << (security_event ? "[SECURITY] " : "");
    ss << message;
    
    return ss.str();
}

void SecureAuditLogger::secure_wipe(std::vector<unsigned char>& data) const {
    SecureRandom::secure_clean_memory(data.data(), data.size());
}

void SecureAuditLogger::secure_wipe(std::string& str) const {
    SecureRandom::secure_clean_memory(&str[0], str.size());
    str.clear();
}

std::string SecureAuditLogger::encrypt_filename(const std::string& base_name) {
    // Шифрование имени файла
    std::vector<unsigned char> base_name_bytes(base_name.begin(), base_name.end());
    
    // Генерация соли
    std::vector<unsigned char> salt = SecureRandom::generate_random_bytes(SecurityConstants::SALT_SIZE);
    
    // Получение ключа шифрования из соли и ключа лога
    std::vector<unsigned char> encryption_key = PostQuantumHash::hkdf_blake3(
        encryption_key_, salt, "filename_encryption", SecurityConstants::ENCRYPTION_KEY_SIZE);
    
    // Генерация nonce
    std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    
    // Шифрование данных
    std::vector<unsigned char> ciphertext(base_name_bytes.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(ciphertext.data(), base_name_bytes.data(), base_name_bytes.size(), 
                         nonce.data(), encryption_key.data());
    
    // Формирование зашифрованного имени
    std::vector<unsigned char> full_data;
    full_data.insert(full_data.end(), salt.begin(), salt.end());
    full_data.insert(full_data.end(), nonce.begin(), nonce.end());
    full_data.insert(full_data.end(), ciphertext.begin(), ciphertext.end());
    
    // Кодируем в base64
    return PostQuantumHash::base64_encode(full_data);
}

std::string SecureAuditLogger::decrypt_filename(const std::string& encrypted_name) {
    // Декодируем из base64
    std::vector<unsigned char> full_data = PostQuantumHash::base64_decode(encrypted_name);
    
    // Проверка размера
    if (full_data.size() < SecurityConstants::SALT_SIZE + 
        crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        return "";
    }
    
    // Извлечение соли
    size_t offset = 0;
    std::vector<unsigned char> salt(full_data.begin(), 
                                  full_data.begin() + SecurityConstants::SALT_SIZE);
    offset += SecurityConstants::SALT_SIZE;
    
    // Извлечение nonce
    std::vector<unsigned char> nonce(full_data.begin() + offset, 
                                  full_data.begin() + offset + crypto_secretbox_NONCEBYTES);
    offset += crypto_secretbox_NONCEBYTES;
    
    // Извлечение ciphertext
    std::vector<unsigned char> ciphertext(full_data.begin() + offset, 
                                       full_data.end());
    
    // Получение ключа шифрования
    std::vector<unsigned char> encryption_key = PostQuantumHash::hkdf_blake3(
        encryption_key_, salt, "filename_encryption", SecurityConstants::ENCRYPTION_KEY_SIZE);
    
    // Расшифровка данных
    std::vector<unsigned char> base_name_bytes(ciphertext.size() - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(base_name_bytes.data(), ciphertext.data(), ciphertext.size(), 
                                  nonce.data(), encryption_key.data()) != 0) {
        return "";
    }
    
    return std::string(base_name_bytes.begin(), base_name_bytes.end());
}

} // namespace toruscsidh
