#ifndef SECURE_AUDIT_LOGGER_H
#define SECURE_AUDIT_LOGGER_H

#include <fstream>
#include <string>
#include <mutex>
#include <vector>
#include <ctime>
#include <sodium.h>
#include "security_constants.h"
#include "code_integrity.h"
#include "postquantum_hash.h"

/**
 * @brief Класс для безопасного аудита системы
 */
class SecureAuditLogger {
public:
    /**
     * @brief Получение единственного экземпляра (Singleton)
     * @return Указатель на экземпляр
     */
    static SecureAuditLogger& get_instance();
    
    /**
     * @brief Запись события в журнал аудита
     * @param event_type Тип события
     * @param message Сообщение
     * @param is_critical Является ли событие критическим
     */
    void log_event(const std::string& event_type, 
                  const std::string& message, 
                  bool is_critical);
    
    /**
     * @brief Установка уровня логирования
     * @param level Уровень логирования
     */
    void set_log_level(int level);
    
    /**
     * @brief Получение текущего уровня логирования
     * @return Уровень логирования
     */
    int get_log_level() const;
    
    /**
     * @brief Закрытие журнала
     */
    void close();

private:
    std::ofstream log_file;            ///< Файл журнала
    std::mutex log_mutex;              ///< Мьютекс для защиты журнала
    int log_level;                     ///< Уровень логирования
    CodeIntegrityProtection& code_integrity; ///< Ссылка на систему целостности
    
    /**
     * @brief Конструктор
     */
    SecureAuditLogger();
    
    /**
     * @brief Деструктор
     */
    ~SecureAuditLogger();
    
    /**
     * @brief Инициализация журнала
     * @return true, если инициализация прошла успешно
     */
    bool initialize();
    
    /**
     * @brief Шифрование имени файла журнала
     * @param filename Имя файла
     * @return Зашифрованное имя файла
     */
    std::string encrypt_filename(const std::string& filename);
    
    /**
     * @brief Расшифровка имени файла журнала
     * @param encrypted_name Зашифрованное имя файла
     * @return Расшифрованное имя файла
     */
    std::string decrypt_filename(const std::string& encrypted_name);
};

SecureAuditLogger::SecureAuditLogger()
    : log_level(1), 
      code_integrity(CodeIntegrityProtection::getInstance()) {
    
    if (!initialize()) {
        throw std::runtime_error("Failed to initialize audit logger");
    }
}

SecureAuditLogger::~SecureAuditLogger() {
    close();
}

SecureAuditLogger& SecureAuditLogger::get_instance() {
    static SecureAuditLogger instance;
    return instance;
}

void SecureAuditLogger::log_event(const std::string& event_type, 
                                 const std::string& message, 
                                 bool is_critical) {
    std::lock_guard<std::mutex> lock(log_mutex);
    
    if (!log_file.is_open()) {
        if (!initialize()) {
            return;
        }
    }
    
    // Проверка целостности системы перед логированием
    if (!code_integrity.system_integrity_check()) {
        if (!code_integrity.self_recovery()) {
            return;
        }
    }
    
    // Форматирование времени
    time_t now = time(nullptr);
    struct tm timeinfo;
    localtime_r(&now, &timeinfo);
    
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &timeinfo);
    
    // Формирование записи
    std::string log_entry = std::string(time_str) + " [" + event_type + "] " + message;
    if (is_critical) {
        log_entry += " [CRITICAL]";
    }
    log_entry += "\n";
    
    // Шифрование записи перед записью в файл
    std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    
    std::vector<unsigned char> plaintext(log_entry.begin(), log_entry.end());
    std::vector<unsigned char> ciphertext(plaintext.size() + crypto_secretbox_MACBYTES);
    
    crypto_secretbox_easy(ciphertext.data(), 
                         plaintext.data(), 
                         plaintext.size(), 
                         nonce.data(), 
                         code_integrity.get_backup_key().data());
    
    // Запись в файл
    log_file.write(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    log_file.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    log_file.flush();
}

void SecureAuditLogger::set_log_level(int level) {
    std::lock_guard<std::mutex> lock(log_mutex);
    log_level = level;
}

int SecureAuditLogger::get_log_level() const {
    return log_level;
}

void SecureAuditLogger::close() {
    std::lock_guard<std::mutex> lock(log_mutex);
    if (log_file.is_open()) {
        log_file.close();
    }
}

bool SecureAuditLogger::initialize() {
    // Проверка целостности системы перед инициализацией
    if (!code_integrity.system_integrity_check()) {
        return false;
    }
    
    // Генерация безопасного имени файла лога
    std::string log_filename = "toruscsidh_audit_" + std::to_string(time(nullptr)) + ".log";
    std::string encrypted_name = encrypt_filename(log_filename);
    
    // Декодирование для открытия файла
    std::string decrypted_name = decrypt_filename(encrypted_name);
    
    // Открытие файла
    log_file.open(decrypted_name, std::ios::app | std::ios::binary);
    return log_file.is_open();
}

std::string SecureAuditLogger::encrypt_filename(const std::string& filename) {
    std::string encrypted_name = filename;
    for (size_t i = 0; i < encrypted_name.size(); i++) {
        encrypted_name[i] ^= (i % 256);
    }
    return encrypted_name;
}

std::string SecureAuditLogger::decrypt_filename(const std::string& encrypted_name) {
    std::string decrypted_name = encrypted_name;
    for (size_t i = 0; i < decrypted_name.size(); i++) {
        decrypted_name[i] ^= (i % 256);
    }
    return decrypted_name;
}

#endif // SECURE_AUDIT_LOGGER_H
