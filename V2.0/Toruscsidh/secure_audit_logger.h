#ifndef TORUSCSIDH_SECURE_AUDIT_LOGGER_H
#define TORUSCSIDH_SECURE_AUDIT_LOGGER_H

#include <string>
#include <vector>
#include <mutex>
#include <ctime>
#include <fstream>
#include <filesystem>
#include <sodium.h>
#include "security_constants.h"
#include "bech32m.h"
#include "postquantum_hash.h"

namespace toruscsidh {

/**
 * @brief Класс для безопасного аудита и логирования
 * 
 * Обеспечивает защищенное логирование событий с шифрованием, проверкой целостности
 * и защитой от атак по времени. Все операции с логами выполняются за постоянное время.
 */
class SecureAuditLogger {
public:
    /**
     * @brief Получение единственного экземпляра (Singleton)
     * 
     * @return Ссылка на экземпляр SecureAuditLogger
     */
    static SecureAuditLogger& get_instance();
    
    /**
     * @brief Инициализация системы аудита
     * 
     * @return true, если инициализация прошла успешно
     */
    bool initialize();
    
    /**
     * @brief Логирование события
     * 
     * @param category Категория события (security, system, key, signature)
     * @param message Сообщение для логирования
     * @param is_critical Является ли событие критическим
     */
    void log_event(const std::string& category, const std::string& message, bool is_critical);
    
    /**
     * @brief Обработка аномалии
     * 
     * Регистрирует аномалию и принимает меры в зависимости от серьезности.
     * 
     * @param anomaly_type Тип аномалии
     * @param description Описание аномалии
     */
    void handle_anomaly(const std::string& anomaly_type, const std::string& description);
    
    /**
     * @brief Сброс счетчика аномалий
     * 
     * Вызывается после успешного восстановления или при сбросе состояния.
     */
    void reset_anomaly_counter();
    
    /**
     * @brief Проверка, что система в нормальном состоянии
     * 
     * @return true, если система в нормальном состоянии
     */
    bool is_system_normal() const;
    
    /**
     * @brief Получение количества аномалий
     * 
     * @return Количество аномалий
     */
    int get_anomaly_count() const;
    
    /**
     * @brief Получение времени последней аномалии
     * 
     * @return Время последней аномалии
     */
    time_t get_last_anomaly_time() const;
    
    /**
     * @brief Шифрование имени файла журнала
     * 
     * @param filename Имя файла для шифрования
     * @return Зашифрованное имя файла
     */
    std::string encrypt_filename(const std::string& filename);
    
    /**
     * @brief Расшифровка имени файла журнала
     * 
     * @param encrypted_filename Зашифрованное имя файла
     * @return Расшифрованное имя файла
     */
    std::string decrypt_filename(const std::string& encrypted_filename);
    
    /**
     * @brief Проверка целостности журнала
     * 
     * @param log_file Файл журнала для проверки
     * @return true, если журнал цел
     */
    bool verify_log_integrity(const std::string& log_file);
    
    /**
     * @brief Получение зашифрованного содержимого журнала
     * 
     * @param log_file Файл журнала
     * @return Зашифрованное содержимое
     */
    std::vector<unsigned char> get_encrypted_log_content(const std::string& log_file);
    
    /**
     * @brief Запись зашифрованного содержимого в журнал
     * 
     * @param log_file Файл журнала
     * @param content Содержимое для записи
     * @return true, если запись прошла успешно
     */
    bool write_encrypted_log_content(const std::string& log_file, const std::vector<unsigned char>& content);
    
    /**
     * @brief Получение текущего уровня логирования
     * 
     * @return Уровень логирования
     */
    int get_log_level() const;
    
    /**
     * @brief Установка уровня логирования
     * 
     * @param level Уровень логирования
     */
    void set_log_level(int level);
    
    /**
     * @brief Очистка старых записей журнала
     * 
     * Удаляет записи старше указанного времени.
     * 
     * @param max_age Максимальный возраст записей в секундах
     */
    void clean_old_logs(time_t max_age);
    
    /**
     * @brief Получение защищенного ключа для шифрования журналов
     * 
     * @return Ключ для шифрования
     */
    const std::vector<unsigned char>& get_encryption_key() const;
    
    /**
     * @brief Получение HMAC ключа для проверки целостности журналов
     * 
     * @return HMAC ключ
     */
    const std::vector<unsigned char>& get_hmac_key() const;
    
    /**
     * @brief Создание HMAC для содержимого журнала
     * 
     * @param content Содержимое журнала
     * @return HMAC
     */
    std::vector<unsigned char> create_log_hmac(const std::vector<unsigned char>& content);
    
    /**
     * @brief Проверка HMAC содержимого журнала
     * 
     * @param content Содержимое журнала
     * @param mac Проверяемый MAC
     * @return true, если MAC верен
     */
    bool verify_log_hmac(const std::vector<unsigned char>& content, 
                        const std::vector<unsigned char>& mac);
    
    /**
     * @brief Обеспечение постоянного времени выполнения
     * 
     * Добавляет задержку, чтобы операция выполнялась за строго определенное время.
     * 
     * @param target_time Целевое время выполнения
     */
    void ensure_constant_time(const std::chrono::microseconds& target_time) const;
    
    /**
     * @brief Проверка, что операция выполнена за постоянное время
     * 
     * @return true, если операция выполнена за постоянное время
     */
    bool is_constant_time_operation() const;
    
    /**
     * @brief Генерация уникального идентификатора события
     * 
     * @return Уникальный идентификатор
     */
    std::string generate_event_id();
    
    /**
     * @brief Получение времени последней записи в журнал
     * 
     * @return Время последней записи
     */
    time_t get_last_log_time() const;
    
    /**
     * @brief Проверка, что журнал не переполнен
     * 
     * @return true, если журнал не переполнен
     */
    bool is_log_not_full() const;
    
    /**
     * @brief Получение максимального размера журнала
     * 
     * @return Максимальный размер в байтах
     */
    size_t get_max_log_size() const;
    
    /**
     * @brief Установка максимального размера журнала
     * 
     * @param size Максимальный размер в байтах
     */
    void set_max_log_size(size_t size);
    
private:
    // Конструктор и деструктор (Singleton)
    SecureAuditLogger();
    ~SecureAuditLogger();
    
    // Запрет копирования
    SecureAuditLogger(const SecureAuditLogger&) = delete;
    SecureAuditLogger& operator=(const SecureAuditLogger&) = delete;
    
    /**
     * @brief Создание каталога для журналов, если он не существует
     */
    void create_log_directory();
    
    /**
     * @brief Получение текущего файла журнала
     * 
     * @return Имя текущего файла журнала
     */
    std::string get_current_log_file();
    
    /**
     * @brief Шифрование содержимого журнала
     * 
     * @param content Содержимое для шифрования
     * @return Зашифрованное содержимое
     */
    std::vector<unsigned char> encrypt_log_content(const std::vector<unsigned char>& content);
    
    /**
     * @brief Расшифровка содержимого журнала
     * 
     * @param encrypted_content Зашифрованное содержимое
     * @return Расшифрованное содержимое
     */
    std::vector<unsigned char> decrypt_log_content(const std::vector<unsigned char>& encrypted_content);
    
    /**
     * @brief Проверка, что журнал готов к использованию
     * 
     * @return true, если журнал готов
     */
    bool is_log_ready() const;
    
    // Статический экземпляр (Singleton)
    static SecureAuditLogger* instance_;
    
    // Мьютекс для синхронизации доступа
    std::mutex log_mutex_;
    
    // Ключ для шифрования журналов
    std::vector<unsigned char> encryption_key_;
    
    // Ключ для HMAC проверки целостности
    std::vector<unsigned char> hmac_key_;
    
    // Каталог для журналов
    std::string log_directory_;
    
    // Текущий файл журнала
    std::string current_log_file_;
    
    // Счетчик аномалий
    int anomaly_count_;
    
    // Время последней аномалии
    time_t last_anomaly_time_;
    
    // Время последней записи в журнал
    time_t last_log_time_;
    
    // Уровень логирования
    int log_level_;
    
    // Максимальный размер журнала
    size_t max_log_size_;
    
    // Флаг инициализации
    bool is_initialized_;
    
    // Константы безопасности
    static constexpr size_t ENCRYPTION_KEY_SIZE = 32;
    static constexpr size_t HMAC_KEY_SIZE = 32;
    static constexpr size_t MAX_LOG_SIZE = 10 * 1024 * 1024; // 10 MB
    static constexpr int DEFAULT_LOG_LEVEL = 2; // 0 - none, 1 - errors, 2 - warnings, 3 - info, 4 - debug
    static constexpr size_t LOG_FILE_RETENTION = 30; // дней
    static constexpr size_t MAX_ANOMALY_COUNT = 3;
    static constexpr size_t ANOMALY_RESET_INTERVAL = 24 * 60 * 60; // 24 часа
};

} // namespace toruscsidh

#endif // TORUSCSIDH_SECURE_AUDIT_LOGGER_H
