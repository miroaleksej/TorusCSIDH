#ifndef TORUSCSIDH_SECURE_AUDIT_LOGGER_H
#define TORUSCSIDH_SECURE_AUDIT_LOGGER_H

#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include <fstream>
#include <sstream>
#include "security_constants.h"
#include "code_integrity.h"

namespace toruscsidh {

/**
 * @brief Класс для безопасного аудит-логирования
 * 
 * Реализует защищенное логирование событий с защитой от утечек информации.
 * Все операции выполняются за постоянное время для защиты от атак по времени.
 */
class SecureAuditLogger {
public:
    /**
     * @brief Получение экземпляра логгера (Singleton)
     * 
     * @return Ссылка на экземпляр логгера
     */
    static SecureAuditLogger& get_instance();
    
    /**
     * @brief Деструктор
     */
    ~SecureAuditLogger();
    
    /**
     * @brief Логирование события
     * 
     * @param category Категория события
     * @param message Сообщение
     * @param security_event Является ли событие связанным с безопасностью
     */
    void log_event(const std::string& category,
                  const std::string& message,
                  bool security_event);
    
    /**
     * @brief Проверка, что логгер инициализирован
     * 
     * @return true, если логгер инициализирован
     */
    bool is_initialized() const;
    
    /**
     * @brief Получение времени последнего логирования
     * 
     * @return Время последнего логирования
     */
    std::chrono::system_clock::time_point get_last_log_time() const;
    
    /**
     * @brief Получение количества записей в логе
     * 
     * @return Количество записей в логе
     */
    size_t get_log_entry_count() const;
    
    /**
     * @brief Очистка лога
     */
    void clear_log();
    
    /**
     * @brief Сохранение лога в защищенное хранилище
     * 
     * @return true, если сохранение прошло успешно
     */
    bool save_log();
    
    /**
     * @brief Загрузка лога из защищенного хранилища
     * 
     * @return true, если загрузка прошла успешно
     */
    bool load_log();
    
    /**
     * @brief Проверка целостности лога
     * 
     * @return true, если лог цел
     */
    bool verify_log_integrity();
    
    /**
     * @brief Шифрование лога
     * 
     * @param log_data Данные лога
     * @param encrypted_log Зашифрованные данные лога
     * @return true, если шифрование прошло успешно
     */
    bool encrypt_log(const std::vector<unsigned char>& log_data,
                    std::vector<unsigned char>& encrypted_log);
    
    /**
     * @brief Расшифровка лога
     * 
     * @param encrypted_log Зашифрованные данные лога
     * @param log_data Данные лога
     * @return true, если расшифровка прошла успешно
     */
    bool decrypt_log(const std::vector<unsigned char>& encrypted_log,
                    std::vector<unsigned char>& log_data);
    
    /**
     * @brief Создание HMAC для данных лога
     * 
     * @param log_data Данные лога
     * @return HMAC значение
     */
    std::vector<unsigned char> create_log_hmac(const std::vector<unsigned char>& log_data);
    
    /**
     * @brief Проверка HMAC лога
     * 
     * @param log_data Данные лога
     * @param hmac HMAC значение
     * @return true, если HMAC верен
     */
    bool verify_log_hmac(const std::vector<unsigned char>& log_data,
                        const std::vector<unsigned char>& hmac);
    
    /**
     * @brief Получение ключа шифрования лога
     * 
     * @return Ключ шифрования лога
     */
    std::vector<unsigned char> get_log_encryption_key() const;
    
    /**
     * @brief Получение ключа HMAC для лога
     * 
     * @return Ключ HMAC для лога
     */
    std::vector<unsigned char> get_log_hmac_key() const;
    
    /**
     * @brief Получение времени последней аномалии
     * 
     * @return Время последней аномалии
     */
    time_t get_last_anomaly_time() const;
    
    /**
     * @brief Получение счетчика аномалий
     * 
     * @return Счетчик аномалий
     */
    size_t get_anomaly_count() const;
    
    /**
     * @brief Получение времени последнего восстановления
     * 
     * @return Время последнего восстановления
     */
    time_t get_last_recovery_time() const;
    
    /**
     * @brief Получение времени последней проверки целостности
     * 
     * @return Время последней проверки целостности
     */
    time_t get_last_integrity_check_time() const;
    
    /**
     * @brief Получение количества проверок целостности
     * 
     * @return Количество проверок целостности
     */
    size_t get_integrity_check_count() const;
    
    /**
     * @brief Получение количества успешных проверок целостности
     * 
     * @return Количество успешных проверок целостности
     */
    size_t get_successful_integrity_checks() const;
    
    /**
     * @brief Получение количества неуспешных проверок целостности
     * 
     * @return Количество неуспешных проверок целостности
     */
    size_t get_failed_integrity_checks() const;
    
    /**
     * @brief Получение времени последнего обновления критериев
     * 
     * @return Время последнего обновления критериев
     */
    time_t get_last_criteria_update_time() const;
    
    /**
     * @brief Получение текущей версии критериев
     * 
     * @param major_version Основная версия
     * @param minor_version Дополнительная версия
     */
    void get_current_criteria_version(int& major_version, int& minor_version) const;
    
    /**
     * @brief Получение запланированной версии критериев
     * 
     * @param major_version Основная версия
     * @param minor_version Дополнительная версия
     * @param activation_time Время активации
     */
    void get_scheduled_criteria_version(int& major_version, int& minor_version, time_t& activation_time) const;
    
    /**
     * @brief Получение уровня безопасности
     * 
     * @return Уровень безопасности
     */
    SecurityConstants::SecurityLevel get_security_level() const;
    
    /**
     * @brief Проверка, что логгер готов к работе
     * 
     * @return true, если логгер готов к работе
     */
    bool is_ready() const;
    
    /**
     * @brief Получение текущего состояния системы
     * 
     * @return Текущее состояние системы
     */
    std::string get_system_status() const;
    
    /**
     * @brief Получение информации о безопасности системы
     * 
     * @return Информация о безопасности системы
     */
    std::string get_security_info() const;
    
    /**
     * @brief Получение статистики по безопасности
     * 
     * @return Статистика по безопасности
     */
    std::string get_security_statistics() const;
    
private:
    /**
     * @brief Конструктор
     */
    SecureAuditLogger();
    
    /**
     * @brief Инициализация логгера
     * 
     * @return true, если инициализация прошла успешно
     */
    bool initialize();
    
    /**
     * @brief Закрытие логгера
     */
    void close();
    
    /**
     * @brief Форматирование времени
     * 
     * @param time_point Точка времени
     * @return Форматированное время
     */
    std::string format_time(const std::chrono::system_clock::time_point& time_point) const;
    
    /**
     * @brief Форматирование сообщения лога
     * 
     * @param category Категория
     * @param message Сообщение
     * @param security_event Является ли событие связанным с безопасностью
     * @return Форматированное сообщение
     */
    std::string format_log_message(const std::string& category,
                                 const std::string& message,
                                 bool security_event) const;
    
    /**
     * @brief Защищенное стирание данных
     * 
     * @param data Данные для стирания
     */
    void secure_wipe(std::vector<unsigned char>& data) const;
    
    /**
     * @brief Защищенное стирание строки
     * 
     * @param str Строка для стирания
     */
    void secure_wipe(std::string& str) const;
    
    /**
     * @brief Создание зашифрованного имени файла
     * 
     * @param base_name Базовое имя файла
     * @return Зашифрованное имя файла
     */
    std::string encrypt_filename(const std::string& base_name);
    
    /**
     * @brief Расшифровка имени файла
     * 
     * @param encrypted_name Зашифрованное имя файла
     * @return Расшифрованное имя файла
     */
    std::string decrypt_filename(const std::string& encrypted_name);
    
    bool initialized_; ///< Инициализирован ли логгер
    bool closed_; ///< Закрыт ли логгер
    std::mutex logger_mutex_; ///< Мьютекс для синхронизации
    std::vector<unsigned char> encryption_key_; ///< Ключ шифрования
    std::vector<unsigned char> hmac_key_; ///< Ключ HMAC
    std::string log_file_path_; ///< Путь к файлу лога
    std::ofstream log_file_; ///< Файл лога
    std::chrono::system_clock::time_point last_log_time_; ///< Время последнего логирования
    size_t log_entry_count_; ///< Количество записей в логе
    time_t last_anomaly_time_; ///< Время последней аномалии
    size_t anomaly_count_; ///< Счетчик аномалий
    time_t last_recovery_time_; ///< Время последнего восстановления
    time_t last_integrity_check_time_; ///< Время последней проверки целостности
    size_t integrity_check_count_; ///< Количество проверок целостности
    size_t successful_integrity_checks_; ///< Количество успешных проверок целостности
    size_t failed_integrity_checks_; ///< Количество неуспешных проверок целостности
    time_t last_criteria_update_time_; ///< Время последнего обновления критериев
    int current_criteria_major_version_; ///< Текущая основная версия критериев
    int current_criteria_minor_version_; ///< Текущая дополнительная версия критериев
    int scheduled_criteria_major_version_; ///< Запланированная основная версия критериев
    int scheduled_criteria_minor_version_; ///< Запланированная дополнительная версия критериев
    time_t criteria_activation_time_; ///< Время активации запланированных критериев
    SecurityConstants::SecurityLevel security_level_; ///< Уровень безопасности
    CodeIntegrityProtection* code_integrity_; ///< Указатель на систему целостности
};

} // namespace toruscsidh

#endif // TORUSCSIDH_SECURE_AUDIT_LOGGER_H
