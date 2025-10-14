#ifndef TORUSCSIDH_CODE_INTEGRITY_H
#define TORUSCSIDH_CODE_INTEGRITY_H

#include <vector>
#include <string>
#include <map>
#include <mutex>
#include <chrono>
#include <ctime>
#include <filesystem>
#include "security_constants.h"
#include "postquantum_hash.h"

namespace toruscsidh {

/**
 * @brief Класс для защиты целостности системы
 * 
 * Реализует комплексную защиту целостности системы через:
 * 1. HMAC-проверку критических модулей
 * 2. Резервное копирование с шифрованием
 * 3. Самовосстановление при обнаружении аномалий
 * 4. Защищенное логирование всех операций
 * 
 * Все операции выполняются за постоянное время для защиты от атак по времени.
 */
class CodeIntegrityProtection {
public:
    /**
     * @brief Конструктор
     */
    CodeIntegrityProtection();
    
    /**
     * @brief Деструктор
     */
    ~CodeIntegrityProtection();
    
    /**
     * @brief Проверка целостности системы
     * 
     * Выполняет проверку целостности всех критических модулей.
     * 
     * @return true, если система цела
     */
    bool system_integrity_check();
    
    /**
     * @brief Самовосстановление системы
     * 
     * Пытается восстановить систему из последней резервной копии.
     * 
     * @return true, если восстановление прошло успешно
     */
    bool self_recovery();
    
    /**
     * @brief Обработка аномалии
     * 
     * Обрабатывает обнаруженную аномалию и принимает меры.
     * 
     * @param anomaly_type Тип аномалии
     * @param description Описание аномалии
     */
    void handle_anomaly(const std::string& anomaly_type, const std::string& description);
    
    /**
     * @brief Проверка, заблокирована ли система из-за аномалий
     * 
     * @return true, если система заблокирована
     */
    bool is_blocked() const;
    
    /**
     * @brief Сброс счетчика аномалий
     */
    void reset_anomaly_counter();
    
    /**
     * @brief Сохранение состояния для восстановления
     * 
     * Сохраняет текущее состояние системы для последующего восстановления.
     */
    void save_recovery_state();
    
    /**
     * @brief Обновление критериев безопасности с отложенной активацией
     * 
     * @param major_version Основная версия
     * @param minor_version Дополнительная версия
     * @param activation_time Время активации
     * @return true, если обновление запланировано успешно
     */
    bool update_criteria_version(int major_version, int minor_version, time_t activation_time);
    
    /**
     * @brief Проверка, является ли текущая версия критериев активной
     * 
     * @return true, если версия активна
     */
    bool is_criteria_version_active() const;
    
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
     * @brief Проверка, заблокирована ли система из-за аномалий
     * 
     * @return true, если система заблокирована
     */
    bool is_blocked_due_to_anomalies() const;
    
private:
    /**
     * @brief Проверка целостности системы с использованием HMAC
     * 
     * @return true, если система цела
     */
    bool verify_system_integrity();
    
    /**
     * @brief Восстановление из резервной копии с проверкой целостности
     * 
     * @return true, если восстановление прошло успешно
     */
    bool recover_from_backup();
    
    /**
     * @brief Инициализация ключа HMAC
     */
    void initialize_hmac_key();
    
    /**
     * @brief Подпись критических модулей
     */
    void sign_critical_modules();
    
    /**
     * @brief Проверка модуля
     * 
     * @param module_name Имя модуля
     * @param data Данные модуля
     * @param size Размер данных
     * @return true, если подпись верна
     */
    bool verify_module(const std::string& module_name, const void* data, size_t size);
    
    /**
     * @brief Подпись модуля
     * 
     * @param module_name Имя модуля
     * @param data Данные модуля
     * @param size Размер данных
     */
    void sign_module(const std::string& module_name, const void* data, size_t size);
    
    /**
     * @brief Загрузка модуля
     * 
     * @param module_name Имя модуля
     * @param data Данные модуля
     * @return true, если загрузка успешна
     */
    bool load_module(const std::string& module_name, std::vector<unsigned char>& data);
    
    /**
     * @brief Создание HMAC для данных
     * 
     * @param data Данные
     * @return HMAC значение
     */
    std::vector<unsigned char> create_hmac(const std::vector<unsigned char>& data) const;
    
    /**
     * @brief Получение оригинального HMAC для модуля
     * 
     * @param module_name Имя модуля
     * @return Оригинальный HMAC
     */
    std::vector<unsigned char> get_original_module_hmac(const std::string& module_name) const;
    
    /**
     * @brief Сохранение модуля в защищенное хранилище
     * 
     * @param module_name Имя модуля
     * @param module_data Данные модуля
     * @return true, если сохранение прошло успешно
     */
    bool save_module_to_secure_storage(const std::string& module_name,
                                    const std::vector<unsigned char>& module_data) const;
    
    /**
     * @brief Получение оригинального HMAC для модуля из защищенного хранилища
     * 
     * @param module_name Имя модуля
     * @return Оригинальный HMAC
     */
    std::vector<unsigned char> get_original_hmac_from_secure_storage(const std::string& module_name) const;
    
    /**
     * @brief Сохранение HMAC в защищенное хранилище
     * 
     * @param module_name Имя модуля
     * @param hmac HMAC значение
     * @return true, если сохранение прошло успешно
     */
    bool save_hmac_to_secure_storage(const std::string& module_name,
                                  const std::vector<unsigned char>& hmac) const;
    
    /**
     * @brief Создание зашифрованной резервной копии
     * 
     * @param backup_data Данные для резервной копии
     * @param encrypted_backup Зашифрованные данные резервной копии
     * @return true, если шифрование прошло успешно
     */
    bool create_encrypted_backup(const std::vector<unsigned char>& backup_data,
                               std::vector<unsigned char>& encrypted_backup) const;
    
    /**
     * @brief Расшифровка резервной копии
     * 
     * @param encrypted_backup Зашифрованные данные резервной копии
     * @param backup_data Данные резервной копии
     * @return true, если расшифровка прошла успешно
     */
    bool decrypt_backup(const std::vector<unsigned char>& encrypted_backup,
                      std::vector<unsigned char>& backup_data) const;
    
    /**
     * @brief Генерация соли для HMAC
     * 
     * @return Соль
     */
    std::vector<unsigned char> generate_hmac_salt() const;
    
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
     * @brief Получение ключа HMAC
     * 
     * @return Ключ HMAC
     */
    std::vector<unsigned char> get_hmac_key() const;
    
    /**
     * @brief Получение ключа для резервного копирования
     * 
     * @return Ключ для резервного копирования
     */
    std::vector<unsigned char> get_backup_key() const;
    
    /**
     * @brief Получение публичного ключа системы
     * 
     * @return Публичный ключ системы
     */
    std::vector<unsigned char> get_system_public_key() const;
    
    /**
     * @brief Проверка, требуется ли обновление критериев
     * 
     * @return true, если требуется обновление
     */
    bool is_criteria_update_required() const;
    
    /**
     * @brief Применение запланированного обновления критериев
     */
    void apply_scheduled_criteria_update();
    
    std::mutex integrity_mutex_; ///< Мьютекс для синхронизации
    bool is_blocked_; ///< Заблокирована ли система из-за аномалий
    size_t anomaly_count_; ///< Счетчик аномалий
    time_t last_anomaly_time_; ///< Время последней анономалии
    time_t last_recovery_time_; ///< Время последнего восстановления
    std::vector<unsigned char> hmac_key_; ///< Ключ HMAC для проверки целостности
    std::vector<unsigned char> backup_key_; ///< Ключ для резервного копирования
    std::vector<unsigned char> system_public_key_; ///< Публичный ключ системы
    std::map<std::string, std::vector<unsigned char>> module_hmacs_; ///< HMAC критических модулей
    std::vector<std::string> critical_modules_; ///< Критические модули системы
    int current_criteria_major_version_; ///< Текущая основная версия критериев
    int current_criteria_minor_version_; ///< Текущая дополнительная версия критериев
    int scheduled_criteria_major_version_; ///< Запланированная основная версия критериев
    int scheduled_criteria_minor_version_; ///< Запланированная дополнительная версия критериев
    time_t criteria_activation_time_; ///< Время активации запланированных критериев
};

} // namespace toruscsidh

#endif // TORUSCSIDH_CODE_INTEGRITY_H
