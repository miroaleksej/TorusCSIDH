#ifndef TORUSCSIDH_CODE_INTEGRITY_PROTECTION_H
#define TORUSCSIDH_CODE_INTEGRITY_PROTECTION_H

#include <vector>
#include <string>
#include <mutex>
#include <ctime>
#include <map>
#include <filesystem>
#include <sodium.h>
#include "security_constants.h"
#include "geometric_validator.h"
#include "secure_audit_logger.h"
#include "postquantum_hash.h"
#include "bech32m.h"

namespace toruscsidh {

/**
 * @brief Класс для защиты целостности кода
 * 
 * Обеспечивает защиту от модификации кода, самовосстановление из резервной копии
 * и детектирование аномалий в работе системы.
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
     * Проверяет HMAC всех критических модулей и проверяет целостность системы.
     * 
     * @return true, если система цела
     */
    bool system_integrity_check();
    
    /**
     * @brief Проверка целостности отдельного модуля
     * 
     * @param module_name Имя модуля
     * @param data Данные модуля
     * @param size Размер данных
     * @return true, если модуль цел
     */
    bool verify_module(const std::string& module_name, const void* data, size_t size);
    
    /**
     * @brief Подпись модуля
     * 
     * Создает и сохраняет HMAC для модуля.
     * 
     * @param module_name Имя модуля
     * @param data Данные модуля
     * @param size Размер данных
     */
    void sign_module(const std::string& module_name, const void* data, size_t size);
    
    /**
     * @brief Загрузка модуля
     * 
     * Загружает модуль из безопасного хранилища с проверкой целостности.
     * 
     * @param module_name Имя модуля
     * @param data Данные модуля (выходной параметр)
     * @return true, если загрузка успешна
     */
    bool load_module(const std::string& module_name, std::vector<unsigned char>& data);
    
    /**
     * @brief Самовосстановление системы из резервной копии
     * 
     * Пытается восстановить систему из резервной копии.
     * 
     * @return true, если восстановление прошло успешно
     */
    bool self_recovery();
    
    /**
     * @brief Сохранение состояния для восстановления
     * 
     * Сохраняет текущее состояние системы для последующего восстановления.
     */
    void save_recovery_state();
    
    /**
     * @brief Обновление критериев геометрической проверки
     * 
     * Безопасно обновляет критерии геометрической проверки.
     * 
     * @param major_version Основная версия
     * @param minor_version Дополнительная версия
     * @param valid_from Дата начала действия обновления
     * @return true, если обновление успешно
     */
    bool update_criteria_version(int major_version, int minor_version, time_t valid_from);
    
    /**
     * @brief Проверка, готова ли система к использованию
     * 
     * @return true, если система готова
     */
    bool is_system_ready() const;
    
    /**
     * @brief Получение HMAC ключа
     * 
     * @return HMAC ключ
     */
    const std::vector<unsigned char>& get_hmac_key() const;
    
    /**
     * @brief Получение ключа для резервного копирования
     * 
     * @return Ключ для резервного копирования
     */
    const std::vector<unsigned char>& get_backup_key() const;
    
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
     * @brief Получение времени последнего восстановления
     * 
     * @return Время последнего восстановления
     */
    time_t get_last_recovery_time() const;
    
    /**
     * @brief Получение времени последней резервной копии
     * 
     * @return Время последней резервной копии
     */
    time_t get_last_backup_time() const;
    
    /**
     * @brief Проверка, заблокирована ли система
     * 
     * @return true, если система заблокирована
     */
    bool is_system_blocked() const;
    
    /**
     * @brief Получение текущей версии критериев геометрической проверки
     * 
     * @param major_version Основная версия (выходной параметр)
     * @param minor_version Дополнительная версия (выходной параметр)
     * @param valid_from Дата начала действия (выходной параметр)
     */
    void get_criteria_version(int& major_version, int& minor_version, time_t& valid_from) const;
    
    /**
     * @brief Проверка, действительны ли текущие критерии геометрической проверки
     * 
     * @return true, если критерии действительны
     */
    bool are_criteria_valid() const;
    
    /**
     * @brief Подпись критических модулей
     * 
     * Создает HMAC для всех критических модулей.
     */
    void sign_critical_modules();
    
    /**
     * @brief Проверка HMAC для данных
     * 
     * @param data Данные
     * @param mac Проверяемый MAC
     * @return true, если MAC верен
     */
    bool verify_hmac(const std::vector<unsigned char>& data, const std::vector<unsigned char>& mac) const;
    
    /**
     * @brief Создание HMAC для данных
     * 
     * @param data Данные
     * @return HMAC
     */
    std::vector<unsigned char> create_hmac(const std::vector<unsigned char>& data) const;
    
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
     */
    void reset_anomaly_counter();
    
    /**
     * @brief Проверка, что система в нормальном состоянии
     * 
     * @return true, если система в нормальном состоянии
     */
    bool is_system_normal() const;
    
    /**
     * @brief Получение пути к каталогу модулей
     * 
     * @return Путь к каталогу модулей
     */
    const std::string& get_modules_directory() const;
    
    /**
     * @brief Получение пути к каталогу резервных копий
     * 
     * @return Путь к каталогу резервных копий
     */
    const std::string& get_backup_directory() const;
    
    /**
     * @brief Создание каталогов для системы
     */
    void create_system_directories();
    
    /**
     * @brief Проверка, что каталоги системы существуют
     * 
     * @return true, если каталоги существуют
     */
    bool system_directories_exist() const;
    
    /**
     * @brief Шифрование данных для резервной копии
     * 
     * @param data Данные для шифрования
     * @return Зашифрованные данные
     */
    std::vector<unsigned char> encrypt_backup_data(const std::vector<unsigned char>& data) const;
    
    /**
     * @brief Расшифровка данных резервной копии
     * 
     * @param encrypted_data Зашифрованные данные
     * @return Расшифрованные данные
     */
    std::vector<unsigned char> decrypt_backup_data(const std::vector<unsigned char>& encrypted_data) const;
    
    /**
     * @brief Проверка целостности резервной копии
     * 
     * @param backup_file Файл резервной копии
     * @return true, если резервная копия цела
     */
    bool verify_backup_integrity(const std::string& backup_file) const;
    
    /**
     * @brief Получение текущей даты и времени в формате строки
     * 
     * @return Строка с датой и временем
     */
    std::string get_current_datetime_str() const;
    
    /**
     * @brief Проверка, требуется ли обновление критериев
     * 
     * @return true, если требуется обновление
     */
    bool is_criteria_update_required() const;
    
    /**
     * @brief Получение информации о последнем обновлении критериев
     * 
     * @param update_time Время обновления (выходной параметр)
     * @param major_version Основная версия (выходной параметр)
     * @param minor_version Дополнительная версия (выходной параметр)
     */
    void get_criteria_update_info(time_t& update_time, int& major_version, int& minor_version) const;
    
private:
    /**
     * @brief Инициализация HMAC ключа
     */
    void initialize_hmac_key();
    
    /**
     * @brief Инициализация ключа для резервного копирования
     */
    void initialize_backup_key();
    
    /**
     * @brief Проверка, требуется ли восстановление системы
     * 
     * @return true, если требуется восстановление
     */
    bool is_recovery_needed() const;
    
    /**
     * @brief Выполнение восстановления системы
     * 
     * @return true, если восстановление прошло успешно
     */
    bool perform_recovery();
    
    /**
     * @brief Создание резервной копии текущего состояния
     */
    void create_backup();
    
    /**
     * @brief Проверка, истекло ли время действия текущих критериев
     * 
     * @return true, если время действия истекло
     */
    bool is_criteria_expired() const;
    
    /**
     * @brief Проверка, активно ли обновление критериев
     * 
     * @return true, если обновление активно
     */
    bool is_criteria_update_active() const;
    
    /**
     * @brief Сохранение данных в безопасное хранилище
     * 
     * @param module_name Имя модуля
     * @param module_data Данные модуля
     * @return true, если сохранение прошло успешно
     */
    bool save_module_to_secure_storage(const std::string& module_name,
                                    const std::vector<unsigned char>& module_data) const;
    
    /**
     * @brief Загрузка данных из безопасного хранилища
     * 
     * @param module_name Имя модуля
     * @param module_data Данные модуля (выходной параметр)
     * @return true, если загрузка успешна
     */
    bool load_module_from_secure_storage(const std::string& module_name,
                                      std::vector<unsigned char>& module_data) const;
    
    /**
     * @brief Проверка HMAC для модуля
     * 
     * @param module_name Имя модуля
     * @param data Данные модуля
     * @param size Размер данных
     * @param stored_mac Сохраненный HMAC
     * @return true, если HMAC верен
     */
    bool verify_module_hmac(const std::string& module_name,
                          const void* data,
                          size_t size,
                          const std::vector<unsigned char>& stored_mac) const;
    
    /**
     * @brief Создание HMAC для модуля
     * 
     * @param module_name Имя модуля
     * @param data Данные модуля
     * @param size Размер данных
     * @return HMAC
     */
    std::vector<unsigned char> create_module_hmac(const std::string& module_name,
                                                const void* data,
                                                size_t size) const;
    
    /**
     * @brief Получение пути к файлу модуля
     * 
     * @param module_name Имя модуля
     * @return Путь к файлу модуля
     */
    std::string get_module_file_path(const std::string& module_name) const;
    
    /**
     * @brief Получение пути к файлу резервной копии
     * 
     * @param backup_name Имя резервной копии
     * @return Путь к файлу резервной копии
     */
    std::string get_backup_file_path(const std::string& backup_name) const;
    
    /**
     * @brief Получение пути к файлу критериев геометрической проверки
     * 
     * @return Путь к файлу критериев
     */
    std::string get_criteria_file_path() const;
    
    /**
     * @brief Загрузка критериев геометрической проверки
     */
    void load_criteria();
    
    /**
     * @brief Сохранение критериев геометрической проверки
     */
    void save_criteria();
    
    /**
     * @brief Проверка, существует ли файл критериев
     * 
     * @return true, если файл существует
     */
    bool criteria_file_exists() const;
    
    /**
     * @brief Создание HMAC для критериев геометрической проверки
     * 
     * @param criteria Данные критериев
     * @return HMAC
     */
    std::vector<unsigned char> create_criteria_hmac(const std::vector<unsigned char>& criteria) const;
    
    /**
     * @brief Проверка HMAC для критериев геометрической проверки
     * 
     * @param criteria Данные критериев
     * @param mac Проверяемый MAC
     * @return true, если MAC верен
     */
    bool verify_criteria_hmac(const std::vector<unsigned char>& criteria,
                            const std::vector<unsigned char>& mac) const;
    
    /**
     * @brief Шифрование критериев геометрической проверки
     * 
     * @param criteria Данные критериев
     * @return Зашифрованные данные
     */
    std::vector<unsigned char> encrypt_criteria(const std::vector<unsigned char>& criteria) const;
    
    /**
     * @brief Расшифровка критериев геометрической проверки
     * 
     * @param encrypted_criteria Зашифрованные данные
     * @return Расшифрованные данные
     */
    std::vector<unsigned char> decrypt_criteria(const std::vector<unsigned char>& encrypted_criteria) const;
    
    /**
     * @brief Проверка, что критерии геометрической проверки не были изменены
     * 
     * @return true, если критерии не были изменены
     */
    bool verify_criteria_integrity() const;
    
    /**
     * @brief Проверка, что резервная копия не была изменена
     * 
     * @param backup_data Данные резервной копии
     * @return true, если резервная копия не была изменена
     */
    bool verify_backup_data_integrity(const std::vector<unsigned char>& backup_data) const;
    
    // Критические модули для проверки
    static const std::vector<std::string> CRITICAL_MODULES;
    
    // Мьютекс для синхронизации доступа
    std::mutex integrity_mutex_;
    
    // HMAC ключ для проверки целостности
    std::vector<unsigned char> hmac_key_;
    
    // Ключ для резервного копирования
    std::vector<unsigned char> backup_key_;
    
    // Флаг блокировки системы
    bool is_blocked_;
    
    // Счетчик аномалий
    int anomaly_count_;
    
    // Время последней аномалии
    time_t last_anomaly_time_;
    
    // Время последнего восстановления
    time_t last_recovery_time_;
    
    // Время последней резервной копии
    time_t last_backup_time_;
    
    // Версия критериев геометрической проверки
    int criteria_major_version_;
    int criteria_minor_version_;
    time_t criteria_valid_from_;
    
    // Время последнего обновления критериев
    time_t last_criteria_update_time_;
    
    // Каталог для модулей
    std::string modules_directory_;
    
    // Каталог для резервных копий
    std::string backup_directory_;
    
    // Константы безопасности
    static constexpr size_t HMAC_KEY_SIZE = 32;
    static constexpr size_t BACKUP_KEY_SIZE = 32;
    static constexpr size_t MAX_ANOMALY_COUNT = 3;
    static constexpr size_t ANOMALY_RESET_INTERVAL = 24 * 60 * 60; // 24 часа
    static constexpr size_t MAX_BACKUP_AGE = 7 * 24 * 60 * 60; // 7 дней
    static constexpr size_t MIN_CONSTANT_TIME_OPS = 1024;
    static constexpr size_t CONSTANT_TIME_SALT_SIZE = 64;
};

} // namespace toruscsidh

#endif // TORUSCSIDH_CODE_INTEGRITY_PROTECTION_H
