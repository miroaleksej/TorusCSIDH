#ifndef TORUSCSIDH_CODE_INTEGRITY_PROTECTION_H
#define TORUSCSIDH_CODE_INTEGRITY_PROTECTION_H

#include <vector>
#include <string>
#include <map>
#include <mutex>
#include <ctime>
#include <unordered_set>
#include <sodium.h>
#include "security_constants.h"
#include "secure_audit_logger.h"

namespace toruscsidh {

/**
 * @brief Класс для проверки и восстановления целостности системы
 * 
 * Обеспечивает защиту от модификации кода и данных системы,
 * а также реализует механизм самовосстановления при обнаружении аномалий.
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
     * Проверяет HMAC всех критических модулей и данных.
     * 
     * @return true, если система цела
     */
    bool system_integrity_check();
    
    /**
     * @brief Самовосстановление системы из резервной копии
     * 
     * @return true, если восстановление прошло успешно
     */
    bool self_recovery();
    
    /**
     * @brief Сохранение состояния для восстановления
     * 
     * Создает защищенную резервную копию текущего состояния системы.
     */
    void save_recovery_state();
    
    /**
     * @brief Восстановление из резервной копии
     * 
     * @return true, если восстановление успешно
     */
    bool recover_from_backup();
    
    /**
     * @brief Обновление версии критериев безопасности
     * 
     * Планирует обновление критериев безопасности на будущее время.
     * 
     * @param major_version Основная версия
     * @param minor_version Дополнительная версия
     * @param activation_time Время активации
     * @return true, если обновление успешно запланировано
     */
    bool update_criteria_version(int major_version, int minor_version, time_t activation_time);
    
    /**
     * @brief Проверка, готова ли система к использованию
     * 
     * Учитывает аномалии, блокировки и состояние целостности.
     * 
     * @return true, если система готова к использованию
     */
    bool is_system_ready() const;
    
    /**
     * @brief Подпись модуля
     * 
     * Создает HMAC для модуля и сохраняет его в защищенном хранилище.
     * 
     * @param module_name Имя модуля
     * @param data Данные модуля
     * @param size Размер данных
     */
    void sign_module(const std::string& module_name, const void* data, size_t size);
    
    /**
     * @brief Проверка подписи модуля
     * 
     * Проверяет HMAC модуля с использованием защищенных ключей.
     * 
     * @param module_name Имя модуля
     * @param data Данные модуля
     * @param size Размер данных
     * @return true, если подпись верна
     */
    bool verify_module(const std::string& module_name, const void* data, size_t size);
    
    /**
     * @brief Проверка HMAC с использованием BLAKE3
     * 
     * @param key Ключ HMAC
     * @param data Данные для проверки
     * @param mac Проверяемый MAC
     * @return true, если HMAC верен
     */
    bool verify_hmac_blake3(const std::vector<unsigned char>& key, 
                          const std::vector<unsigned char>& data,
                          const std::vector<unsigned char>& mac) const;
    
    /**
     * @brief Сравнение в постоянное время
     * 
     * Защищает от атак по времени при сравнении секретных данных.
     * 
     * @param a Первый буфер
     * @param b Второй буфер
     * @param len Длина буферов
     */
    void constant_time_compare(const unsigned char* a, const unsigned char* b, size_t len) const;
    
    /**
     * @brief Обновление критических компонентов
     * 
     * Используется при активации новой версии критериев безопасности.
     */
    void update_critical_components();
    
    /**
     * @brief Проверка аномалий
     * 
     * @return true, если система в нормальном состоянии
     */
    bool check_anomalies() const;
    
    /**
     * @brief Сброс счетчика аномалий
     * 
     * Вызывается после успешного восстановления или при сбросе состояния.
     */
    void reset_anomaly_counter();

private:
    /**
     * @brief Инициализация критических модулей
     * 
     * Определяет, какие модули требуют защиты целостности.
     */
    void initialize_critical_modules();
    
    /**
     * @brief Загрузка модуля из защищенного хранилища
     * 
     * @param module_name Имя модуля
     * @param data Данные модуля
     * @return true, если загрузка успешна
     */
    bool load_module(const std::string& module_name, std::vector<unsigned char>& data);
    
    /**
     * @brief Обработка аномалии
     * 
     * Регистрирует аномалию и принимает меры в зависимости от серьезности.
     * 
     * @param anomaly_type Тип аномалии
     * @param description Описание аномалии
     */
    void handle_anomaly(const std::string& anomaly_type, const std::string& description);
    
    // Критические модули, требующие защиты целостности
    std::unordered_set<std::string> critical_modules_;
    
    // Ключ HMAC для проверки целостности
    std::vector<unsigned char> hmac_key_;
    
    // Ключ для шифрования резервных копий
    std::vector<unsigned char> backup_key_;
    
    // Состояние блокировки системы
    bool is_blocked_;
    
    // Счетчик аномалий
    int anomaly_count_;
    
    // Время последней аномалии
    time_t last_anomaly_time_;
    
    // Время последней резервной копии
    time_t last_backup_time_;
    
    // Время последнего восстановления
    time_t last_recovery_time_;
    
    // Мьютекс для синхронизации доступа
    mutable std::mutex integrity_mutex_;
    
    // Планируемая новая версия критериев
    struct PendingCriteriaVersion {
        int major_version;
        int minor_version;
        time_t activation_time;
    } pending_criteria_version_;
    
    // Текущая версия критериев
    struct CurrentCriteriaVersion {
        int major_version;
        int minor_version;
        time_t activation_time;
    } current_criteria_version_;
    
    // Константы безопасности
    static constexpr int MAX_ANOMALY_COUNT = 3;
    static constexpr int ANOMALY_RESET_INTERVAL = 24 * 60 * 60; // 24 часа
};

} // namespace toruscsidh

#endif // TORUSCSIDH_CODE_INTEGRITY_PROTECTION_H
