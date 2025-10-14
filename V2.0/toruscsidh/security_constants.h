#ifndef TORUSCSIDH_SECURITY_CONSTANTS_H
#define TORUSCSIDH_SECURITY_CONSTANTS_H

#include <vector>
#include <gmpxx.h>
#include <map>
#include <chrono>
#include "elliptic_curve.h"

namespace toruscsidh {

/**
 * @brief Класс для хранения констант безопасности
 * 
 * Содержит параметры безопасности для различных уровней защиты.
 */
class SecurityConstants {
public:
    /**
     * @brief Уровни безопасности
     */
    enum SecurityLevel {
        LEVEL_128,  ///< 128-битная безопасность
        LEVEL_192,  ///< 192-битная безопасность
        LEVEL_256   ///< 256-битная безопасность
    };
    
    /**
     * @brief Параметры безопасности для конкретного уровня
     */
    struct SecurityParams {
        int num_primes;              ///< Количество простых чисел
        int max_key_magnitude;       ///< Максимальная величина ключа (L∞ норма)
        int max_key_sum;             ///< Максимальная сумма ключа (L1 норма)
        int geometric_radius;        ///< Радиус подграфа для геометрической проверки
        std::vector<GmpRaii> primes; ///< Простые числа для изогений
    };
    
    /**
     * @brief Параметры геометрической проверки
     */
    struct GeometricParams {
        double min_cyclomatic;       ///< Минимальное цикломатическое число
        double min_spectral_gap;     ///< Минимальный спектральный зазор
        double min_clustering_coeff; ///< Минимальный коэффициент кластеризации
        double min_degree_entropy;   ///< Минимальная энтропия степеней
        double min_distance_entropy; ///< Минимальная энтропия расстояний
        int geometric_radius;        ///< Радиус подграфа для анализа
    };
    
    /**
     * @brief Константы для постквантовой безопасности
     */
    static const size_t HASH_SIZE = 64;                ///< Размер хеша
    static const size_t SIGNATURE_SIZE = 96;           ///< Размер подписи
    static const size_t ADDRESS_SIZE = 32;             ///< Размер адреса
    static const size_t HMAC_KEY_SIZE = 64;            ///< Размер ключа HMAC
    static const size_t BACKUP_KEY_SIZE = 32;          ///< Размер ключа резервного копирования
    static const size_t SYSTEM_PUBLIC_KEY_SIZE = 64;   ///< Размер публичного ключа системы
    static const size_t SALT_SIZE = 32;                ///< Размер соли
    static const size_t ENCRYPTION_KEY_SIZE = 32;      ///< Размер ключа шифрования
    static const size_t MESSAGE_HASH_SIZE = 64;        ///< Размер хеша сообщения
    static const size_t MIN_POSTQUANTUM_HASH_SIZE = 48; ///< Минимальный размер постквантового хеша
    static const size_t MIN_POSTQUANTUM_HMAC_SIZE = 48; ///< Минимальный размер постквантового HMAC
    
    /**
     * @brief Константы для защиты от атак
     */
    static const size_t MAX_ANOMALY_COUNT = 3;         ///< Максимальное количество аномалий
    static const time_t ANOMALY_RESET_INTERVAL = 3600; ///< Интервал сброса счетчика аномалий (1 час)
    static const size_t MAX_POINTS_TO_TRY = 1000;      ///< Максимальное количество попыток поиска точки
    static const size_t MAX_RFC6979_RETRIES = 10;      ///< Максимальное количество попыток генерации k по RFC 6979
    static const size_t MIN_KEY_PATTERN_LEN = 4;       ///< Минимальная длина регулярного паттерна
    static const size_t MAX_CONSECUTIVE_SAME = 10;     ///< Максимальное количество одинаковых последовательных значений
    static const double WEAK_KEY_THRESHOLD = 0.7;      ///< Порог для определения слабых ключей
    
    /**
     * @brief Константы для обеспечения постоянного времени
     */
    static const size_t CONSTANT_TIME_SALT_SIZE = 64;  ///< Размер соли для постоянного времени
    static const size_t MIN_CONSTANT_TIME_OPS = 1024;  ///< Минимальное количество операций
    
    /**
     * @brief Целевые времена выполнения операций
     */
    static const std::chrono::microseconds SIGN_TARGET_TIME;
    static const std::chrono::microseconds VERIFY_TARGET_TIME;
    
    /**
     * @brief Получение параметров безопасности для уровня
     * 
     * @param level Уровень безопасности
     * @return Параметры безопасности
     */
    static const SecurityParams& get_params(SecurityLevel level);
    
    /**
     * @brief Получение простых чисел для уровня
     * 
     * @param level Уровень безопасности
     * @return Вектор простых чисел
     */
    static const std::vector<GmpRaii>& get_primes(SecurityLevel level);
    
    /**
     * @brief Получение максимальной величины ключа для уровня
     * 
     * @param level Уровень безопасности
     * @return Максимальная величина ключа
     */
    static int get_max_key_magnitude(SecurityLevel level);
    
    /**
     * @brief Получение максимальной суммы ключа для уровня
     * 
     * @param level Уровень безопасности
     * @return Максимальная сумма ключа
     */
    static int get_max_key_sum(SecurityLevel level);
    
    /**
     * @brief Получение базовой кривой для уровня
     * 
     * @param level Уровень безопасности
     * @return Базовая кривая
     */
    static MontgomeryCurve get_base_curve(SecurityLevel level);
    
    /**
     * @brief Получение базового простого числа
     * 
     * @return Базовое простое число
     */
    static GmpRaii get_base_prime();
    
    /**
     * @brief Инициализация параметров безопасности
     * 
     * @param level Уровень безопасности
     * @param params Параметры безопасности
     */
    static void initialize_geometric_params(SecurityLevel level, GeometricParams& params);
    
    /**
     * @brief Получение параметров геометрической проверки
     * 
     * @param level Уровень безопасности
     * @return Параметры геометрической проверки
     */
    static const GeometricParams& get_geometric_params(SecurityLevel level);
    
    /**
     * @brief Преобразование уровня безопасности в строку
     * 
     * @param level Уровень безопасности
     * @return Строковое представление уровня
     */
    static std::string security_level_to_string(SecurityLevel level);
    
    /**
     * @brief Получение количества простых чисел для уровня
     * 
     * @param level Уровень безопасности
     * @return Количество простых чисел
     */
    static int get_num_primes(SecurityLevel level);
    
private:
    static std::map<SecurityLevel, SecurityParams> security_params_; ///< Параметры безопасности
    static std::map<SecurityLevel, GeometricParams> geometric_params_; ///< Параметры геометрической проверки
    
    /**
     * @brief Инициализация параметров безопасности
     */
    static void initialize_security_params();
    
    /**
     * @brief Инициализация параметров геометрической проверки
     */
    static void initialize_geometric_params();
};

} // namespace toruscsidh

#endif // TORUSCSIDH_SECURITY_CONSTANTS_H
