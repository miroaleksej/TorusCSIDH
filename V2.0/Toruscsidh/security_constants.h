#ifndef TORUSCSIDH_SECURITY_CONSTANTS_H
#define TORUSCSIDH_SECURITY_CONSTANTS_H

#include <vector>
#include <gmpxx.h>
#include "elliptic_curve.h"

namespace toruscsidh {

/**
 * @brief Пространство имен для констант безопасности
 * 
 * Содержит параметры безопасности для различных уровней защиты.
 */
namespace SecurityConstants {
    
    /**
     * @brief Уровень безопасности
     */
    enum class SecurityLevel {
        LEVEL_128,  // 128 бит безопасности
        LEVEL_192,  // 192 бит безопасности
        LEVEL_256   // 256 бит безопасности
    };
    
    /**
     * @brief Параметры эллиптической кривой
     */
    struct CurveParams {
        GmpRaii p;  // Характеристика поля
        GmpRaii A;  // Параметр кривой
        GmpRaii B;  // Параметр кривой
    };
    
    /**
     * @brief Параметры CSIDH
     */
    struct CSIDHParams {
        std::vector<GmpRaii> primes;  // Простые числа для изогений
        int max_Linf;                  // Максимальная L∞ норма ключа
        int max_L1;                    // Максимальная L1 норма ключа
        double min_cyclomatic;         // Минимальное цикломатическое число
        double min_spectral_gap;       // Минимальный спектральный зазор
        double min_clustering_coeff;   // Минимальный коэффициент кластеризации
        double min_degree_entropy;     // Минимальная энтропия распределения степеней
        double min_distance_entropy;   // Минимальная энтропия расстояний
    };
    
    // Общие константы безопасности
    static constexpr size_t HASH_SIZE = 32;                 // Размер хеша в байтах
    static constexpr size_t HMAC_KEY_SIZE = 32;             // Размер HMAC ключа в байтах
    static constexpr size_t HMAC_SIZE = 32;                 // Размер HMAC в байтах
    static constexpr size_t MIN_SIGNATURE_SIZE = 64;        // Минимальный размер подписи в байтах
    static constexpr size_t ADDRESS_DATA_SIZE = 32;         // Размер данных адреса в байтах
    static constexpr size_t SIGNING_TIME = 10000;           // Время подписания в микросекундах
    static constexpr size_t VERIFICATION_TIME = 15000;      // Время верификации в микросекундах
    static constexpr size_t RFC6979_TIME = 8000;            // Время выполнения RFC6979 в микросекундах
    static constexpr size_t MIN_ENTROPY_BITS = 256;         // Минимальная энтропия в битах
    static constexpr size_t MIN_KEY_PATTERN_LEN = 4;        // Минимальная длина регулярного паттерна
    static constexpr size_t MAX_CONSECUTIVE_128 = 12;       // Максимальное количество подряд идущих одинаковых знаков для 128 бит
    static constexpr size_t MAX_CONSECUTIVE_192 = 15;       // Максимальное количество подряд идущих одинаковых знаков для 192 бит
    static constexpr size_t MAX_CONSECUTIVE_256 = 18;       // Максимальное количество подряд идущих одинаковых знаков для 256 бит
    static constexpr size_t MODULES_DIR_SIZE = 256;         // Размер буфера для каталога модулей
    static constexpr size_t BACKUP_DIR_SIZE = 256;          // Размер буфера для каталога резервных копий
    
    // Каталоги
    static constexpr const char* MODULES_DIR = "./secure_modules";
    static constexpr const char* BACKUP_DIR = "./secure_backups";
    
    // Параметры для геометрической проверки
    static constexpr double MIN_CYCLOMATIC_NUMBER_128 = 1.95;
    static constexpr double MIN_CYCLOMATIC_NUMBER_192 = 1.97;
    static constexpr double MIN_CYCLOMATIC_NUMBER_256 = 1.99;
    
    static constexpr double MIN_SPECTRAL_GAP_128 = 0.15;
    static constexpr double MIN_SPECTRAL_GAP_192 = 0.18;
    static constexpr double MIN_SPECTRAL_GAP_256 = 0.22;
    
    static constexpr double MIN_CLUSTERING_COEFF_128 = 0.35;
    static constexpr double MIN_CLUSTERING_COEFF_192 = 0.40;
    static constexpr double MIN_CLUSTERING_COEFF_256 = 0.45;
    
    static constexpr double MIN_DEGREE_ENTROPY_128 = 0.75;
    static constexpr double MIN_DEGREE_ENTROPY_192 = 0.80;
    static constexpr double MIN_DEGREE_ENTROPY_256 = 0.85;
    
    static constexpr double MIN_DISTANCE_ENTROPY_128 = 0.65;
    static constexpr double MIN_DISTANCE_ENTROPY_192 = 0.70;
    static constexpr double MIN_DISTANCE_ENTROPY_256 = 0.75;
    
    static constexpr double MAX_PATH_LENGTH_RATIO_128 = 0.75;
    static constexpr double MAX_PATH_LENGTH_RATIO_192 = 0.70;
    static constexpr double MAX_PATH_LENGTH_RATIO_256 = 0.65;
    
    // Параметры для проверки ключей
    static constexpr int MAX_LINF_128 = 19;
    static constexpr int MAX_L1_128 = 256;
    
    static constexpr int MAX_LINF_192 = 24;
    static constexpr int MAX_L1_192 = 320;
    
    static constexpr int MAX_LINF_256 = 28;
    static constexpr int MAX_L1_256 = 384;
    
    // Параметры для защиты от атак по времени
    static constexpr size_t ANOMALY_RESET_INTERVAL = 24 * 60 * 60; // 24 часа в секундах
    
    /**
     * @brief Получение параметров безопасности для указанного уровня
     * 
     * @param level Уровень безопасности
     * @return Параметры безопасности
     */
    CSIDHParams get_csidh_params(SecurityLevel level);
    
    /**
     * @brief Получение максимальной L∞ нормы для уровня безопасности
     * 
     * @param level Уровень безопасности
     * @return Максимальная L∞ норма
     */
    int get_max_linf(SecurityLevel level);
    
    /**
     * @brief Получение максимальной L1 нормы для уровня безопасности
     * 
     * @param level Уровень безопасности
     * @return Максимальная L1 норма
     */
    int get_max_l1(SecurityLevel level);
    
    /**
     * @brief Получение базовой кривой для уровня безопасности
     * 
     * @param level Уровень безопасности
     * @return Базовая кривая
     */
    MontgomeryCurve get_base_curve(SecurityLevel level);
    
    /**
     * @brief Инициализация параметров безопасности
     */
    void initialize();
    
    /**
     * @brief Проверка, инициализированы ли параметры безопасности
     * 
     * @return true, если параметры инициализированы
     */
    bool is_initialized();
}

} // namespace toruscsidh

#endif // TORUSCSIDH_SECURITY_CONSTANTS_H
