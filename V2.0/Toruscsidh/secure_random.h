#ifndef TORUSCSIDH_SECURE_RANDOM_H
#define TORUSCSIDH_SECURE_RANDOM_H

#include <vector>
#include <gmpxx.h>
#include <sodium.h>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <cmath>
#include "security_constants.h"
#include "rfc6979_rng.h"

namespace toruscsidh {

/**
 * @brief Класс для безопасной генерации случайных чисел
 * 
 * Обеспечивает криптографически безопасную генерацию случайных чисел
 * с защитой от утечек через побочные каналы.
 */
class SecureRandom {
public:
    /**
     * @brief Безопасная очистка памяти
     * 
     * Заполняет память случайными данными перед очисткой,
     * чтобы предотвратить восстановление секретных данных.
     * 
     * @param ptr Указатель на память
     * @param len Длина памяти в байтах
     */
    static void secure_clean_memory(void* ptr, size_t len);
    
    /**
     * @brief Генерация случайных байтов
     * 
     * Использует libsodium для генерации криптографически безопасных случайных чисел.
     * 
     * @param length Длина требуемых случайных данных
     * @return Вектор случайных байтов
     */
    static std::vector<unsigned char> generate_random_bytes(size_t length);
    
    /**
     * @brief Генерация случайного числа в заданном диапазоне
     * 
     * Генерирует случайное число в диапазоне [0, max).
     * Использует rejection sampling для обеспечения равномерного распределения.
     * 
     * @param max Максимальное значение (не включая)
     * @return Случайное число
     */
    static GmpRaii generate_random_mpz(const GmpRaii& max);
    
    /**
     * @brief Генерация случайного числа в диапазоне для CSIDH
     * 
     * Генерирует случайное число, соответствующее критериям безопасности CSIDH.
     * 
     * @param security_level Уровень безопасности
     * @param params Параметры безопасности
     * @return Случайный ключ CSIDH
     */
    static std::vector<short> generate_csidh_key(SecurityConstants::SecurityLevel security_level,
                                              const SecurityConstants::CSIDHParams& params);
    
    /**
     * @brief Генерация случайной точки на кривой
     * 
     * Генерирует случайную точку на эллиптической кривой заданного порядка.
     * 
     * @param curve Эллиптическая кривая
     * @param order Порядок точки
     * @return Случайная точка
     */
    static EllipticCurvePoint generate_random_point(const MontgomeryCurve& curve, 
                                                 unsigned int order);
    
    /**
     * @brief Обеспечение постоянного времени выполнения
     * 
     * Добавляет задержку, чтобы операция выполнялась за строго определенное время,
     * предотвращая атаки по времени.
     * 
     * @param target_time Целевое время выполнения
     */
    static void ensure_constant_time(const std::chrono::microseconds& target_time);
    
    /**
     * @brief Проверка, является ли операция выполненной за постоянное время
     * 
     * @return true, если операция выполнена за постоянное время
     */
    static bool is_constant_time_operation();
    
    /**
     * @brief Генерация случайного числа с использованием RFC6979
     * 
     * Использует детерминированный алгоритм RFC6979 для генерации случайного числа.
     * 
     * @param private_key Приватный ключ
     * @param message Хешированное сообщение
     * @param curve_params Параметры кривой
     * @return Случайное число
     */
    static GmpRaii generate_rfc6979_random(const GmpRaii& private_key,
                                        const std::vector<unsigned char>& message,
                                        const SecurityConstants::CurveParams& curve_params);
    
    /**
     * @brief Генерация случайного числа для эфемерного ключа
     * 
     * Генерирует случайное число для эфемерного ключа с учетом ограничений безопасности.
     * 
     * @param security_level Уровень безопасности
     * @param params Параметры безопасности
     * @return Эфемерный ключ
     */
    static std::vector<short> generate_ephemeral_key(SecurityConstants::SecurityLevel security_level,
                                                  const SecurityConstants::CSIDHParams& params);
    
    /**
     * @brief Получение системного времени в микросекундах
     * 
     * @return Текущее время в микросекундах
     */
    static uint64_t get_current_time_us();
    
    /**
     * @brief Инициализация безопасного генератора
     * 
     * Инициализирует внутренние состояния генератора.
     */
    static void initialize();
    
    /**
     * @brief Деинициализация безопасного генератора
     * 
     * Очищает внутренние состояния генератора.
     */
    static void finalize();
    
    /**
     * @brief Генерация случайного числа в диапазоне для геометрического валидатора
     * 
     * Генерирует случайное число, соответствующее требованиям геометрического валидатора.
     * 
     * @param min Минимальное значение
     * @param max Максимальное значение
     * @return Случайное число
     */
    static GmpRaii generate_geometric_random(const GmpRaii& min, const GmpRaii& max);
    
    /**
     * @brief Проверка качества случайных чисел
     * 
     * Проводит статистические тесты на качество генерируемых случайных чисел.
     * 
     * @return true, если качество случайных чисел удовлетворительно
     */
    static bool check_random_quality();
    
    /**
     * @brief Генерация случайного бита
     * 
     * Генерирует случайный бит (0 или 1).
     * 
     * @return Случайный бит
     */
    static bool generate_random_bit();
    
    /**
     * @brief Генерация случайного числа с заданным весом
     * 
     * Генерирует случайное число с учетом заданного веса для защиты от атак.
     * 
     * @param max Максимальное значение
     * @param weight Вес
     * @return Случайное число
     */
    static GmpRaii generate_weighted_random(const GmpRaii& max, double weight);
    
    /**
     * @brief Проверка, что операция выполняется за постоянное время
     * 
     * @return true, если операция выполняется за постоянное время
     */
    static bool is_constant_time();
    
private:
    /**
     * @brief Проверка инициализации libsodium
     */
    static void check_sodium_initialized();
    
    /**
     * @brief Генерация случайного числа с использованием rejection sampling
     * 
     * @param max Максимальное значение
     * @return Случайное число
     */
    static GmpRaii rejection_sampling(const GmpRaii& max);
    
    /**
     * @brief Вычисление обратного элемента по модулю
     * 
     * @param a Число
     * @param p Модуль
     * @return Обратный элемент
     */
    static GmpRaii mod_inverse(const GmpRaii& a, const GmpRaii& p);
    
    /**
     * @brief Расширенный алгоритм Евклида
     * 
     * @param a Первое число
     * @param b Второе число
     * @param g НОД
     * @param x Коэффициент
     * @param y Коэффициент
     */
    static void extended_gcd(const GmpRaii& a, const GmpRaii& b, GmpRaii& g, GmpRaii& x, GmpRaii& y);
    
    // Флаг инициализации
    static bool is_initialized_;
    
    // Внутренний счетчик для обеспечения постоянного времени
    static uint64_t operation_counter_;
    
    // Константы безопасности
    static constexpr size_t MAX_RETRIES = 1000;
    static constexpr double MAX_WEIGHT = 1.5;
    static constexpr double MIN_WEIGHT = 0.5;
};

} // namespace toruscsidh

#endif // TORUSCSIDH_SECURE_RANDOM_H
