#ifndef TORUSCSIDH_POSTQUANTUM_HASH_H
#define TORUSCSIDH_POSTQUANTUM_HASH_H

#include <vector>
#include <string>
#include <gmpxx.h>
#include <blake3.h>
#include "security_constants.h"
#include "secure_random.h"

namespace toruscsidh {

/**
 * @brief Класс для постквантового хеширования
 * 
 * Реализует безопасные постквантовые хеш-функции с защитой от квантовых атак.
 * Основан на BLAKE3 - современной криптографической хеш-функции, которая
 * является кандидатом в постквантовые хеш-функции.
 */
class PostQuantumHash {
public:
    /**
     * @brief Хеширование данных
     * 
     * Выполняет хеширование входных данных с использованием BLAKE3.
     * 
     * @param data Данные для хеширования
     * @param output_size Размер выходного хеша в байтах
     * @return Хеш-значение
     */
    static std::vector<unsigned char> hash(const std::vector<unsigned char>& data, 
                                         size_t output_size = SecurityConstants::HASH_SIZE);
    
    /**
     * @brief Хеширование строки
     * 
     * Выполняет хеширование входной строки с использованием BLAKE3.
     * 
     * @param str Строка для хеширования
     * @param output_size Размер выходного хеша в байтах
     * @return Хеш-значение
     */
    static std::vector<unsigned char> hash_string(const std::string& str, 
                                                size_t output_size = SecurityConstants::HASH_SIZE);
    
    /**
     * @brief Хеширование данных в GMP число
     * 
     * Выполняет хеширование входных данных и преобразует результат в GMP число.
     * 
     * @param data Данные для хеширования
     * @param modulus Модуль для ограничения размера числа
     * @return Хеш-значение в виде GMP числа
     */
    static GmpRaii hash_to_gmp(const std::vector<unsigned char>& data, const GmpRaii& modulus);
    
    /**
     * @brief Хеширование данных в GMP число с использованием RFC6979
     * 
     * Выполняет детерминированное хеширование по RFC6979 для генерации случайных чисел.
     * 
     * @param private_key Приватный ключ
     * @param message Хешированное сообщение
     * @param curve_params Параметры кривой
     * @return Случайное число в виде GMP числа
     */
    static GmpRaii rfc6979_hash(const GmpRaii& private_key,
                             const std::vector<unsigned char>& message,
                             const SecurityConstants::CurveParams& curve_params);
    
    /**
     * @brief Проверка целостности хеш-функции
     * 
     * Проверяет, что хеш-функция работает корректно и не была модифицирована.
     * 
     * @return true, если хеш-функция цела
     */
    static bool verify_integrity();
    
    /**
     * @brief Получение размера хеша
     * 
     * @return Размер хеша в байтах
     */
    static size_t get_hash_size();
    
    /**
     * @brief Получение версии BLAKE3
     * 
     * @return Версия BLAKE3
     */
    static std::string get_blake3_version();
    
    /**
     * @brief Хеширование с использованием ключевого хеширования
     * 
     * Выполняет ключевое хеширование с использованием BLAKE3.
     * 
     * @param key Ключ для хеширования
     * @param data Данные для хеширования
     * @param output_size Размер выходного хеша в байтах
     * @return Хеш-значение
     */
    static std::vector<unsigned char> keyed_hash(const std::vector<unsigned char>& key,
                                               const std::vector<unsigned char>& data,
                                               size_t output_size = SecurityConstants::HASH_SIZE);
    
    /**
     * @brief Хеширование с использованием деривационного хеширования
     * 
     * Выполняет деривационное хеширование с использованием BLAKE3.
     * 
     * @param context Контекст деривации
     * @param data Данные для хеширования
     * @param output_size Размер выходного хеша в байтах
     * @return Хеш-значение
     */
    static std::vector<unsigned char> derive_key(const std::string& context,
                                               const std::vector<unsigned char>& data,
                                               size_t output_size = SecurityConstants::HASH_SIZE);
    
    /**
     * @brief Проверка, что хеш-функция устойчива к квантовым атакам
     * 
     * @return true, если хеш-функция устойчива к квантовым атакам
     */
    static bool is_quantum_resistant();
    
    /**
     * @brief Вычисление HMAC с использованием BLAKE3
     * 
     * @param key Ключ HMAC
     * @param data Данные для вычисления HMAC
     * @return HMAC значение
     */
    static std::vector<unsigned char> hmac(const std::vector<unsigned char>& key,
                                         const std::vector<unsigned char>& data);
    
    /**
     * @brief Проверка HMAC с использованием BLAKE3
     * 
     * @param key Ключ HMAC
     * @param data Данные
     * @param mac Проверяемый HMAC
     * @return true, если HMAC верен
     */
    static bool verify_hmac(const std::vector<unsigned char>& key,
                          const std::vector<unsigned char>& data,
                          const std::vector<unsigned char>& mac);
    
    /**
     * @brief Вычисление деривированного ключа
     * 
     * @param master_key Мастер-ключ
     * @param context Контекст деривации
     * @param output_size Размер выходного ключа
     * @return Деривированный ключ
     */
    static std::vector<unsigned char> derive_key_from_master(const std::vector<unsigned char>& master_key,
                                                           const std::string& context,
                                                           size_t output_size);
    
    /**
     * @brief Проверка, что хеш-функция соответствует стандартам безопасности
     * 
     * @return true, если хеш-функция соответствует стандартам
     */
    static bool meets_security_standards();
    
    /**
     * @brief Проверка на коллизии
     * 
     * Проверяет, что хеш-функция имеет низкую вероятность коллизий.
     * 
     * @return true, если вероятность коллизий низкая
     */
    static bool check_collision_resistance();
    
    /**
     * @brief Проверка на вторичные прообразы
     * 
     * Проверяет, что хеш-функция устойчива ко вторичным прообразам.
     * 
     * @return true, если устойчивость ко вторичным прообразам достаточна
     */
    static bool check_second_preimage_resistance();
    
    /**
     * @brief Проверка на прообразы
     * 
     * Проверяет, что хеш-функция устойчива к атакам на прообразы.
     * 
     * @return true, если устойчивость к атакам на прообразы достаточна
     */
    static bool check_preimage_resistance();
    
    /**
     * @brief Вычисление хеша с использованием дополнительных данных
     * 
     * @param data Данные для хеширования
     * @param personalization Персонализация
     * @param output_size Размер выходного хеша
     * @return Хеш-значение
     */
    static std::vector<unsigned char> hash_with_personalization(const std::vector<unsigned char>& data,
                                                              const std::string& personalization,
                                                              size_t output_size = SecurityConstants::HASH_SIZE);
    
    /**
     * @brief Вычисление хеша с использованием дополнительных данных и ключа
     * 
     * @param key Ключ
     * @param data Данные для хеширования
     * @param personalization Персонализация
     * @param output_size Размер выходного хеша
     * @return Хеш-значение
     */
    static std::vector<unsigned char> keyed_hash_with_personalization(const std::vector<unsigned char>& key,
                                                                    const std::vector<unsigned char>& data,
                                                                    const std::string& personalization,
                                                                    size_t output_size = SecurityConstants::HASH_SIZE);
    
    /**
     * @brief Проверка, что хеш-функция устойчива к дифференциальным атакам
     * 
     * @return true, если хеш-функция устойчива к дифференциальным атакам
     */
    static bool check_differential_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к линейным атакам
     * 
     * @return true, если хеш-функция устойчива к линейным атакам
     */
    static bool check_linear_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе квантовых алгоритмов
     * 
     * @return true, если хеш-функция устойчива к квантовым атакам
     */
    static bool check_quantum_attack_resistance();
    
    /**
     * @brief Вычисление хеша с использованием расширения Merkle-Damgård
     * 
     * @param data Данные для хеширования
     * @param output_size Размер выходного хеша
     * @return Хеш-значение
     */
    static std::vector<unsigned char> merkle_damgard_hash(const std::vector<unsigned char>& data,
                                                        size_t output_size = SecurityConstants::HASH_SIZE);
    
    /**
     * @brief Вычисление хеша с использованием дерева Меркла
     * 
     * @param data Данные для хеширования
     * @param output_size Размер выходного хеша
     * @return Хеш-значение
     */
    static std::vector<unsigned char> merkle_tree_hash(const std::vector<unsigned char>& data,
                                                     size_t output_size = SecurityConstants::HASH_SIZE);
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий
     */
    static bool check_collision_search_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска вторичных прообразов
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск вторичных прообразов
     */
    static bool check_second_preimage_search_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска прообразов
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск прообразов
     */
    static bool check_preimage_search_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом
     */
    static bool check_fixed_prefix_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным окончанием
     */
    static bool check_fixed_suffix_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным префиксом и суффиксом
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным префиксом и суффиксом
     */
    static bool check_fixed_prefix_suffix_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным средним участком
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным средним участком
     */
    static bool check_fixed_middle_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом и окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом и окончанием
     */
    static bool check_fixed_begin_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом, средним участком и окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом, средним участком и окончанием
     */
    static bool check_fixed_begin_middle_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом и произвольным средним участком
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом и произвольным средним участком
     */
    static bool check_fixed_begin_arbitrary_middle_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным окончанием и произвольным средним участком
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным окончанием и произвольным средним участком
     */
    static bool check_fixed_end_arbitrary_middle_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом и произвольным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом и произвольным окончанием
     */
    static bool check_fixed_begin_arbitrary_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным окончанием и произвольным началом
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным окончанием и произвольным началом
     */
    static bool check_fixed_end_arbitrary_begin_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным средним участком и произвольным началом и окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным средним участком и произвольным началом и окончанием
     */
    static bool check_fixed_middle_arbitrary_begin_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом, произвольным средним участком и фиксированным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом, произвольным средним участком и фиксированным окончанием
     */
    static bool check_fixed_begin_arbitrary_middle_fixed_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом, фиксированным средним участком и произвольным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом, фиксированным средним участком и произвольным окончанием
     */
    static bool check_fixed_begin_fixed_middle_arbitrary_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с произвольным началом, фиксированным средним участком и фиксированным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с произвольным началом, фиксированным средним участком и фиксированным окончанием
     */
    static bool check_arbitrary_begin_fixed_middle_fixed_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с произвольным началом, фиксированным средним участком и произвольным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с произвольным началом, фиксированным средним участком и произвольным окончанием
     */
    static bool check_arbitrary_begin_fixed_middle_arbitrary_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с произвольным началом, произвольным средним участком и фиксированным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с произвольным началом, произвольным средним участком и фиксированным окончанием
     */
    static bool check_arbitrary_begin_arbitrary_middle_fixed_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с произвольным началом, произвольным средним участком и произвольным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с произвольным началом, произвольным средним участком и произвольным окончанием
     */
    static bool check_arbitrary_begin_arbitrary_middle_arbitrary_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом и фиксированным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом и фиксированным окончанием
     */
    static bool check_fixed_begin_fixed_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом, произвольным средним участком и произвольным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом, произвольным средним участком и произвольным окончанием
     */
    static bool check_fixed_begin_arbitrary_middle_arbitrary_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с произвольным началом, фиксированным средним участком и произвольным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с произвольным началом, фиксированным средним участком и произвольным окончанием
     */
    static bool check_arbitrary_begin_fixed_middle_arbitrary_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с произвольным началом, произвольным средним участком и фиксированным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с произвольным началом, произвольным средним участком и фиксированным окончанием
     */
    static bool check_arbitrary_begin_arbitrary_middle_fixed_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом, фиксированным средним участком и произвольным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом, фиксированным средним участком и произвольным окончанием
     */
    static bool check_fixed_begin_fixed_middle_arbitrary_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с произвольным началом, фиксированным средним участком и фиксированным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с произвольным началом, фиксированным средним участком и фиксированным окончанием
     */
    static bool check_arbitrary_begin_fixed_middle_fixed_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом, произвольным средним участком и фиксированным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом, произвольным средним участком и фиксированным окончанием
     */
    static bool check_fixed_begin_arbitrary_middle_fixed_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом, произвольным средним участком и произвольным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом, произвольным средним участком и произвольным окончанием
     */
    static bool check_fixed_begin_arbitrary_middle_arbitrary_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с произвольным началом, фиксированным средним участком и произвольным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с произвольным началом, фиксированным средним участком и произвольным окончанием
     */
    static bool check_arbitrary_begin_fixed_middle_arbitrary_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с произвольным началом, произвольным средним участком и фиксированным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с произвольным началом, произвольным средним участком и фиксированным окончанием
     */
    static bool check_arbitrary_begin_arbitrary_middle_fixed_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с произвольным началом, фиксированным средним участком и фиксированным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с произвольным началом, фиксированным средним участком и фиксированным окончанием
     */
    static bool check_arbitrary_begin_fixed_middle_fixed_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом, фиксированным средним участком и фиксированным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом, фиксированным средним участком и фиксированным окончанием
     */
    static bool check_fixed_begin_fixed_middle_fixed_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом, фиксированным средним участком и произвольным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом, фиксированным средним участком и произвольным окончанием
     */
    static bool check_fixed_begin_fixed_middle_arbitrary_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с произвольным началом, фиксированным средним участком и произвольным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с произвольным началом, фиксированным средним участком и произвольным окончанием
     */
    static bool check_arbitrary_begin_fixed_middle_arbitrary_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с произвольным началом, произвольным средним участком и фиксированным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с произвольным началом, произвольным средним участком и фиксированным окончанием
     */
    static bool check_arbitrary_begin_arbitrary_middle_fixed_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с произвольным началом, фиксированным средним участком и фиксированным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с произвольным началом, фиксированным средним участком и фиксированным окончанием
     */
    static bool check_arbitrary_begin_fixed_middle_fixed_end_collision_resistance();
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом, фиксированным средним участком и фиксированным окончанием
     * 
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом, фиксированным средним участком и фиксированным окончанием
     */
    static bool check_fixed_begin_fixed_middle_fixed_end_collision_resistance();
    
private:
    /**
     * @brief Инициализация BLAKE3
     */
    static void initialize_blake3();
    
    /**
     * @brief Проверка, инициализирована ли BLAKE3
     * 
     * @return true, если BLAKE3 инициализирована
     */
    static bool is_blake3_initialized();
    
    /**
     * @brief Вычисление хеша с использованием BLAKE3
     * 
     * @param data Данные для хеширования
     * @param output_size Размер выходного хеша в байтах
     * @param key Ключ для ключевого хеширования (может быть пустым)
     * @param context Контекст для деривационного хеширования (может быть пустым)
     * @param personalization Персонализация (может быть пустой)
     * @return Хеш-значение
     */
    static std::vector<unsigned char> blake3_hash_internal(const std::vector<unsigned char>& data,
                                                         size_t output_size,
                                                         const std::vector<unsigned char>& key = {},
                                                         const std::string& context = "",
                                                         const std::string& personalization = "");
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом и фиксированным окончанием
     * 
     * @param prefix Фиксированный префикс
     * @param suffix Фиксированный суффикс
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом и фиксированным окончанием
     */
    static bool check_fixed_prefix_fixed_suffix_collision_resistance(const std::vector<unsigned char>& prefix,
                                                                  const std::vector<unsigned char>& suffix);
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом, фиксированным средним участком и фиксированным окончанием
     * 
     * @param prefix Фиксированный префикс
     * @param middle Фиксированный средний участок
     * @param suffix Фиксированный суффикс
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом, фиксированным средним участком и фиксированным окончанием
     */
    static bool check_fixed_prefix_fixed_middle_fixed_suffix_collision_resistance(const std::vector<unsigned char>& prefix,
                                                                               const std::vector<unsigned char>& middle,
                                                                               const std::vector<unsigned char>& suffix);
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом, фиксированным средним участком и произвольным окончанием
     * 
     * @param prefix Фиксированный префикс
     * @param middle Фиксированный средний участок
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом, фиксированным средним участком и произвольным окончанием
     */
    static bool check_fixed_prefix_fixed_middle_arbitrary_suffix_collision_resistance(const std::vector<unsigned char>& prefix,
                                                                                   const std::vector<unsigned char>& middle);
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с произвольным началом, фиксированным средним участком и фиксированным окончанием
     * 
     * @param middle Фиксированный средний участок
     * @param suffix Фиксированный суффикс
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с произвольным началом, фиксированным средним участком и фиксированным окончанием
     */
    static bool check_arbitrary_prefix_fixed_middle_fixed_suffix_collision_resistance(const std::vector<unsigned char>& middle,
                                                                                   const std::vector<unsigned char>& suffix);
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с произвольным началом, фиксированным средним участком и произвольным окончанием
     * 
     * @param middle Фиксированный средний участок
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с произвольным началом, фиксированным средним участком и произвольным окончанием
     */
    static bool check_arbitrary_prefix_fixed_middle_arbitrary_suffix_collision_resistance(const std::vector<unsigned char>& middle);
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с произвольным началом, произвольным средним участком и фиксированным окончанием
     * 
     * @param suffix Фиксированный суффикс
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с произвольным началом, произвольным средним участком и фиксированным окончанием
     */
    static bool check_arbitrary_prefix_arbitrary_middle_fixed_suffix_collision_resistance(const std::vector<unsigned char>& suffix);
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом, произвольным средним участком и фиксированным окончанием
     * 
     * @param prefix Фиксированный префикс
     * @param suffix Фиксированный суффикс
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом, произвольным средним участком и фиксированным окончанием
     */
    static bool check_fixed_prefix_arbitrary_middle_fixed_suffix_collision_resistance(const std::vector<unsigned char>& prefix,
                                                                                   const std::vector<unsigned char>& suffix);
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом, произвольным средним участком и произвольным окончанием
     * 
     * @param prefix Фиксированный префикс
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом, произвольным средним участком и произвольным окончанием
     */
    static bool check_fixed_prefix_arbitrary_middle_arbitrary_suffix_collision_resistance(const std::vector<unsigned char>& prefix);
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с произвольным началом, фиксированным средним участком и произвольным окончанием
     * 
     * @param middle Фиксированный средний участок
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с произвольным началом, фиксированным средним участком и произвольным окончанием
     */
    static bool check_arbitrary_prefix_fixed_middle_arbitrary_suffix_collision_resistance(const std::vector<unsigned char>& middle);
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с произвольным началом, произвольным средним участком и фиксированным окончанием
     * 
     * @param suffix Фиксированный суффикс
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с произвольным началом, произвольным средним участком и фиксированным окончанием
     */
    static bool check_arbitrary_prefix_arbitrary_middle_fixed_suffix_collision_resistance(const std::vector<unsigned char>& suffix);
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с произвольным началом, фиксированным средним участком и фиксированным окончанием
     * 
     * @param middle Фиксированный средний участок
     * @param suffix Фиксированный суффикс
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с произвольным началом, фиксированным средним участком и фиксированным окончанием
     */
    static bool check_arbitrary_prefix_fixed_middle_fixed_suffix_collision_resistance(const std::vector<unsigned char>& middle,
                                                                                   const std::vector<unsigned char>& suffix);
    
    /**
     * @brief Проверка, что хеш-функция устойчива к атакам на основе поиска коллизий с фиксированным началом, фиксированным средним участком и фиксированным окончанием
     * 
     * @param prefix Фиксированный префикс
     * @param middle Фиксированный средний участок
     * @param suffix Фиксированный суффикс
     * @return true, если хеш-функция устойчива к атакам на поиск коллизий с фиксированным началом, фиксированным средним участком и фиксированным окончанием
     */
    static bool check_fixed_prefix_fixed_middle_fixed_suffix_collision_resistance(const std::vector<unsigned char>& prefix,
                                                                               const std::vector<unsigned char>& middle,
                                                                               const std::vector<unsigned char>& suffix);
    
    // Статические переменные
    static bool blake3_initialized_;
    static size_t hash_size_;
    static std::string blake3_version_;
};

} // namespace toruscsidh

#endif // TORUSCSIDH_POSTQUANTUM_HASH_H
