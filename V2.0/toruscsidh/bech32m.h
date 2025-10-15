#ifndef TORUSCSIDH_BECH32M_H
#define TORUSCSIDH_BECH32M_H

#include <string>
#include <vector>

namespace bech32m {

/**
 * @brief Кодирование в формат Bech32m
 * 
 * @param hrp Человекочитаемая часть
 * @param values Значения для кодирования
 * @return Закодированная строка
 */
std::string encode(const std::string& hrp, const std::vector<unsigned char>& values);

/**
 * @brief Декодирование из формата Bech32m
 * 
 * @param encoded Закодированная строка
 * @param hrp_out Человекочитаемая часть
 * @param values_out Значения
 * @return true, если декодирование прошло успешно
 */
bool decode(const std::string& encoded, std::string& hrp_out, std::vector<unsigned char>& values_out);

/**
 * @brief Создание контрольной суммы Bech32m
 * 
 * @param hrp Человекочитаемая часть
 * @param values Значения
 * @return Контрольная сумма
 */
std::vector<unsigned char> create_checksum(const std::string& hrp, const std::vector<unsigned char>& values);

/**
 * @brief Проверка контрольной суммы Bech32m
 * 
 * @param hrp Человекочитаемая часть
 * @param values Значения
 * @return true, если контрольная сумма верна
 */
bool verify_checksum(const std::string& hrp, const std::vector<unsigned char>& values);

/**
 * @brief Полиномиальное модулярное умножение для Bech32m
 * 
 * @param values Значения
 * @param generator Генератор
 * @return Результат полиномиального умножения
 */
unsigned int polymod(const std::vector<unsigned char>& values, const unsigned int* generator);

/**
 * @brief Преобразование 8-битных данных в 5-битные
 * 
 * @param data 8-битные данные
 * @param pad Добавление нулей
 * @return 5-битные данные
 */
std::vector<unsigned char> convert_bits(const std::vector<unsigned char>& data, bool pad = true);

/**
 * @brief Преобразование 5-битных данных в 8-битные
 * 
 * @param data 5-битные данные
 * @param pad Добавление нулей
 * @return 8-битные данные
 */
std::vector<unsigned char> convert_bits_back(const std::vector<unsigned char>& data, bool pad = true);

} // namespace bech32m

#endif // TORUSCSIDH_BECH32M_H
