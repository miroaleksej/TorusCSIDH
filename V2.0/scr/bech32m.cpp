#ifndef BECH32M_H
#define BECH32M_H

#include <vector>
#include <string>
#include <cstdint>

/**
 * @brief Создание контрольной суммы Bech32m
 * @param hrp Человекочитаемая часть
 * @param values Значения
 * @return Контрольная сумма
 */
std::vector<uint8_t> bech32m_create_checksum(const std::string& hrp, const std::vector<uint8_t>& values);

/**
 * @brief Кодирование в Bech32m
 * @param hrp Человекочитаемая часть
 * @param values Значения
 * @return Закодированная строка
 */
std::string bech32m_encode(const std::string& hrp, const std::vector<uint8_t>& values);

/**
 * @brief Декодирование из Bech32m
 * @param encoded Закодированная строка
 * @param hrp_out Человекочитаемая часть (выход)
 * @param values_out Значения (выход)
 * @return true, если декодирование успешно
 */
bool bech32m_decode(const std::string& encoded, std::string& hrp_out, std::vector<uint8_t>& values_out);

#endif // BECH32M_H
