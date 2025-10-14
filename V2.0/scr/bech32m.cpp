#include "bech32m.h"
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <stdexcept>

// Полином для Bech32m
const uint32_t BECH32M_GENERATOR[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

/**
 * @brief Вычисление контрольной суммы Bech32m
 * @param values Значения
 * @param generator Генератор
 * @return Контрольная сумма
 */
uint32_t bech32m_polymod(const std::vector<uint8_t>& values, const uint32_t* generator) {
    uint32_t chk = 1;
    for (uint8_t v : values) {
        uint8_t top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ v;
        
        for (int i = 0; i < 5; i++) {
            if ((top >> i) & 1) {
                chk ^= generator[i];
            }
        }
    }
    
    return chk;
}

std::vector<uint8_t> bech32m_create_checksum(const std::string& hrp, const std::vector<uint8_t>& values) {
    std::vector<uint8_t> encoding;
    
    // Добавляем HRP в последовательность
    for (char c : hrp) {
        encoding.push_back(c >> 5);
    }
    encoding.push_back(0); // Сепаратор
    for (char c : hrp) {
        encoding.push_back(c & 0x1f);
    }
    
    // Добавляем данные
    encoding.insert(encoding.end(), values.begin(), values.end());
    
    // Добавляем фиксированные значения для контрольной суммы
    encoding.push_back(0);
    encoding.push_back(0);
    encoding.push_back(0);
    encoding.push_back(0);
    encoding.push_back(0);
    encoding.push_back(0);
    
    // Вычисляем контрольную сумму
    uint32_t mod = bech32m_polymod(encoding, BECH32M_GENERATOR) ^ 0x2bc830a3;
    
    std::vector<uint8_t> checksum(6);
    for (int i = 0; i < 6; i++) {
        checksum[i] = (mod >> (5 * (5 - i))) & 0x1f;
    }
    
    return checksum;
}

std::string bech32m_encode(const std::string& hrp, const std::vector<uint8_t>& values) {
    // Создаем контрольную сумму
    std::vector<uint8_t> checksum = bech32m_create_checksum(hrp, values);
    
    // Формируем полные данные
    std::vector<uint8_t> combined = values;
    combined.insert(combined.end(), checksum.begin(), checksum.end());
    
    // Алфавит для Bech32m
    const char* charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    
    // Формируем строку
    std::string result = hrp + "1";
    for (uint8_t c : combined) {
        if (c >= 32) {
            throw std::invalid_argument("Invalid value for Bech32m encoding");
        }
        result += charset[c];
    }
    
    return result;
}

bool bech32m_decode(const std::string& encoded, std::string& hrp_out, std::vector<uint8_t>& values_out) {
    // Проверяем длину
    if (encoded.size() < 8 || encoded.size() > 90) {
        return false;
    }
    
    // Находим сепаратор
    size_t sep_pos = encoded.find('1');
    if (sep_pos == std::string::npos || sep_pos < 1 || sep_pos > 83) {
        return false;
    }
    
    // Проверяем HRP
    hrp_out = encoded.substr(0, sep_pos);
    for (char c : hrp_out) {
        if (c < 33 || c > 126) {
            return false;
        }
    }
    
    // Декодируем данные
    values_out.clear();
    const char* charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    for (size_t i = sep_pos + 1; i < encoded.size(); i++) {
        size_t pos = std::string(charset).find(encoded[i]);
        if (pos == std::string::npos) {
            return false;
        }
        values_out.push_back(static_cast<uint8_t>(pos));
    }
    
    // Проверяем длину контрольной суммы
    if (values_out.size() < 6) {
        return false;
    }
    
    // Проверяем контрольную сумму
    std::vector<uint8_t> encoding;
    
    // Добавляем HRP в последовательность
    for (char c : hrp_out) {
        encoding.push_back(c >> 5);
    }
    encoding.push_back(0); // Сепаратор
    for (char c : hrp_out) {
        encoding.push_back(c & 0x1f);
    }
    
    // Добавляем данные
    encoding.insert(encoding.end(), values_out.begin(), values_out.end());
    
    if (bech32m_polymod(encoding, BECH32M_GENERATOR) != 0x2bc830a3) {
        return false;
    }
    
    // Удаляем контрольную сумму
    values_out.resize(values_out.size() - 6);
    
    return true;
}
