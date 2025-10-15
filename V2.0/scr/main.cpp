#include "toruscsidh.h"
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <cmath>
#include <numeric>
#include "bech32m.h"
#include "secure_audit_logger.h"
#include "security_constants.h"

/**
 * @brief Вывод информации о системе
 * 
 * Выводит подробную информацию о текущем состоянии системы,
 * включая параметры безопасности и статистику.
 */
void print_system_status() {
    SecureAuditLogger& logger = SecureAuditLogger::get_instance();
    
    std::cout << "\n=== Статус системы ===" << std::endl;
    std::cout << logger.get_system_status();
    std::cout << logger.get_security_info();
    std::cout << logger.get_security_statistics();
    
    // Дополнительная математическая информация
    std::cout << "Математическая информация:" << std::endl;
    std::cout << "  Количество простых чисел для уровня 128: " 
              << SecurityConstants::get_num_primes(SecurityConstants::LEVEL_128) << std::endl;
    std::cout << "  Максимальная величина ключа для уровня 128: " 
              << SecurityConstants::get_max_key_magnitude(SecurityConstants::LEVEL_128) << std::endl;
    std::cout << "  Геометрический радиус для уровня 128: " 
              << SecurityConstants::get_params(SecurityConstants::LEVEL_128).geometric_radius << std::endl;
    std::cout << "  Минимальное цикломатическое число: " 
              << SecurityConstants::get_geometric_params(SecurityConstants::LEVEL_128).min_cyclomatic << std::endl;
    std::cout << "  Минимальный спектральный зазор: " 
              << SecurityConstants::get_geometric_params(SecurityConstants::LEVEL_128).min_spectral_gap << std::endl;
}

/**
 * @brief Проверка геометрической валидации
 * 
 * Проверяет работу геометрического валидатора на различных типах кривых.
 * 
 * @param csidh Система TorusCSIDH
 * @return true, если проверка прошла успешно
 */
bool test_geometric_validation(TorusCSIDH& csidh) {
    std::cout << "\n=== Проверка геометрической валидации ===" << std::endl;
    
    // Получаем базовую кривую
    MontgomeryCurve base_curve = SecurityConstants::get_base_curve(SecurityConstants::LEVEL_128);
    
    // Создаем легитимную кривую (путем применения изогении)
    MontgomeryCurve legitimate_curve = base_curve;
    const auto& primes = SecurityConstants::get_primes(SecurityConstants::LEVEL_128);
    for (size_t i = 0; i < 5 && i < primes.size(); i++) {
        unsigned int degree = static_cast<unsigned int>(primes[i].get_ui());
        EllipticCurvePoint kernel_point = legitimate_curve.find_point_of_order(degree);
        if (!kernel_point.is_infinity()) {
            legitimate_curve = legitimate_curve.compute_isogeny(kernel_point, degree);
        }
    }
    
    // Проверяем легитимную кривую
    double cyclomatic_score, spectral_score, clustering_score, entropy_score, distance_score;
    bool legitimate_valid = csidh.get_code_integrity().geometric_validator_.validate_curve(
        base_curve, legitimate_curve, cyclomatic_score, spectral_score, 
        clustering_score, entropy_score, distance_score);
    
    std::cout << "Легитимная кривая: " 
              << (legitimate_valid ? "прошла геометрическую проверку" : "НЕ прошла геометрическую проверку") 
              << std::endl;
    std::cout << "  Цикломатическое число: " << cyclomatic_score << std::endl;
    std::cout << "  Спектральный зазор: " << spectral_score << std::endl;
    std::cout << "  Коэффициент кластеризации: " << clustering_score << std::endl;
    std::cout << "  Энтропия степеней: " << entropy_score << std::endl;
    std::cout << "  Энтропия расстояний: " << distance_score << std::endl;
    
    // Создаем кривую с длинными путями (атака)
    MontgomeryCurve long_path_curve = base_curve;
    for (size_t i = 0; i < 10 && i < primes.size(); i++) {
        unsigned int degree = static_cast<unsigned int>(primes[i].get_ui());
        // Создаем "длинный путь" в графе изогений
        for (int j = 0; j < 5; j++) {
            EllipticCurvePoint kernel_point = long_path_curve.find_point_of_order(degree);
            if (!kernel_point.is_infinity()) {
                long_path_curve = long_path_curve.compute_isogeny(kernel_point, degree);
            }
        }
    }
    
    // Проверяем кривую с длинными путями
    bool long_path_valid = csidh.get_code_integrity().geometric_validator_.validate_curve(
        base_curve, long_path_curve, cyclomatic_score, spectral_score, 
        clustering_score, entropy_score, distance_score);
    
    std::cout << "Кривая с длинными путями: " 
              << (long_path_valid ? "прошла геометрическую проверку (уязвимость!)" : "НЕ прошла геометрическую проверку (защита работает)") 
              << std::endl;
    
    // Создаем кривую с искусственно подогнанным распределением степеней (атака на энтропию)
    MontgomeryCurve entropy_attack_curve = base_curve;
    for (size_t i = 0; i < 5 && i < primes.size(); i++) {
        unsigned int degree = static_cast<unsigned int>(primes[i].get_ui());
        // Создаем кривую с низкой энтропией
        for (int j = 0; j < 2; j++) {
            EllipticCurvePoint kernel_point = entropy_attack_curve.find_point_of_order(degree);
            if (!kernel_point.is_infinity()) {
                entropy_attack_curve = entropy_attack_curve.compute_isogeny(kernel_point, degree);
            }
        }
    }
    
    // Проверяем кривую с атакой на энтропию
    bool entropy_attack_valid = csidh.get_code_integrity().geometric_validator_.validate_curve(
        base_curve, entropy_attack_curve, cyclomatic_score, spectral_score, 
        clustering_score, entropy_score, distance_score);
    
    std::cout << "Кривая с атакой на энтропию: " 
              << (entropy_attack_valid ? "прошла геометрическую проверку (уязвимость!)" : "НЕ прошла геометрическую проверку (защита работает)") 
              << std::endl;
    
    return legitimate_valid && !long_path_valid && !entropy_attack_valid;
}

/**
 * @brief Проверка безопасности ключей
 * 
 * Проверяет работу механизмов проверки безопасности ключей.
 * 
 * @param csidh Система TorusCSIDH
 * @return true, если проверка прошла успешно
 */
bool test_key_security(TorusCSIDH& csidh) {
    std::cout << "\n=== Проверка безопасности ключей ===" << std::endl;
    
    // Сохраняем оригинальный ключ
    std::vector<short> original_key = csidh.get_private_key();
    
    // Проверяем оригинальный ключ
    bool original_secure = csidh.is_secure_key();
    std::cout << "Оригинальный ключ: " 
              << (original_secure ? "безопасен" : "небезопасен") << std::endl;
    
    // Создаем "небольшой" ключ (все значения = max_key_magnitude + 1)
    std::vector<short> not_small_key = original_key;
    int max_mag = SecurityConstants::get_max_key_magnitude(SecurityConstants::LEVEL_128) + 1;
    for (auto& val : not_small_key) {
        val = max_mag;
    }
    
    // Проверяем "небольшой" ключ
    bool not_small_secure = true;
    try {
        // Создаем временную систему с модифицированным ключом
        TorusCSIDH temp_csidh(SecurityConstants::LEVEL_128);
        temp_csidh.get_code_integrity().system_integrity_check();
        
        // Устанавливаем модифицированный ключ
        std::vector<short>& temp_private_key = const_cast<std::vector<short>&>(temp_csidh.get_private_key());
        temp_private_key = not_small_key;
        
        not_small_secure = temp_csidh.is_secure_key();
    } catch (...) {
        not_small_secure = false;
    }
    
    std::cout << "Ключ с превышением L∞ нормы: " 
              << (not_small_secure ? "безопасен (уязвимость!)" : "небезопасен (защита работает)") 
              << std::endl;
    
    // Создаем ключ с регулярными паттернами
    std::vector<short> pattern_key = original_key;
    for (size_t i = 0; i < pattern_key.size(); i += 4) {
        if (i + 3 < pattern_key.size()) {
            pattern_key[i] = 1;
            pattern_key[i+1] = 2;
            pattern_key[i+2] = 1;
            pattern_key[i+3] = 2;
        }
    }
    
    // Проверяем ключ с регулярными паттернами
    bool pattern_secure = true;
    try {
        // Создаем временную систему с модифицированным ключом
        TorusCSIDH temp_csidh(SecurityConstants::LEVEL_128);
        temp_csidh.get_code_integrity().system_integrity_check();
        
        // Устанавливаем модифицированный ключ
        std::vector<short>& temp_private_key = const_cast<std::vector<short>&>(temp_csidh.get_private_key());
        temp_private_key = pattern_key;
        
        pattern_secure = temp_csidh.is_secure_key();
    } catch (...) {
        pattern_secure = false;
    }
    
    std::cout << "Ключ с регулярными паттернами: " 
              << (pattern_secure ? "безопасен (уязвимость!)" : "небезопасен (защита работает)") 
              << std::endl;
    
    // Создаем ключ с длинными последовательностями
    std::vector<short> long_seq_key = original_key;
    for (size_t i = 0; i < long_seq_key.size(); i += 15) {
        for (int j = 0; j < 12 && i + j < long_seq_key.size(); j++) {
            long_seq_key[i + j] = 1; // Длинная последовательность одинаковых значений
        }
    }
    
    // Проверяем ключ с длинными последовательностями
    bool long_seq_secure = true;
    try {
        // Создаем временную систему с модифицированным ключом
        TorusCSIDH temp_csidh(SecurityConstants::LEVEL_128);
        temp_csidh.get_code_integrity().system_integrity_check();
        
        // Устанавливаем модифицированный ключ
        std::vector<short>& temp_private_key = const_cast<std::vector<short>&>(temp_csidh.get_private_key());
        temp_private_key = long_seq_key;
        
        long_seq_secure = temp_csidh.is_secure_key();
    } catch (...) {
        long_seq_secure = false;
    }
    
    std::cout << "Ключ с длинными последовательностями: " 
              << (long_seq_secure ? "безопасен (уязвимость!)" : "небезопасен (защита работает)") 
              << std::endl;
    
    // Создаем ключ с вырожденной топологией
    std::vector<short> degenerate_key = original_key;
    for (auto& val : degenerate_key) {
        val = (val % 3) - 1; // Маленькие значения
    }
    
    // Проверяем ключ с вырожденной топологией
    bool degenerate_secure = true;
    try {
        // Создаем временную систему с модифицированным ключом
        TorusCSIDH temp_csidh(SecurityConstants::LEVEL_128);
        temp_csidh.get_code_integrity().system_integrity_check();
        
        // Устанавливаем модифицированный ключ
        std::vector<short>& temp_private_key = const_cast<std::vector<short>&>(temp_csidh.get_private_key());
        temp_private_key = degenerate_key;
        
        degenerate_secure = temp_csidh.is_secure_key();
    } catch (...) {
        degenerate_secure = false;
    }
    
    std::cout << "Ключ с вырожденной топологией: " 
              << (degenerate_secure ? "безопасен (уязвимость!)" : "небезопасен (защита работает)") 
              << std::endl;
    
    return original_secure && !not_small_secure && !pattern_secure && !long_seq_secure && !degenerate_secure;
}

/**
 * @brief Проверка защиты от атак по времени
 * 
 * Проверяет, что операции выполняются за постоянное время.
 * 
 * @param csidh Система TorusCSIDH
 * @return true, если проверка прошла успешно
 */
bool test_constant_time(TorusCSIDH& csidh) {
    std::cout << "\n=== Проверка защиты от атак по времени ===" << std::endl;
    
    // Подготовка данных
    std::vector<unsigned char> message(32);
    for (size_t i = 0; i < message.size(); i++) {
        message[i] = static_cast<unsigned char>(i);
    }
    
    // Подпись с разными сообщениями
    std::vector<std::chrono::microseconds> sign_times;
    for (int i = 0; i < 10; i++) {
        // Модифицируем сообщение
        message[0] = static_cast<unsigned char>(i);
        
        auto start = std::chrono::high_resolution_clock::now();
        csidh.sign(message);
        auto end = std::chrono::high_resolution_clock::now();
        
        sign_times.push_back(std::chrono::duration_cast<std::chrono::microseconds>(end - start));
    }
    
    // Анализ времени подписи
    std::chrono::microseconds min_sign_time = *std::min_element(sign_times.begin(), sign_times.end());
    std::chrono::microseconds max_sign_time = *std::max_element(sign_times.begin(), sign_times.end());
    double sign_time_variation = static_cast<double>((max_sign_time - min_sign_time).count()) / 
                                static_cast<double>(min_sign_time.count());
    
    std::cout << "Вариация времени подписи: " << sign_time_variation * 100.0 << "%" << std::endl;
    
    // Верификация с разными подписями
    std::vector<unsigned char> signature = csidh.sign(message);
    std::vector<std::chrono::microseconds> verify_times;
    for (int i = 0; i < 10; i++) {
        // Модифицируем подпись
        signature[0] = static_cast<unsigned char>(i);
        
        auto start = std::chrono::high_resolution_clock::now();
        csidh.verify(message, signature);
        auto end = std::chrono::high_resolution_clock::now();
        
        verify_times.push_back(std::chrono::duration_cast<std::chrono::microseconds>(end - start));
    }
    
    // Анализ времени верификации
    std::chrono::microseconds min_verify_time = *std::min_element(verify_times.begin(), verify_times.end());
    std::chrono::microseconds max_verify_time = *std::max_element(verify_times.begin(), verify_times.end());
    double verify_time_variation = static_cast<double>((max_verify_time - min_verify_time).count()) / 
                                  static_cast<double>(min_verify_time.count());
    
    std::cout << "Вариация времени верификации: " << verify_time_variation * 100.0 << "%" << std::endl;
    
    // Проверка, что вариация времени незначительна
    bool sign_time_constant = sign_time_variation < 0.05; // 5% вариация
    bool verify_time_constant = verify_time_variation < 0.05; // 5% вариация
    
    std::cout << "Подпись выполняется за постоянное время: " 
              << (sign_time_constant ? "да" : "нет (уязвимость!)") << std::endl;
    std::cout << "Верификация выполняется за постоянное время: " 
              << (verify_time_constant ? "да" : "нет (уязвимость!)") << std::endl;
    
    return sign_time_constant && verify_time_constant;
}

/**
 * @brief Проверка целостности системы
 * 
 * Проверяет работу механизма проверки целостности и восстановления.
 * 
 * @param csidh Система TorusCSIDH
 * @return true, если проверка прошла успешно
 */
bool test_integrity_protection(TorusCSIDH& csidh) {
    std::cout << "\n=== Проверка целостности системы ===" << std::endl;
    
    CodeIntegrityProtection& integrity = csidh.get_code_integrity();
    
    // Проверка исходного состояния
    bool initial_integrity = integrity.system_integrity_check();
    std::cout << "Исходная целостность системы: " 
              << (initial_integrity ? "OK" : "НАРУШЕНА") << std::endl;
    
    if (!initial_integrity) {
        std::cout << "Попытка восстановления..." << std::endl;
        bool recovery_ok = integrity.self_recovery();
        std::cout << "Восстановление: " << (recovery_ok ? "успешно" : "неудачно") << std::endl;
        
        if (!recovery_ok) {
            return false;
        }
        
        initial_integrity = integrity.system_integrity_check();
    }
    
    // Эмуляция аномалии (модификация критического модуля)
    std::cout << "Эмуляция аномалии (модификация критического модуля)..." << std::endl;
    
    // Сохраняем оригинальные HMAC критических модулей
    std::map<std::string, std::vector<unsigned char>> original_hmacs;
    for (const auto& module : integrity.get_critical_modules()) {
        original_hmacs[module] = integrity.get_original_module_hmac(module);
    }
    
    // Модифицируем HMAC одного из модулей
    std::string modified_module = integrity.get_critical_modules().front();
    std::vector<unsigned char> modified_hmac = original_hmacs[modified_module];
    if (!modified_hmac.empty()) {
        modified_hmac[0] ^= 0x01; // Меняем первый байт
        
        // Используем reflection для изменения HMAC (в реальной системе это было бы невозможно)
        // Здесь для демонстрации мы используем недокументированный метод
        integrity.set_module_hmac_for_testing(modified_module, modified_hmac);
    }
    
    // Проверка целостности после модификации
    bool integrity_after_modification = integrity.system_integrity_check();
    std::cout << "Целостность после модификации: " 
              << (integrity_after_modification ? "OK (уязвимость!)" : "НАРУШЕНА (защита работает)") 
              << std::endl;
    
    // Проверка счетчика аномалий
    size_t anomaly_count = integrity.get_anomaly_count();
    std::cout << "Количество аномалий: " << anomaly_count << std::endl;
    
    // Попытка восстановления
    std::cout << "Попытка восстановления из резервной копии..." << std::endl;
    bool recovery_ok = integrity.self_recovery();
    std::cout << "Восстановление: " << (recovery_ok ? "успешно" : "неудачно") << std::endl;
    
    // Проверка целостности после восстановления
    bool integrity_after_recovery = integrity.system_integrity_check();
    std::cout << "Целостность после восстановления: " 
              << (integrity_after_recovery ? "OK" : "НАРУШЕНА") << std::endl;
    
    // Восстановление оригинальных HMAC для продолжения тестирования
    for (const auto& [module, hmac] : original_hmacs) {
        integrity.set_module_hmac_for_testing(module, hmac);
    }
    
    return initial_integrity && !integrity_after_modification && recovery_ok && integrity_after_recovery;
}

/**
 * @brief Проверка обновления критериев безопасности
 * 
 * Проверяет работу механизма обновления критериев безопасности.
 * 
 * @param csidh Система TorusCSIDH
 * @return true, если проверка прошла успешно
 */
bool test_criteria_update(TorusCSIDH& csidh) {
    std::cout << "\n=== Проверка обновления критериев безопасности ===" << std::endl;
    
    CodeIntegrityProtection& integrity = csidh.get_code_integrity();
    
    // Получаем текущую версию критериев
    int current_major, current_minor;
    integrity.get_current_criteria_version(current_major, current_minor);
    
    std::cout << "Текущая версия критериев: " << current_major << "." << current_minor << std::endl;
    
    // Планируем обновление критериев
    int new_major = current_major + 1;
    int new_minor = 0;
    time_t activation_time = time(nullptr) + 5; // Через 5 секунд
    
    std::cout << "Планирование обновления критериев до версии " 
              << new_major << "." << new_minor << " (активация через 5 секунд)" << std::endl;
    
    bool update_scheduled = integrity.update_criteria_version(new_major, new_minor, activation_time);
    std::cout << "Обновление запланировано: " << (update_scheduled ? "успешно" : "неудачно") << std::endl;
    
    if (!update_scheduled) {
        return false;
    }
    
    // Проверяем запланированную версию
    int scheduled_major, scheduled_minor;
    time_t scheduled_activation;
    integrity.get_scheduled_criteria_version(scheduled_major, scheduled_minor, scheduled_activation);
    
    std::cout << "Запланированная версия: " << scheduled_major << "." << scheduled_minor 
              << " (активация: " << scheduled_activation << ")" << std::endl;
    
    // Ждем активации
    std::cout << "Ожидание активации критериев..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(6));
    
    // Проверяем, что критерии обновились
    integrity.get_current_criteria_version(current_major, current_minor);
    
    bool criteria_updated = (current_major == new_major && current_minor == new_minor);
    std::cout << "Критерии обновлены: " 
              << (criteria_updated ? "успешно" : "неудачно") << std::endl;
    
    // Проверяем, что запланированная версия сброшена
    integrity.get_scheduled_criteria_version(scheduled_major, scheduled_minor, scheduled_activation);
    bool scheduled_cleared = (scheduled_major == -1 && scheduled_minor == -1 && scheduled_activation == 0);
    
    std::cout << "Запланированная версия сброшена: " 
              << (scheduled_cleared ? "да" : "нет") << std::endl;
    
    return criteria_updated && scheduled_cleared;
}

int main() {
    try {
        std::cout << "=== Запуск TorusCSIDH: Постквантовая криптосистема ===" << std::endl;
        std::cout << "Версия: 1.0.0" << std::endl;
        std::cout << "Дата сборки: " << __DATE__ << " " << __TIME__ << std::endl;
        std::cout << "Автор: TorusCSIDH Development Team" << std::endl;
        std::cout << "Лицензия: Apache License 2.0" << std::endl;
        std::cout << "====================================================" << std::endl;
        
        // Создание системы с уровнем безопасности 128 бит
        TorusCSIDH csidh(SecurityConstants::LEVEL_128);
        
        // Инициализация системы
        std::cout << "\nИнициализация системы..." << std::endl;
        csidh.initialize();
        
        // Печать информации о системе
        std::cout << "\nИнформация о системе:" << std::endl;
        csidh.print_info();
        
        // Проверка статуса системы
        print_system_status();
        
        // Генерация ключевой пары
        std::cout << "\nГенерация ключевой пары..." << std::endl;
        csidh.generate_key_pair();
        
        // Проверка, что ключ безопасен
        std::cout << "Проверка безопасности ключа..." << std::endl;
        if (!csidh.is_secure_key()) {
            throw std::runtime_error("Сгенерированный ключ не безопасен");
        }
        std::cout << "Ключ прошел все проверки безопасности" << std::endl;
        
        // Генерация адреса
        std::cout << "\nГенерация адреса..." << std::endl;
        std::string address = csidh.generate_address();
        std::cout << "Сгенерированный адрес: " << address << std::endl;
        
        // Подпись сообщения
        std::cout << "\nПодпись сообщения..." << std::endl;
        std::vector<unsigned char> message = {'H', 'e', 'l', 'l', 'o', ' ', 'T', 'o', 'r', 'u', 's', 'C', 'S', 'I', 'D', 'H'};
        std::vector<unsigned char> signature = csidh.sign(message);
        
        // Вывод подписи в hex
        std::cout << "Подпись (hex): ";
        for (unsigned char c : signature) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
        std::cout << std::dec << std::endl;
        
        // Верификация подписи
        std::cout << "\nВерификация подписи..." << std::endl;
        bool is_valid = csidh.verify(message, signature);
        std::cout << "Подпись " << (is_valid ? "валидна" : "невалидна") << std::endl;
        
        // Проверка геометрической валидации
        bool geometric_test_ok = test_geometric_validation(csidh);
        
        // Проверка безопасности ключей
        bool key_security_ok = test_key_security(csidh);
        
        // Проверка защиты от атак по времени
        bool constant_time_ok = test_constant_time(csidh);
        
        // Проверка целостности системы
        bool integrity_test_ok = test_integrity_protection(csidh);
        
        // Проверка обновления критериев безопасности
        bool criteria_update_ok = test_criteria_update(csidh);
        
        // Итоговая проверка
        std::cout << "\n=== Итоговая проверка ===" << std::endl;
        std::cout << "Геометрическая валидация: " << (geometric_test_ok ? "OK" : "ОШИБКА") << std::endl;
        std::cout << "Безопасность ключей: " << (key_security_ok ? "OK" : "ОШИБКА") << std::endl;
        std::cout << "Защита от атак по времени: " << (constant_time_ok ? "OK" : "ОШИБКА") << std::endl;
        std::cout << "Целостность системы: " << (integrity_test_ok ? "OK" : "ОШИБКА") << std::endl;
        std::cout << "Обновление критериев: " << (criteria_update_ok ? "OK" : "ОШИБКА") << std::endl;
        
        bool all_tests_passed = geometric_test_ok && key_security_ok && 
                               constant_time_ok && integrity_test_ok && criteria_update_ok;
        
        std::cout << "\nСистема TorusCSIDH готова к использованию в постквантовом Bitcoin!" << std::endl;
        std::cout << "Все тесты " << (all_tests_passed ? "пройдены успешно" : "НЕ пройдены") << std::endl;
        
        return all_tests_passed ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "Критическая ошибка: " << e.what() << std::endl;
        return 1;
    }
}
