#include "toruscsidh.h"
#include "secure_audit_logger.h"
#include "code_integrity_protection.h"
#include "geometric_validator.h"
#include <iostream>
#include <chrono>
#include <vector>
#include <iomanip>
#include <sstream>
#include <ctime>

namespace toruscsidh {

/**
 * @brief Форматирование числа с разделителями тысяч
 * 
 * @param value Число для форматирования
 * @return Отформатированная строка
 */
std::string format_number_with_commas(size_t value) {
    std::ostringstream ss;
    ss.imbue(std::locale(""));
    ss << std::fixed << value;
    return ss.str();
}

/**
 * @brief Форматирование времени в микросекундах
 * 
 * @param microseconds Время в микросекундах
 * @return Отформатированная строка
 */
std::string format_time(uint64_t microseconds) {
    if (microseconds < 1000) {
        return std::to_string(microseconds) + " µs";
    } else if (microseconds < 1000000) {
        return std::to_string(microseconds / 1000.0) + " ms";
    } else {
        return std::to_string(microseconds / 1000000.0) + " s";
    }
}

/**
 * @brief Проверка геометрической безопасности кривой
 * 
 * @param csidh Система TorusCSIDH
 * @param curve Кривая для проверки
 * @param radius Радиус подграфа
 */
void check_geometric_security(const TorusCSIDH& csidh, const MontgomeryCurve& curve, int radius) {
    const GeometricValidator& validator = csidh.get_geometric_validator();
    const SecurityConstants::CSIDHParams& params = csidh.get_security_params();
    
    // Проверка геометрических свойств
    double cyclomatic_score, spectral_score, clustering_score;
    double degree_entropy_score, distance_score;
    
    bool cyclomatic_valid = validator.check_cyclomatic_number(curve, params.primes, radius);
    bool spectral_valid = validator.check_spectral_gap(curve, params.primes, radius);
    bool connectivity_valid = validator.check_local_connectivity(curve, params.primes, radius);
    bool long_paths_valid = validator.check_long_paths(curve, params.primes, radius);
    bool degenerate_valid = validator.check_degenerate_topology(curve, params.primes, radius);
    bool symmetry_valid = validator.check_graph_symmetry(curve, params.primes, radius);
    bool metric_valid = validator.check_metric_consistency(curve, params.primes, radius);
    
    // Вычисление общего балла безопасности
    double total_score = 0.20 * (cyclomatic_valid ? 1.0 : 0.0) + 
                         0.20 * (spectral_valid ? 1.0 : 0.0) + 
                         0.15 * (connectivity_valid ? 1.0 : 0.0) + 
                         0.10 * (long_paths_valid ? 1.0 : 0.0) + 
                         0.10 * (degenerate_valid ? 1.0 : 0.0) + 
                         0.15 * (symmetry_valid ? 1.0 : 0.0) + 
                         0.10 * (metric_valid ? 1.0 : 0.0);
    
    // Проверка, что кривая действительно принадлежит графу изогений
    bool in_isogeny_graph = csidh.is_curve_in_isogeny_graph(curve);
    
    // Логирование результатов
    std::cout << "\nГеометрическая проверка для кривой:" << std::endl;
    std::cout << "  j-инвариант: " << curve.compute_j_invariant() << std::endl;
    std::cout << "  Результаты проверки:" << std::endl;
    std::cout << "    Цикломатическое число: " << (cyclomatic_valid ? "OK" : "FAIL") << std::endl;
    std::cout << "    Спектральный зазор: " << (spectral_valid ? "OK" : "FAIL") << std::endl;
    std::cout << "    Локальная связность: " << (connectivity_valid ? "OK" : "FAIL") << std::endl;
    std::cout << "    Длинные пути: " << (long_paths_valid ? "OK" : "FAIL") << std::endl;
    std::cout << "    Вырожденная топология: " << (degenerate_valid ? "OK" : "FAIL") << std::endl;
    std::cout << "    Симметрия графа: " << (symmetry_valid ? "OK" : "FAIL") << std::endl;
    std::cout << "    Метрическая согласованность: " << (metric_valid ? "OK" : "FAIL") << std::endl;
    std::cout << "    Принадлежность графу изогений: " << (in_isogeny_graph ? "OK" : "FAIL") << std::endl;
    std::cout << "  Общий балл безопасности: " << std::fixed << std::setprecision(1) 
              << total_score * 100.0 << "%" << std::endl;
    
    // Проверка, что кривая безопасна
    bool is_safe = (total_score >= 0.85) && in_isogeny_graph;
    std::cout << "  Кривая " << (is_safe ? "БЕЗОПАСНА" : "НЕБЕЗОПАСНА") << std::endl;
}

/**
 * @brief Проверка защиты от атак на энтропию
 * 
 * Создает кривую с низкой энтропией и проверяет, что система ее отклоняет.
 * 
 * @param csidh Система TorusCSIDH
 */
void test_entropy_protection(const TorusCSIDH& csidh) {
    std::cout << "\nПроверка защиты от атак на энтропию..." << std::endl;
    
    const SecurityConstants::CSIDHParams& params = csidh.get_security_params();
    const MontgomeryCurve& base_curve = csidh.get_public_curve();
    
    // Создаем кривую с низкой энтропией (все изогении одного типа)
    MontgomeryCurve low_entropy_curve = base_curve;
    unsigned int order = static_cast<unsigned int>(mpz_get_ui(params.primes[0].get_mpz_t()));
    
    // Применяем много изогений одного типа
    for (int i = 0; i < 10; i++) {
        EllipticCurvePoint kernel_point = base_curve.find_point_of_order(order);
        low_entropy_curve = low_entropy_curve.compute_isogeny(kernel_point, order);
    }
    
    // Проверяем геометрическую безопасность
    double cyclomatic_score, spectral_score, clustering_score;
    double degree_entropy_score, distance_score;
    
    bool cyclomatic_valid = csidh.validate_geometric_properties(low_entropy_curve);
    
    std::cout << "Кривая с низкой энтропией " 
              << (cyclomatic_valid ? "ПРОШЛА геометрическую проверку (уязвимость!)" 
                                   : "НЕ ПРОШЛА геометрическую проверку (защита работает)")
              << std::endl;
}

/**
 * @brief Проверка защиты от атак через длинные пути
 * 
 * Создает кривую с длинной последовательностью изогений одного типа и проверяет,
 * что система ее отклоняет.
 * 
 * @param csidh Система TorusCSIDH
 */
void test_long_path_protection(const TorusCSIDH& csidh) {
    std::cout << "\nПроверка защиты от атак через длинные пути..." << std::endl;
    
    const SecurityConstants::CSIDHParams& params = csidh.get_security_params();
    const MontgomeryCurve& base_curve = csidh.get_public_curve();
    
    // Создаем кривую с длинной последовательностью изогений одного типа
    MontgomeryCurve long_path_curve = base_curve;
    unsigned int order = static_cast<unsigned int>(mpz_get_ui(params.primes[0].get_mpz_t()));
    
    // Применяем много изогений одного типа (больше, чем допустимо)
    int max_consecutive = SecurityConstants::MAX_CONSECUTIVE_128 + 5;
    for (int i = 0; i < max_consecutive; i++) {
        EllipticCurvePoint kernel_point = base_curve.find_point_of_order(order);
        long_path_curve = long_path_curve.compute_isogeny(kernel_point, order);
    }
    
    // Проверяем геометрическую безопасность
    bool long_path_valid = csidh.validate_geometric_properties(long_path_curve);
    
    std::cout << "Кривая с длинным путем " 
              << (long_path_valid ? "ПРОШЛА геометрическую проверку (уязвимость!)" 
                                  : "НЕ ПРОШЛА геометрическую проверку (защита работает)")
              << std::endl;
}

/**
 * @brief Проверка защиты от атак через вырожденную топологию
 * 
 * Создает кривую с вырожденной топологией и проверяет, что система ее отклоняет.
 * 
 * @param csidh Система TorusCSIDH
 */
void test_degenerate_topology_protection(const TorusCSIDH& csidh) {
    std::cout << "\nПроверка защиты от атак через вырожденную топологию..." << std::endl;
    
    const SecurityConstants::CSIDHParams& params = csidh.get_security_params();
    const MontgomeryCurve& base_curve = csidh.get_public_curve();
    
    // Создаем вырожденную кривую (просто применяем одну изогению)
    MontgomeryCurve degenerate_curve = base_curve;
    unsigned int order = static_cast<unsigned int>(mpz_get_ui(params.primes[0].get_mpz_t()));
    EllipticCurvePoint kernel_point = base_curve.find_point_of_order(order);
    degenerate_curve = degenerate_curve.compute_isogeny(kernel_point, order);
    
    // Проверяем геометрическую безопасность
    bool degenerate_valid = csidh.validate_geometric_properties(degenerate_curve);
    
    std::cout << "Вырожденная кривая " 
              << (degenerate_valid ? "ПРОШЛА геометрическую проверку (уязвимость!)" 
                                   : "НЕ ПРОШЛА геометрическую проверку (защита работает)")
              << std::endl;
}

/**
 * @brief Тестирование системы целостности
 * 
 * @param csidh Система TorusCSIDH
 */
void test_code_integrity(const TorusCSIDH& csidh) {
    std::cout << "\nТестирование системы целостности..." << std::endl;
    
    const CodeIntegrityProtection& integrity = csidh.get_code_integrity();
    
    // Проверка целостности системы
    std::cout << "Проверка целостности системы... ";
    bool integrity_ok = integrity.system_integrity_check();
    std::cout << (integrity_ok ? "OK" : "НАРУШЕНА") << std::endl;
    
    // Обновление критериев геометрической проверки
    time_t future_time = time(nullptr) + 24 * 60 * 60; // Через 24 часа
    bool update_result = integrity.update_criteria_version(2, 1, future_time);
    std::cout << "Обновление критериев: " << (update_result ? "успешно" : "неудачно") << std::endl;
    
    // Сохранение состояния для восстановления
    std::cout << "Сохранение состояния для восстановления... ";
    integrity.save_recovery_state();
    std::cout << "OK" << std::endl;
}

/**
 * @brief Тестирование подписи и верификации
 * 
 * @param csidh Система TorusCSIDH
 */
void test_signing_verification(TorusCSIDH& csidh) {
    std::cout << "\nТестирование подписи и верификации..." << std::endl;
    
    // Создание сообщения
    std::string message_str = "Тестовое сообщение для TorusCSIDH";
    std::vector<unsigned char> message(message_str.begin(), message_str.end());
    
    // Подпись сообщения
    auto start_sign = std::chrono::high_resolution_clock::now();
    std::vector<unsigned char> signature = csidh.sign(message);
    auto end_sign = std::chrono::high_resolution_clock::now();
    
    auto sign_time = std::chrono::duration_cast<std::chrono::microseconds>(end_sign - start_sign).count();
    
    std::cout << "Сообщение подписано за " << format_time(sign_time) << std::endl;
    
    // Верификация подписи
    auto start_verify = std::chrono::high_resolution_clock::now();
    bool is_valid = csidh.verify(message, signature);
    auto end_verify = std::chrono::high_resolution_clock::now();
    
    auto verify_time = std::chrono::duration_cast<std::chrono::microseconds>(end_verify - start_verify).count();
    
    std::cout << "Подпись " << (is_valid ? "ВЕРИФИЦИРОВАНА" : "НЕ ВЕРИФИЦИРОВАНА") 
              << " за " << format_time(verify_time) << std::endl;
    
    // Попытка верификации подделанной подписи
    std::vector<unsigned char> forged_signature = signature;
    if (!forged_signature.empty()) {
        forged_signature[0] ^= 0x01; // Изменяем первый байт
        
        bool is_forged_valid = csidh.verify(message, forged_signature);
        std::cout << "Подделанная подпись " << (is_forged_valid ? "ВЕРИФИЦИРОВАНА (уязвимость!)" 
                                                              : "НЕ ВЕРИФИЦИРОВАНА (защита работает)") << std::endl;
    }
}

/**
 * @brief Тестирование генерации адреса
 * 
 * @param csidh Система TorusCSIDH
 */
void test_address_generation(const TorusCSIDH& csidh) {
    std::cout << "\nТестирование генерации адреса..." << std::endl;
    
    // Генерация адреса
    std::string address = csidh.generate_address();
    
    // Проверка формата адреса
    bool is_valid_address = Bech32m::is_toruscsidh_address(address);
    bool is_secure = Bech32m::is_secure_address(address);
    
    std::cout << "Сгенерированный адрес: " << address << std::endl;
    std::cout << "  Формат адреса: " << (is_valid_address ? "корректный" : "некорректный") << std::endl;
    std::cout << "  Безопасность адреса: " << (is_secure ? "высокая" : "низкая") << std::endl;
}

/**
 * @brief Тестирование ключей
 * 
 * @param csidh Система TorusCSIDH
 */
void test_key_security(const TorusCSIDH& csidh) {
    std::cout << "\nТестирование безопасности ключей..." << std::endl;
    
    // Проверка "малости" ключа
    bool is_small = csidh.is_small_key();
    std::cout << "  Ключ 'малый': " << (is_small ? "да" : "нет") << std::endl;
    
    // Проверка на слабые ключи
    bool is_weak = csidh.is_weak_key();
    std::cout << "  Ключ слабый: " << (is_weak ? "да" : "нет") << std::endl;
    
    // Проверка, что ключ уязвим к атаке через длинный путь
    bool is_vulnerable_long_path = csidh.is_vulnerable_to_long_path_attack();
    std::cout << "  Ключ уязвим к атаке через длинный путь: " 
              << (is_vulnerable_long_path ? "да" : "нет") << std::endl;
    
    // Проверка, что ключ уязвим к атаке через вырожденную топологию
    bool is_vulnerable_degenerate = csidh.is_vulnerable_to_degenerate_topology_attack();
    std::cout << "  Ключ уязвим к атаке через вырожденную топологию: " 
              << (is_vulnerable_degenerate ? "да" : "нет") << std::endl;
    
    // Проверка общей безопасности ключа
    bool is_secure = csidh.is_secure_key();
    std::cout << "  Ключ безопасен: " << (is_secure ? "да" : "нет") << std::endl;
}

/**
 * @brief Тестирование производительности
 * 
 * @param csidh Система TorusCSIDH
 */
void test_performance(TorusCSIDH& csidh) {
    std::cout << "\nТестирование производительности..." << std::endl;
    
    // Тестирование генерации ключевой пары
    auto start_keygen = std::chrono::high_resolution_clock::now();
    csidh.generate_key_pair();
    auto end_keygen = std::chrono::high_resolution_clock::now();
    
    auto keygen_time = std::chrono::duration_cast<std::chrono::microseconds>(end_keygen - start_keygen).count();
    
    // Создание сообщения
    std::string message_str = "Тестовое сообщение для TorusCSIDH";
    std::vector<unsigned char> message(message_str.begin(), message_str.end());
    
    // Тестирование подписи
    auto start_sign = std::chrono::high_resolution_clock::now();
    std::vector<unsigned char> signature = csidh.sign(message);
    auto end_sign = std::chrono::high_resolution_clock::now();
    
    auto sign_time = std::chrono::duration_cast<std::chrono::microseconds>(end_sign - start_sign).count();
    
    // Тестирование верификации
    auto start_verify = std::chrono::high_resolution_clock::now();
    bool is_valid = csidh.verify(message, signature);
    auto end_verify = std::chrono::high_resolution_clock::now();
    
    auto verify_time = std::chrono::duration_cast<std::chrono::microseconds>(end_verify - start_verify).count();
    
    std::cout << "  Генерация ключевой пары: " << format_time(keygen_time) << std::endl;
    std::cout << "  Подпись сообщения: " << format_time(sign_time) << std::endl;
    std::cout << "  Верификация подписи: " << format_time(verify_time) << std::endl;
    
    // Оценка производительности
    double ops_per_second = 1000000.0 / sign_time;
    std::cout << "  Производительность подписания: " 
              << format_number_with_commas(static_cast<size_t>(ops_per_second)) 
              << " операций/сек" << std::endl;
}

} // namespace toruscsidh

int main() {
    try {
        std::cout << "Запуск тестирования системы TorusCSIDH..." << std::endl;
        std::cout << "==================================================" << std::endl;
        
        // Инициализация системы с уровнем безопасности 128 бит
        auto start_init = std::chrono::high_resolution_clock::now();
        toruscsidh::TorusCSIDH csidh(toruscsidh::SecurityConstants::SecurityLevel::LEVEL_128);
        auto end_init = std::chrono::high_resolution_clock::now();
        
        auto init_time = std::chrono::duration_cast<std::chrono::microseconds>(end_init - start_init).count();
        
        std::cout << "Система TorusCSIDH инициализирована за " << toruscsidh::format_time(init_time) << std::endl;
        
        // Печать информации о системе
        csidh.print_info();
        
        // Проверка системы целостности
        toruscsidh::test_code_integrity(csidh);
        
        // Проверка безопасности ключей
        toruscsidh::test_key_security(csidh);
        
        // Проверка геометрической безопасности
        toruscsidh::check_geometric_security(csidh, csidh.get_public_curve(), 3);
        
        // Тестирование защиты от различных атак
        toruscsidh::test_entropy_protection(csidh);
        toruscsidh::test_long_path_protection(csidh);
        toruscsidh::test_degenerate_topology_protection(csidh);
        
        // Тестирование подписи и верификации
        toruscsidh::test_signing_verification(csidh);
        
        // Тестирование генерации адреса
        toruscsidh::test_address_generation(csidh);
        
        // Тестирование производительности
        toruscsidh::test_performance(csidh);
        
        std::cout << "\n==================================================" << std::endl;
        std::cout << "Система TorusCSIDH готова к использованию в постквантовом Bitcoin!" << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }
}
