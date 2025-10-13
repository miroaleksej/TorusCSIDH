#include "toruscsidh.h"
#include <iostream>

int main() {
    try {
        std::cout << "=== Инициализация системы TorusCSIDH ===" << std::endl;
        
        // Создание системы с уровнем безопасности 128 бит
        TorusCSIDH csidh(SecurityLevel::LEVEL_128);
        
        // Генерация ключевой пары
        std::cout << "Генерация ключевой пары..." << std::endl;
        csidh.generate_key_pair();
        
        // Вывод информации о системе
        csidh.print_info();
        
        // Генерация адреса
        std::string address = csidh.generate_address();
        std::cout << "Сгенерированный адрес: " << address << std::endl;
        
        // Подпись сообщения
        std::cout << "Подписание сообщения..." << std::endl;
        std::string message = "Пример транзакции Bitcoin";
        auto signature = csidh.sign(std::vector<unsigned char>(message.begin(), message.end()));
        
        // Верификация подписи
        std::cout << "Верификация подписи..." << std::endl;
        bool is_valid = csidh.verify(std::vector<unsigned char>(message.begin(), message.end()),
                                    signature,
                                    csidh.get_public_curve());
        std::cout << "Верификация подписи: " << (is_valid ? "УСПЕШНО" : "НЕУДАЧНО") << std::endl;
        
        // Проверка геометрической защиты
        std::cout << "Проверка геометрической защиты..." << std::endl;
        // Создание поддельной кривой с плохими геометрическими свойствами
        MontgomeryCurve base_curve = csidh.get_base_curve();
        MontgomeryCurve forged_curve(1, base_curve.get_p()); // Вырожденная кривая
        
        // Построение подграфа вокруг поддельной кривой
        int radius = csidh.get_radius();
        IsogenyGraph forged_graph = csidh.build_isogeny_subgraph(forged_curve, radius);
        
        // Проверка через геометрический валидатор
        GeometricValidator validator(csidh.get_security_level(),
                                  csidh.get_code_integrity(),
                                  csidh.get_audit_logger(),
                                  csidh.get_network_state(),
                                  csidh.get_rfc6979_rng());
        
        double cyclomatic_score, spectral_score, clustering_score, entropy_score, distance_score;
        bool forged_valid = validator.validate_curve(forged_curve, forged_graph,
                                                   cyclomatic_score, spectral_score,
                                                   clustering_score, entropy_score, distance_score);
        
        std::cout << "Кривая адаптивной атаки " 
                  << (forged_valid ? "прошла геометрическую проверку (уязвимость!)" 
                                   : "НЕ прошла геометрическую проверку (защита работает)") 
                  << std::endl;
        
        // Проверка защиты от атаки через длинный путь
        std::cout << "Проверка защиты от атаки через длинный путь..." << std::endl;
        // Создание кривой с "длинным путем"
        MontgomeryCurve long_path_curve = base_curve;
        for (int i = 0; i < 100; i++) {
            EllipticCurvePoint kernel_point = long_path_curve.find_point_of_order(csidh.get_primes()[0].get_ui(), csidh.get_rfc6979_rng());
            if (!kernel_point.is_infinite()) {
                long_path_curve = csidh.compute_isogeny(long_path_curve, kernel_point);
            }
        }
        
        // Проверка через геометрический валидатор
        IsogenyGraph long_path_graph = csidh.build_isogeny_subgraph(long_path_curve, radius);
        bool long_path_valid = validator.validate_curve(long_path_curve, long_path_graph,
                                                      cyclomatic_score, spectral_score,
                                                      clustering_score, entropy_score, distance_score);
        
        std::cout << "Кривая с длинным путем " 
                  << (long_path_valid ? "прошла геометрическую проверку (уязвимость!)" 
                                     : "НЕ прошла геометрическую проверку (защита работает)") 
                  << std::endl;
        
        // Проверка защиты от атак на энтропию
        std::cout << "Проверка защиты от атак на энтропию..." << std::endl;
        // Создание кривой с искусственно подогнанным распределением степеней
        MontgomeryCurve entropy_attack_curve = base_curve;
        for (int i = 0; i < 5; i++) {
            EllipticCurvePoint kernel_point = entropy_attack_curve.find_point_of_order(csidh.get_primes()[0].get_ui(), csidh.get_rfc6979_rng());
            if (!kernel_point.is_infinite()) {
                entropy_attack_curve = csidh.compute_isogeny(entropy_attack_curve, kernel_point);
            }
        }
        
        // Проверка через геометрический валидатор
        IsogenyGraph entropy_attack_graph = csidh.build_isogeny_subgraph(entropy_attack_curve, radius);
        bool entropy_attack_valid = validator.validate_curve(entropy_attack_curve, entropy_attack_graph,
                                                          cyclomatic_score, spectral_score,
                                                          clustering_score, entropy_score, distance_score);
        
        std::cout << "Кривая атаки на энтропию " 
                  << (entropy_attack_valid ? "прошла геометрическую проверку (уязвимость!)" 
                                          : "НЕ прошла геометрическую проверку (защита работает)") 
                  << std::endl;
        
        // Обновление критериев геометрической проверки
        time_t future_time = time(nullptr) + 24 * 60 * 60; // Через 24 часа
        bool update_result = csidh.code_integrity.update_criteria_version(2, 1, future_time);
        std::cout << "Обновление критериев: " << (update_result ? "успешно" : "неудачно") << std::endl;
        
        std::cout << "Система TorusCSIDH готова к использованию в постквантовом Bitcoin!" << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }
}
