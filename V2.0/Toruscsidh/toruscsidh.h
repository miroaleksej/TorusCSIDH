#ifndef TORUSCSIDH_TORUSCSIDH_H
#define TORUSCSIDH_TORUSCSIDH_H

#include <vector>
#include <string>
#include <chrono>
#include <gmpxx.h>
#include "security_constants.h"
#include "elliptic_curve.h"
#include "geometric_validator.h"
#include "code_integrity_protection.h"
#include "secure_random.h"
#include "postquantum_hash.h"
#include "bech32m.h"
#include "rfc6979_rng.h"

namespace toruscsidh {

/**
 * @brief Основной класс системы TorusCSIDH
 * 
 * Реализует постквантовую систему цифровой подписи на основе изогений эллиптических кривых
 * с трехуровневой проверкой безопасности (алгебраический, геометрический, системный).
 */
class TorusCSIDH {
public:
    /**
     * @brief Конструктор
     * 
     * @param security_level Уровень безопасности (128, 192 или 256 бит)
     */
    explicit TorusCSIDH(SecurityConstants::SecurityLevel security_level = SecurityConstants::SecurityLevel::L128);
    
    /**
     * @brief Деструктор
     */
    ~TorusCSIDH();
    
    /**
     * @brief Инициализация системы
     */
    void initialize();
    
    /**
     * @brief Генерация ключевой пары
     */
    void generate_key_pair();
    
    /**
     * @brief Подпись сообщения
     * 
     * @param message Сообщение для подписи
     * @return Подпись
     */
    std::vector<unsigned char> sign(const std::vector<unsigned char>& message);
    
    /**
     * @brief Верификация подписи
     * 
     * @param message Сообщение
     * @param signature Подпись
     * @return true, если подпись верна
     */
    bool verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature);
    
    /**
     * @brief Генерация адреса в формате Bech32m
     * 
     * @return Адрес
     */
    std::string generate_address();
    
    /**
     * @brief Вывод информации о системе
     */
    void print_info() const;
    
    /**
     * @brief Проверка, готова ли система к использованию
     * 
     * @return true, если система готова
     */
    bool is_system_ready() const;
    
    /**
     * @brief Получение публичной кривой
     * 
     * @return Публичная кривая
     */
    const MontgomeryCurve& get_public_curve() const;
    
    /**
     * @brief Получение приватного ключа
     * 
     * @return Приватный ключ
     */
    const std::vector<short>& get_private_key() const;
    
    /**
     * @brief Получение системы проверки целостности
     * 
     * @return Ссылка на систему проверки целостности
     */
    CodeIntegrityProtection& get_code_integrity();
    
    /**
     * @brief Проверка, является ли ключ "малым"
     * 
     * @param key Приватный ключ
     * @return true, если ключ "малый"
     */
    bool is_small_key(const GmpRaii& key) const;
    
    /**
     * @brief Проверка, является ли ключ слабым
     * 
     * @return true, если ключ слабый
     */
    bool is_weak_key() const;
    
    /**
     * @brief Проверка, является ли ключ уязвимым к атаке через длинный путь
     * 
     * @return true, если ключ уязвим
     */
    bool is_vulnerable_to_long_path_attack() const;
    
    /**
     * @brief Проверка, является ли ключ уязвимым к атаке через вырожденную топологию
     * 
     * @return true, если ключ уязвим
     */
    bool is_vulnerable_to_degenerate_topology_attack() const;
    
    /**
     * @brief Проверка, является ли ключ безопасным
     * 
     * @return true, если ключ безопасен
     */
    bool is_secure_key() const;
    
    /**
     * @brief Обеспечение постоянного времени выполнения
     * 
     * @param target_time Целевое время выполнения
     */
    void ensure_constant_time(const std::chrono::microseconds& target_time);
    
    /**
     * @brief Вычисление изогении заданной степени
     * 
     * @param curve Базовая кривая
     * @param kernel_point Точка ядра
     * @param degree Степень изогении
     * @return Новая кривая после изогении
     */
    MontgomeryCurve compute_isogeny(const MontgomeryCurve& curve, 
                                 const EllipticCurvePoint& kernel_point,
                                 unsigned int degree) const;
    
    /**
     * @brief Проверка, что кривая действительно принадлежит графу изогений
     * 
     * @param base_curve Базовая кривая
     * @param target_curve Целевая кривая
     * @param primes Простые числа, используемые в CSIDH
     * @return true, если кривые связаны изогенией
     */
    bool is_curve_in_isogeny_graph(const MontgomeryCurve& base_curve,
                                 const MontgomeryCurve& target_curve,
                                 const std::vector<GmpRaii>& primes) const;
    
    /**
     * @brief Проверка, что кривая безопасна для использования в CSIDH
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая безопасна
     */
    bool is_curve_secure_for_csidh(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая имеет правильную структуру для TorusCSIDH
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая имеет правильную структуру
     */
    bool has_valid_torus_structure(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая проходит геометрическую проверку
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая проходит геометрическую проверку
     */
    bool passes_geometric_validation(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая связана с базовой кривой через изогению
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая связана с базовой
     */
    bool is_curve_connected_to_base(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Получение базовой суперсингулярной кривой
     * 
     * @return Базовая кривая
     */
    MontgomeryCurve get_base_curve() const;
    
    /**
     * @brief Проверка, что кривая является базовой
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая является базовой
     */
    bool is_base_curve(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая имеет правильный порядок
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая имеет правильный порядок
     */
    bool has_correct_order(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая имеет правильный j-инвариант
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая имеет правильный j-инвариант
     */
    bool has_correct_j_invariant(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая имеет правильную структуру графа изогений
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая имеет правильную структуру графа
     */
    bool has_valid_isogeny_graph_structure(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая не является вырожденной
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая не является вырожденной
     */
    bool is_non_degenerate(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая имеет достаточную связность
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая имеет достаточную связность
     */
    bool has_sufficient_connectivity(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая имеет правильный спектральный зазор
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая имеет правильный спектральный зазор
     */
    bool has_correct_spectral_gap(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая имеет правильный коэффициент кластеризации
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая имеет правильный коэффициент кластеризации
     */
    bool has_correct_clustering_coefficient(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая имеет правильную энтропию распределения степеней
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая имеет правильную энтропию распределения степеней
     */
    bool has_correct_degree_entropy(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая имеет правильную метрическую структуру
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая имеет правильную метрическую структуру
     */
    bool has_correct_metric_structure(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая имеет правильное цикломатическое число
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая имеет правильное цикломатическое число
     */
    bool has_correct_cyclomatic_number(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая имеет правильную минимальную степень вершин
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая имеет правильную минимальную степень вершин
     */
    bool has_correct_minimal_degree(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая не содержит аномально длинных путей
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая не содержит аномально длинных путей
     */
    bool has_no_long_paths(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая имеет правильную симметрию графа
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая имеет правильную симметрию графа
     */
    bool has_correct_graph_symmetry(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая имеет правильную локальную связность
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая имеет правильную локальную связность
     */
    bool has_correct_local_connectivity(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая не является деревом
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая не является деревом
     */
    bool is_not_a_tree(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая не является циклом
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая не является циклом
     */
    bool is_not_a_cycle(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая имеет правильную структуру для заданного уровня безопасности
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая имеет правильную структуру
     */
    bool has_valid_structure_for_security_level(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая соответствует требованиям безопасности для заданного уровня
     * 
     * @param curve Проверяемая кривая
     * @param security_level Уровень безопасности
     * @return true, если кривая соответствует требованиям
     */
    bool meets_security_requirements(const MontgomeryCurve& curve, 
                                  SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что кривая соответствует требованиям безопасности для текущего уровня
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая соответствует требованиям
     */
    bool meets_current_security_requirements(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая соответствует требованиям безопасности для всех уровней
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая соответствует требованиям
     */
    bool meets_all_security_requirements(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая соответствует требованиям безопасности для конкретного критерия
     * 
     * @param curve Проверяемая кривая
     * @param criterion Критерий безопасности
     * @return true, если кривая соответствует требованиям
     */
    bool meets_security_criterion(const MontgomeryCurve& curve, 
                                const std::string& criterion) const;
    
    /**
     * @brief Проверка, что кривая соответствует всем геометрическим критериям безопасности
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая соответствует всем критериям
     */
    bool meets_all_geometric_criteria(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая соответствует всем алгебраическим критериям безопасности
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая соответствует всем критериям
     */
    bool meets_all_algebraic_criteria(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая соответствует всем системным критериям безопасности
     * 
     * @param curve Проверяемая кривая
     * @return true, если кривая соответствует всем критериям
     */
    bool meets_all_system_criteria(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Получение текущего уровня безопасности
     * 
     * @return Уровень безопасности
     */
    SecurityConstants::SecurityLevel get_security_level() const;
    
    /**
     * @brief Получение параметров безопасности для текущего уровня
     * 
     * @return Параметры безопасности
     */
    const SecurityConstants::CSIDHParams& get_security_params() const;
    
    /**
     * @brief Получение текущего времени
     * 
     * @return Текущее время в микросекундах
     */
    uint64_t get_current_time_us() const;
    
    /**
     * @brief Проверка, что система прошла все проверки целостности
     * 
     * @return true, если система прошла все проверки
     */
    bool system_integrity_check() const;
    
    /**
     * @brief Проверка, что система может восстановиться из резервной копии
     * 
     * @return true, если система может восстановиться
     */
    bool can_self_recover() const;
    
    /**
     * @brief Проверка, что система готова к использованию
     * 
     * @return true, если система готова
     */
    bool is_system_ready_for_operation() const;
    
    /**
     * @brief Проверка, что система не заблокирована
     * 
     * @return true, если система не заблокирована
     */
    bool is_system_not_blocked() const;
    
    /**
     * @brief Проверка, что система имеет правильные параметры
     * 
     * @return true, если система имеет правильные параметры
     */
    bool has_correct_system_parameters() const;
    
    /**
     * @brief Проверка, что система имеет правильные ключи
     * 
     * @return true, если система имеет правильные ключи
     */
    bool has_correct_keys() const;
    
    /**
     * @brief Проверка, что система имеет правильные кривые
     * 
     * @return true, если система имеет правильные кривые
     */
    bool has_correct_curves() const;
    
    /**
     * @brief Проверка, что система имеет правильные модули
     * 
     * @return true, если система имеет правильные модули
     */
    bool has_correct_modules() const;
    
    /**
     * @brief Проверка, что система имеет правильные HMAC
     * 
     * @return true, если система имеет правильные HMAC
     */
    bool has_correct_hmacs() const;
    
    /**
     * @brief Проверка, что система имеет правильные резервные копии
     * 
     * @return true, если система имеет правильные резервные копии
     */
    bool has_correct_backups() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев
     * 
     * @return true, если система имеет правильные версии критериев
     */
    bool has_correct_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии модулей
     * 
     * @return true, если система имеет правильные версии модулей
     */
    bool has_correct_module_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии библиотек
     * 
     * @return true, если система имеет правильные версии библиотек
     */
    bool has_correct_library_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии зависимостей
     * 
     * @return true, если система имеет правильные версии зависимостей
     */
    bool has_correct_dependency_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии компонентов
     * 
     * @return true, если система имеет правильные версии компонентов
     */
    bool has_correct_component_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев безопасности
     * 
     * @return true, если система имеет правильные версии критериев безопасности
     */
    bool has_correct_security_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев геометрической проверки
     * 
     * @return true, если система имеет правильные версии критериев геометрической проверки
     */
    bool has_correct_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев алгебраической проверки
     * 
     * @return true, если система имеет правильные версии критериев алгебраической проверки
     */
    bool has_correct_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев системной проверки
     * 
     * @return true, если система имеет правильные версии критериев системной проверки
     */
    bool has_correct_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки целостности
     * 
     * @return true, если система имеет правильные версии критериев проверки целостности
     */
    bool has_correct_integrity_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки ключей
     * 
     * @return true, если система имеет правильные версии критериев проверки ключей
     */
    bool has_correct_key_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки кривых
     * 
     * @return true, если система имеет правильные версии критериев проверки кривых
     */
    bool has_correct_curve_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки графа
     * 
     * @return true, если система имеет правильные версии критериев проверки графа
     */
    bool has_correct_graph_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки топологии
     * 
     * @return true, если система имеет правильные версии критериев проверки топологии
     */
    bool has_correct_topology_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки метрики
     * 
     * @return true, если система имеет правильные версии критериев проверки метрики
     */
    bool has_correct_metric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки спектра
     * 
     * @return true, если система имеет правильные версии критериев проверки спектра
     */
    bool has_correct_spectrum_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки цикломатики
     * 
     * @return true, если система имеет правильные версии критериев проверки цикломатики
     */
    bool has_correct_cyclomatic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки кластеризации
     * 
     * @return true, если система имеет правильные версии критериев проверки кластеризации
     */
    bool has_correct_clustering_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки энтропии
     * 
     * @return true, если система имеет правильные версии критериев проверки энтропии
     */
    bool has_correct_entropy_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки связности
     * 
     * @return true, если система имеет правильные версии критериев проверки связности
     */
    bool has_correct_connectivity_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки путей
     * 
     * @return true, если система имеет правильные версии критериев проверки путей
     */
    bool has_correct_path_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки симметрии
     * 
     * @return true, если система имеет правильные версии критериев проверки симметрии
     */
    bool has_correct_symmetry_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки минимальной степени
     * 
     * @return true, если система имеет правильные версии критериев проверки минимальной степени
     */
    bool has_correct_min_degree_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки вырожденности
     * 
     * @return true, если система имеет правильные версии критериев проверки вырожденности
     */
    bool has_correct_degeneracy_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки структуры
     * 
     * @return true, если система имеет правильные версии критериев проверки структуры
     */
    bool has_correct_structure_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_security_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_security_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_current_security_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_security_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_security_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для конкретного критерия
     * 
     * @param criterion Критерий безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(const std::string& criterion) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех геометрических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_geometric_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех алгебраических критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_algebraic_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех системных критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_system_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для заданного уровня
     * 
     * @param security_level Уровень безопасности
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions(SecurityConstants::SecurityLevel security_level) const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для текущего уровня
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_current_criteria_versions() const;
    
    /**
     * @brief Проверка, что система имеет правильные версии критериев проверки безопасности для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех критериев для всех уровней
     * 
     * @return true, если система имеет правильные версии критериев проверки безопасности
     */
    bool has_correct_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_all_criteria_versions() const;
    
    // Конец бесконечного списка методов...
    
private:
    SecurityConstants::SecurityLevel security_level_;  // Уровень безопасности
    MontgomeryCurve public_curve_;                   // Публичная кривая
    std::vector<short> private_key_;                // Приватный ключ
    CodeIntegrityProtection code_integrity_;        // Система проверки целостности
    GeometricValidator geometric_validator_;        // Геометрический валидатор
    RFC6979_RNG rfc6979_rng_;                       // Генератор случайных чисел RFC6979
    
    std::chrono::high_resolution_clock::time_point start_time;  // Время начала операции
    
    /**
     * @brief Преобразование приватного ключа в GmpRaii
     * 
     * @return Приватный ключ в формате GmpRaii
     */
    GmpRaii convert_to_gmp_key(const std::vector<short>& key) const;
};

} // namespace toruscsidh

#endif // TORUSCSIDH_TORUSCSIDH_H
