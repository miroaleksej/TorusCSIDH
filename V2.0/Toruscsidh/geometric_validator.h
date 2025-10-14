#ifndef TORUSCSIDH_GEOMETRIC_VALIDATOR_H
#define TORUSCSIDH_GEOMETRIC_VALIDATOR_H

#include <vector>
#include <map>
#include <set>
#include <queue>
#include <cmath>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/laplacian_matrix.hpp>
#include <boost/graph/connected_components.hpp>
#include <boost/graph/clustering_coefficient.hpp>
#include "elliptic_curve.h"
#include "security_constants.h"
#include "secure_audit_logger.h"

namespace toruscsidh {

// Тип графа изогений
typedef boost::adjacency_list<
    boost::vecS, 
    boost::vecS, 
    boost::undirectedS,
    boost::property<boost::vertex_index_t, int>,
    boost::property<boost::edge_index_t, int>
> IsogenyGraph;

/**
 * @brief Класс для геометрической проверки кривых
 * 
 * Реализует комплексную проверку кривых на основе анализа их позиции
 * в графе изогений. Проверка включает 7 критериев безопасности:
 * 1. Цикломатическое число
 * 2. Спектральный анализ (спектральный зазор)
 * 3. Коэффициент кластеризации
 * 4. Энтропия распределения степеней
 * 5. Энтропия распределения кратчайших путей
 * 6. Расстояние до базовой кривой
 * 7. Гибридная оценка на основе всех критериев
 */
class GeometricValidator {
public:
    /**
     * @brief Конструктор
     * 
     * @param security_level Уровень безопасности
     */
    explicit GeometricValidator(SecurityConstants::SecurityLevel security_level);
    
    /**
     * @brief Деструктор
     */
    ~GeometricValidator();
    
    /**
     * @brief Проверка кривой на безопасность
     * 
     * Выполняет комплексную геометрическую проверку кривой.
     * 
     * @param curve Кривая для проверки
     * @param subgraph Подграф изогений вокруг базовой кривой
     * @param cyclomatic_score Результат проверки цикломатического числа
     * @param spectral_gap_score Результат проверки спектрального зазора
     * @param clustering_score Результат проверки коэффициента кластеризации
     * @param degree_entropy_score Результат проверки энтропии степеней
     * @param distance_entropy_score Результат проверки энтропии кратчайших путей
     * @return true, если кривая безопасна
     */
    bool validate_curve(const MontgomeryCurve& curve,
                       const IsogenyGraph& subgraph,
                       double& cyclomatic_score,
                       double& spectral_gap_score,
                       double& clustering_score,
                       double& degree_entropy_score,
                       double& distance_entropy_score);
    
    /**
     * @brief Построение подграфа изогений
     * 
     * Строит подграф изогений вокруг базовой кривой с заданным радиусом.
     * 
     * @param base_curve Базовая кривая
     * @param target_curve Целевая кривая
     * @param radius Радиус подграфа
     * @return Подграф изогений
     */
    IsogenyGraph build_isogeny_subgraph(const MontgomeryCurve& base_curve,
                                      const MontgomeryCurve& target_curve,
                                      int radius);
    
    /**
     * @brief Вычисление цикломатического числа
     * 
     * Цикломатическое число = E - V + C, где
     * E - количество ребер
     * V - количество вершин
     * C - количество компонент связности
     * 
     * @param graph Граф изогений
     * @return Нормализованное цикломатическое число [0,1]
     */
    double compute_cyclomatic_number(const IsogenyGraph& graph);
    
    /**
     * @brief Вычисление спектрального зазора
     * 
     * Спектральный зазор = (λ₄ - λ₃) / λ₃
     * где λ₃, λ₄ - собственные значения нормализованной матрицы Лапласа
     * 
     * @param graph Граф изогений
     * @return Нормализованный спектральный зазор [0,1]
     */
    double compute_spectral_gap(const IsogenyGraph& graph);
    
    /**
     * @brief Вычисление коэффициента кластеризации
     * 
     * Коэффициент кластеризации = 3 * количество треугольников / количество связок
     * 
     * @param graph Граф изогений
     * @return Нормализованный коэффициент кластеризации [0,1]
     */
    double compute_clustering_coefficient(const IsogenyGraph& graph);
    
    /**
     * @brief Вычисление энтропии распределения степеней
     * 
     * Энтропия степеней = -Σ p_i * log2(p_i)
     * где p_i - вероятность степени i
     * 
     * @param graph Граф изогений
     * @return Нормализованная энтропия степеней [0,1]
     */
    double compute_degree_entropy(const IsogenyGraph& graph);
    
    /**
     * @brief Вычисление энтропии распределения кратчайших путей
     * 
     * Энтропия кратчайших путей = -Σ p_d * log2(p_d)
     * где p_d - вероятность кратчайшего пути длины d
     * 
     * @param graph Граф изогений
     * @param base_curve Базовая кривая
     * @param target_curve Целевая кривая
     * @return Нормализованная энтропия кратчайших путей [0,1]
     */
    double compute_distance_entropy(const IsogenyGraph& graph,
                                   const MontgomeryCurve& base_curve,
                                   const MontgomeryCurve& target_curve);
    
    /**
     * @brief Вычисление гибридной оценки
     * 
     * Гибридная оценка = w1*c1 + w2*c2 + w3*c3 + w4*c4 + w5*c5
     * где ci - нормализованные значения критериев
     * 
     * @param cyclomatic_score Цикломатическое число
     * @param spectral_gap_score Спектральный зазор
     * @param clustering_score Коэффициент кластеризации
     * @param degree_entropy_score Энтропия степеней
     * @param distance_entropy_score Энтропия кратчайших путей
     * @return Гибридная оценка [0,1]
     */
    double compute_hybrid_score(double cyclomatic_score,
                              double spectral_gap_score,
                              double clustering_score,
                              double degree_entropy_score,
                              double distance_entropy_score);
    
    /**
     * @brief Проверка, что кривая принадлежит графу изогений
     * 
     * @param base_curve Базовая кривая
     * @param target_curve Целевая кривая
     * @param primes Простые числа для изогений
     * @return true, если кривая принадлежит графу изогений
     */
    bool is_curve_in_isogeny_graph(const MontgomeryCurve& base_curve,
                                 const MontgomeryCurve& target_curve,
                                 const std::vector<GmpRaii>& primes);
    
    /**
     * @brief Вычисление изогении заданной степени
     * 
     * @param curve Базовая кривая
     * @param kernel_point Точка ядра
     * @param degree Степень изогении
     * @return Результирующая кривая
     */
    MontgomeryCurve compute_isogeny(const MontgomeryCurve& curve,
                                  const EllipticCurvePoint& kernel_point,
                                  unsigned int degree) const;
    
    /**
     * @brief Проверка целостности геометрической проверки
     * 
     * @return true, если геометрическая проверка цела
     */
    bool verify_integrity() const;
    
    /**
     * @brief Получение текущего уровня безопасности
     * 
     * @return Уровень безопасности
     */
    SecurityConstants::SecurityLevel get_security_level() const;
    
    /**
     * @brief Получение текущих параметров безопасности
     * 
     * @return Параметры безопасности
     */
    const SecurityConstants::GeometricParams& get_geometric_params() const;
    
    /**
     * @brief Обновление параметров безопасности
     * 
     * @param params Новые параметры безопасности
     * @return true, если обновление успешно
     */
    bool update_geometric_params(const SecurityConstants::GeometricParams& params);
    
    /**
     * @brief Проверка, что кривая не является поддельной
     * 
     * @param curve Кривая для проверки
     * @return true, если кривая не поддельная
     */
    bool is_not_fake_curve(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая имеет правильную структуру
     * 
     * @param curve Кривая для проверки
     * @return true, если кривая имеет правильную структуру
     */
    bool has_valid_structure(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая устойчива к топологическим атакам
     * 
     * @param curve Кривая для проверки
     * @return true, если кривая устойчива к топологическим атакам
     */
    bool is_resistant_to_topological_attacks(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через вырожденную топологию
     * 
     * @param curve Кривая для проверки
     * @return true, если кривая устойчива к атакам через вырожденную топологию
     */
    bool is_resistant_to_degenerate_topology_attacks(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через длинные пути
     * 
     * @param curve Кривая для проверки
     * @return true, если кривая устойчива к атакам через длинные пути
     */
    bool is_resistant_to_long_path_attacks(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через регулярные паттерны
     * 
     * @param curve Кривая для проверки
     * @return true, если кривая устойчива к атакам через регулярные паттерны
     */
    bool is_resistant_to_regular_pattern_attacks(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через малые подгруппы
     * 
     * @param curve Кривая для проверки
     * @return true, если кривая устойчива к атакам через малые подгруппы
     */
    bool is_resistant_to_small_subgroup_attacks(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через недопустимые кривые
     * 
     * @param curve Кривая для проверки
     * @return true, если кривая устойчива к атакам через недопустимые кривые
     */
    bool is_resistant_to_invalid_curve_attacks(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через недопустимые точки
     * 
     * @param curve Кривая для проверки
     * @return true, если кривая устойчива к атакам через недопустимые точки
     */
    bool is_resistant_to_invalid_point_attacks(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе
     * 
     * @param curve Кривая для проверки
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом конкретного набора простых чисел
     * 
     * @param curve Кривая для проверки
     * @param primes Набор простых чисел
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                          const std::vector<GmpRaii>& primes) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом конкретного простого числа
     * 
     * @param curve Кривая для проверки
     * @param prime Простое число
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                          const GmpRaii& prime) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом конкретного простого числа и максимальной степени
     * 
     * @param curve Кривая для проверки
     * @param prime Простое число
     * @param max_degree Максимальная степень
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                          const GmpRaii& prime,
                                                          unsigned int max_degree) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом конкретного набора простых чисел и максимальной степени
     * 
     * @param curve Кривая для проверки
     * @param primes Набор простых чисел
     * @param max_degree Максимальная степень
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                          const std::vector<GmpRaii>& primes,
                                                          unsigned int max_degree) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом конкретного простого числа, максимальной степени и максимального количества
     * 
     * @param curve Кривая для проверки
     * @param prime Простое число
     * @param max_degree Максимальная степень
     * @param max_count Максимальное количество
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                          const GmpRaii& prime,
                                                          unsigned int max_degree,
                                                          unsigned int max_count) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом конкретного набора простых чисел, максимальной степени и максимального количества
     * 
     * @param curve Кривая для проверки
     * @param primes Набор простых чисел
     * @param max_degree Максимальная степень
     * @param max_count Максимальное количество
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                          const std::vector<GmpRaii>& primes,
                                                          unsigned int max_degree,
                                                          unsigned int max_count) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом конкретного простого числа, максимальной степени, максимального количества и максимального отношения
     * 
     * @param curve Кривая для проверки
     * @param prime Простое число
     * @param max_degree Максимальная степень
     * @param max_count Максимальное количество
     * @param max_ratio Максимальное отношение
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                          const GmpRaii& prime,
                                                          unsigned int max_degree,
                                                          unsigned int max_count,
                                                          double max_ratio) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом конкретного набора простых чисел, максимальной степени, максимального количества и максимального отношения
     * 
     * @param curve Кривая для проверки
     * @param primes Набор простых чисел
     * @param max_degree Максимальная степень
     * @param max_count Максимальное количество
     * @param max_ratio Максимальное отношение
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                          const std::vector<GmpRaii>& primes,
                                                          unsigned int max_degree,
                                                          unsigned int max_count,
                                                          double max_ratio) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом фиксированного префикса и суффикса
     * 
     * @param curve Кривая для проверки
     * @param prefix Фиксированный префикс
     * @param suffix Фиксированный суффикс
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                          const std::vector<unsigned char>& prefix,
                                                          const std::vector<unsigned char>& suffix) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом фиксированного префикса, среднего участка и суффикса
     * 
     * @param curve Кривая для проверки
     * @param prefix Фиксированный префикс
     * @param middle Фиксированный средний участок
     * @param suffix Фиксированный суффикс
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                          const std::vector<unsigned char>& prefix,
                                                          const std::vector<unsigned char>& middle,
                                                          const std::vector<unsigned char>& suffix) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом фиксированного префикса, среднего участка и произвольного суффикса
     * 
     * @param curve Кривая для проверки
     * @param prefix Фиксированный префикс
     * @param middle Фиксированный средний участок
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                          const std::vector<unsigned char>& prefix,
                                                          const std::vector<unsigned char>& middle) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом произвольного префикса, фиксированного среднего участка и фиксированного суффикса
     * 
     * @param curve Кривая для проверки
     * @param middle Фиксированный средний участок
     * @param suffix Фиксированный суффикс
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                          const std::vector<unsigned char>& middle,
                                                          const std::vector<unsigned char>& suffix) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом произвольного префикса, фиксированного среднего участка и произвольного суффикса
     * 
     * @param curve Кривая для проверки
     * @param middle Фиксированный средний участок
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                          const std::vector<unsigned char>& middle) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом произвольного префикса, произвольного среднего участка и фиксированного суффикса
     * 
     * @param curve Кривая для проверки
     * @param suffix Фиксированный суффикс
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                          const std::vector<unsigned char>& suffix) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом фиксированного префикса, произвольного среднего участка и фиксированного суффикса
     * 
     * @param curve Кривая для проверки
     * @param prefix Фиксированный префикс
     * @param suffix Фиксированный суффикс
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                          const std::vector<unsigned char>& prefix,
                                                          const std::vector<unsigned char>& suffix) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом фиксированного префикса, произвольного среднего участка и произвольного суффикса
     * 
     * @param curve Кривая для проверки
     * @param prefix Фиксированный префикс
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks(const MontgomeryCurve& curve,
                                                          const std::vector<unsigned char>& prefix) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом произвольного префикса, фиксированного среднего участка и произвольного суффикса
     * 
     * @param curve Кривая для проверки
     * @param middle Фиксированный средний участок
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks_with_middle(const MontgomeryCurve& curve,
                                                                     const std::vector<unsigned char>& middle) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом произвольного префикса, произвольного среднего участка и фиксированного суффикса
     * 
     * @param curve Кривая для проверки
     * @param suffix Фиксированный суффикс
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks_with_suffix(const MontgomeryCurve& curve,
                                                                     const std::vector<unsigned char>& suffix) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом произвольного префикса, фиксированного среднего участка и фиксированного суффикса
     * 
     * @param curve Кривая для проверки
     * @param middle Фиксированный средний участок
     * @param suffix Фиксированный суффикс
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks_with_middle_and_suffix(const MontgomeryCurve& curve,
                                                                                const std::vector<unsigned char>& middle,
                                                                                const std::vector<unsigned char>& suffix) const;
    
    /**
     * @brief Проверка, что кривая устойчива к атакам через конфайнмент в малой подгруппе с учетом фиксированного префикса, фиксированного среднего участка и фиксированного суффикса
     * 
     * @param curve Кривая для проверки
     * @param prefix Фиксированный префикс
     * @param middle Фиксированный средний участок
     * @param suffix Фиксированный суффикс
     * @return true, если кривая устойчива к атакам через конфайнмент в малой подгруппе
     */
    bool is_resistant_to_small_subgroup_confinement_attacks_with_prefix_middle_suffix(const MontgomeryCurve& curve,
                                                                                   const std::vector<unsigned char>& prefix,
                                                                                   const std::vector<unsigned char>& middle,
                                                                                   const std::vector<unsigned char>& suffix) const;
    
private:
    /**
     * @brief Вычисление цикломатического числа для подграфа
     * 
     * @param subgraph Подграф изогений
     * @param base_curve Базовая кривая
     * @param target_curve Целевая кривая
     * @return Нормализованное цикломатическое число [0,1]
     */
    double compute_cyclomatic_number_for_subgraph(const IsogenyGraph& subgraph,
                                                const MontgomeryCurve& base_curve,
                                                const MontgomeryCurve& target_curve);
    
    /**
     * @brief Вычисление спектрального зазора для подграфа
     * 
     * @param subgraph Подграф изогений
     * @param base_curve Базовая кривая
     * @param target_curve Целевая кривая
     * @return Нормализованный спектральный зазор [0,1]
     */
    double compute_spectral_gap_for_subgraph(const IsogenyGraph& subgraph,
                                           const MontgomeryCurve& base_curve,
                                           const MontgomeryCurve& target_curve);
    
    /**
     * @brief Вычисление коэффициента кластеризации для подграфа
     * 
     * @param subgraph Подграф изогений
     * @param base_curve Базовая кривая
     * @param target_curve Целевая кривая
     * @return Нормализованный коэффициент кластеризации [0,1]
     */
    double compute_clustering_coefficient_for_subgraph(const IsogenyGraph& subgraph,
                                                    const MontgomeryCurve& base_curve,
                                                    const MontgomeryCurve& target_curve);
    
    /**
     * @brief Вычисление энтропии степеней для подграфа
     * 
     * @param subgraph Подграф изогений
     * @param base_curve Базовая кривая
     * @param target_curve Целевая кривая
     * @return Нормализованная энтропия степеней [0,1]
     */
    double compute_degree_entropy_for_subgraph(const IsogenyGraph& subgraph,
                                             const MontgomeryCurve& base_curve,
                                             const MontgomeryCurve& target_curve);
    
    /**
     * @brief Вычисление энтропии кратчайших путей для подграфа
     * 
     * @param subgraph Подграф изогений
     * @param base_curve Базовая кривая
     * @param target_curve Целевая кривая
     * @return Нормализованная энтропия кратчайших путей [0,1]
     */
    double compute_distance_entropy_for_subgraph(const IsogenyGraph& subgraph,
                                               const MontgomeryCurve& base_curve,
                                               const MontgomeryCurve& target_curve);
    
    /**
     * @brief Проверка на наличие двух независимых циклов
     * 
     * @param eigenvalues Собственные значения матрицы Лапласа
     * @return true, если есть два независимых цикла
     */
    bool has_two_independent_cycles(const std::vector<double>& eigenvalues) const;
    
    /**
     * @brief Проверка спектрального зазора
     * 
     * @param eigenvalues Собственные значения матрицы Лапласа
     * @return true, если спектральный зазор достаточен
     */
    bool has_sufficient_spectral_gap(const std::vector<double>& eigenvalues) const;
    
    /**
     * @brief Вычисление матрицы Лапласа
     * 
     * @param graph Граф изогений
     * @return Матрица Лапласа
     */
    std::vector<std::vector<double>> compute_laplacian_matrix(const IsogenyGraph& graph) const;
    
    /**
     * @brief Вычисление собственных значений матрицы
     * 
     * @param matrix Матрица
     * @return Собственные значения
     */
    std::vector<double> compute_eigenvalues(const std::vector<std::vector<double>>& matrix) const;
    
    /**
     * @brief Вычисление кратчайших путей
     * 
     * @param graph Граф изогений
     * @param source_vertex Исходная вершина
     * @return Длины кратчайших путей
     */
    std::vector<int> compute_shortest_paths(const IsogenyGraph& graph, int source_vertex) const;
    
    /**
     * @brief Вычисление энтропии
     * 
     * @param probabilities Вероятности
     * @return Энтропия
     */
    double compute_entropy(const std::vector<double>& probabilities) const;
    
    /**
     * @brief Нормализация значения к [0,1]
     * 
     * @param value Значение
     * @param min_value Минимальное значение
     * @param max_value Максимальное значение
     * @return Нормализованное значение
     */
    double normalize_value(double value, double min_value, double max_value) const;
    
    /**
     * @brief Проверка целостности внутренних данных
     * 
     * @return true, если данные целы
     */
    bool verify_internal_data_integrity() const;
    
    SecurityConstants::SecurityLevel security_level_; // Уровень безопасности
    SecurityConstants::GeometricParams params_; // Параметры безопасности
    std::mutex validator_mutex_; // Мьютекс для синхронизации
};

} // namespace toruscsidh

#endif // TORUSCSIDH_GEOMETRIC_VALIDATOR_H
