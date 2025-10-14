#ifndef TORUSCSIDH_GEOMETRIC_VALIDATOR_H
#define TORUSCSIDH_GEOMETRIC_VALIDATOR_H

#include <vector>
#include <map>
#include <set>
#include <cmath>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/laplacian_matrix.hpp>
#include <boost/graph/connected_components.hpp>
#include <boost/graph/clustering_coefficient.hpp>
#include <boost/graph/floyd_warshall_shortest.hpp>
#include <boost/graph/cuthill_mckee_ordering.hpp>
#include <boost/numeric/ublas/matrix.hpp>
#include <boost/numeric/ublas/io.hpp>
#include <boost/numeric/ublas/lu.hpp>
#include <boost/numeric/ublas/eigen.hpp>
#include "elliptic_curve.h"
#include "security_constants.h"
#include "secure_audit_logger.h"

namespace toruscsidh {

// Определение пользовательского свойства для хранения кривой в вершине графа
struct vertex_curve_t {
    typedef boost::vertex_property_tag kind;
};

// Тип графа изогений с информацией о кривых в вершинах
typedef boost::property<vertex_curve_t, MontgomeryCurve> VertexProperty;
typedef boost::adjacency_list<
    boost::vecS, 
    boost::vecS, 
    boost::undirectedS,
    VertexProperty,
    boost::property<boost::edge_index_t, int>
> IsogenyGraph;

/**
 * @brief Класс для геометрической проверки кривых
 * 
 * Реализует комплексную проверку кривых на основе анализа их позиции
 * в графе изогений. Проверка включает 7 критериев безопасности:
 * 1. Цикломатическое число (вес: 15%)
 * 2. Спектральный анализ (спектральный зазор) (вес: 30%)
 * 3. Коэффициент кластеризации (вес: 20%)
 * 4. Энтропия распределения степеней (вес: 25%)
 * 5. Энтропия распределения кратчайших путей (вес: 0%)
 * 6. Структурная сложность (вес: 0%)
 * 7. Расстояние до базовой кривой (вес: 10%)
 * 
 * Кривая считается легитимной, если суммарный вес пройденных критериев ≥ 85%.
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
     * @param base_curve Базовая кривая
     * @param public_curve Публичная кривая для проверки
     * @param subgraph Подграф изогений вокруг базовой кривой
     * @param cyclomatic_score Результат проверки цикломатического числа
     * @param spectral_score Результат проверки спектрального зазора
     * @param clustering_score Результат проверки коэффициента кластеризации
     * @param degree_entropy_score Результат проверки энтропии степеней
     * @param distance_score Результат проверки расстояния до базовой кривой
     * @return true, если кривая легитимна (суммарный вес критериев ≥ 85%)
     */
    bool validate_curve(const MontgomeryCurve& base_curve,
                       const MontgomeryCurve& public_curve,
                       const IsogenyGraph& subgraph,
                       double& cyclomatic_score,
                       double& spectral_score,
                       double& clustering_score,
                       double& degree_entropy_score,
                       double& distance_score);
    
    /**
     * @brief Построение подграфа изогений
     * 
     * Строит подграф изогений вокруг базовой кривой с заданным радиусом.
     * 
     * @param base_curve Базовая кривая
     * @param public_curve Публичная кривая
     * @param radius Радиус подграфа
     * @return Подграф изогений
     */
    IsogenyGraph build_isogeny_subgraph(const MontgomeryCurve& base_curve,
                                      const MontgomeryCurve& public_curve,
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
    double compute_cyclomatic_number(const IsogenyGraph& graph) const;
    
    /**
     * @brief Вычисление спектрального зазора
     * 
     * Спектральный зазор = (λ₄ - λ₃) / λ₃
     * где λ₃, λ₄ - собственные значения нормализованной матрицы Лапласа
     * 
     * @param graph Граф изогений
     * @return Нормализованный спектральный зазор [0,1]
     */
    double compute_spectral_gap(const IsogenyGraph& graph) const;
    
    /**
     * @brief Вычисление коэффициента кластеризации
     * 
     * Коэффициент кластеризации = 3 * количество треугольников / количество связок
     * 
     * @param graph Граф изогений
     * @return Нормализованный коэффициент кластеризации [0,1]
     */
    double compute_clustering_coefficient(const IsogenyGraph& graph) const;
    
    /**
     * @brief Вычисление энтропии распределения степеней
     * 
     * Энтропия степеней = -Σ p_i * log2(p_i)
     * где p_i - вероятность степени i
     * 
     * @param graph Граф изогений
     * @return Нормализованная энтропия степеней [0,1]
     */
    double compute_degree_entropy(const IsogenyGraph& graph) const;
    
    /**
     * @brief Вычисление энтропии распределения кратчайших путей
     * 
     * Энтропия кратчайших путей = -Σ p_d * log2(p_d)
     * где p_d - вероятность кратчайшего пути длины d
     * 
     * @param graph Граф изогений
     * @param base_curve Базовая кривая
     * @param public_curve Публичная кривая
     * @return Нормализованная энтропия кратчайших путей [0,1]
     */
    double compute_distance_entropy(const IsogenyGraph& graph,
                                   const MontgomeryCurve& base_curve,
                                   const MontgomeryCurve& public_curve) const;
    
    /**
     * @brief Вычисление структурной сложности
     * 
     * Структурная сложность = 1 - (количество изоморфных подграфов / общее количество подграфов)
     * 
     * @param graph Граф изогений
     * @return Нормализованная структурная сложность [0,1]
     */
    double compute_structural_complexity(const IsogenyGraph& graph) const;
    
    /**
     * @brief Вычисление расстояния до базовой кривой
     * 
     * @param graph Граф изогений
     * @param base_curve Базовая кривая
     * @param public_curve Публичная кривая
     * @return Нормализованное расстояние [0,1]
     */
    double compute_distance_to_base_curve(const IsogenyGraph& graph,
                                         const MontgomeryCurve& base_curve,
                                         const MontgomeryCurve& public_curve) const;
    
    /**
     * @brief Проверка, что кривая принадлежит графу изогений
     * 
     * @param base_curve Базовая кривая
     * @param public_curve Публичная кривая
     * @param primes Простые числа для изогений
     * @return true, если кривая принадлежит графу изогений
     */
    bool is_curve_in_isogeny_graph(const MontgomeryCurve& base_curve,
                                  const MontgomeryCurve& public_curve,
                                  const std::vector<GmpRaii>& primes) const;
    
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
    
private:
    /**
     * @brief Проверка, что кривая имеет правильную структуру
     * 
     * @param curve Кривая для проверки
     * @return true, если кривая имеет правильную структуру
     */
    bool has_valid_structure(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая не является поддельной
     * 
     * @param curve Кривая для проверки
     * @return true, если кривая не поддельная
     */
    bool is_not_fake_curve(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Вычисление матрицы Лапласа
     * 
     * @param graph Граф изогений
     * @return Матрица Лапласа
     */
    boost::numeric::ublas::matrix<double> compute_laplacian_matrix(const IsogenyGraph& graph) const;
    
    /**
     * @brief Вычисление собственных значений матрицы
     * 
     * @param matrix Матрица
     * @return Собственные значения
     */
    std::vector<double> compute_eigenvalues(const boost::numeric::ublas::matrix<double>& matrix) const;
    
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
    
    /**
     * @brief Получение кривой из вершины графа
     * 
     * @param graph Граф изогений
     * @param v Вершина графа
     * @return Кривая, соответствующая вершине
     */
    const MontgomeryCurve& get_curve_from_vertex(const IsogenyGraph& graph, 
                                              IsogenyGraph::vertex_descriptor v) const;
    
    /**
     * @brief Проверка модулярного уравнения для изогении степени 3
     * 
     * @param j1 Первый j-инвариант
     * @param j2 Второй j-инвариант
     * @param p Простое число характеристики поля
     * @return true, если модулярное уравнение выполняется
     */
    bool verify_modular_equation_degree_3(const GmpRaii& j1, const GmpRaii& j2, const GmpRaii& p) const;
    
    /**
     * @brief Проверка модулярного уравнения для изогении степени 5
     * 
     * @param j1 Первый j-инвариант
     * @param j2 Второй j-инвариант
     * @param p Простое число характеристики поля
     * @return true, если модулярное уравнение выполняется
     */
    bool verify_modular_equation_degree_5(const GmpRaii& j1, const GmpRaii& j2, const GmpRaii& p) const;
    
    /**
     * @brief Проверка модулярного уравнения для изогении степени 7
     * 
     * @param j1 Первый j-инвариант
     * @param j2 Второй j-инвариант
     * @param p Простое число характеристики поля
     * @return true, если модулярное уравнение выполняется
     */
    bool verify_modular_equation_degree_7(const GmpRaii& j1, const GmpRaii& j2, const GmpRaii& p) const;
    
    /**
     * @brief Проверка модулярного уравнения для изогении общей степени
     * 
     * @param j1 Первый j-инвариант
     * @param j2 Второй j-инвариант
     * @param degree Степень изогении
     * @param p Простое число характеристики поля
     * @return true, если модулярное уравнение выполняется
     */
    bool verify_modular_equation_general(const GmpRaii& j1, const GmpRaii& j2, 
                                       unsigned int degree, const GmpRaii& p) const;
    
    SecurityConstants::SecurityLevel security_level_; // Уровень безопасности
    SecurityConstants::GeometricParams params_; // Параметры безопасности
    std::mutex validator_mutex_; // Мьютекс для синхронизации
};

} // namespace toruscsidh

#endif // TORUSCSIDH_GEOMETRIC_VALIDATOR_H
