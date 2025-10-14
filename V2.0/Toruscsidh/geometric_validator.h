#ifndef GEOMETRIC_VALIDATOR_H
#define GEOMETRIC_VALIDATOR_H

#include <vector>
#include <gmpxx.h>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/cuthill_mckee_ordering.hpp>
#include <boost/graph/floyd_warshall_shortest.hpp>
#include <boost/graph/laplacian_matrix.hpp>
#include <Eigen/Dense>
#include "security_constants.h"
#include "elliptic_curve.h"

/**
 * @brief Граф изогений
 */
typedef boost::adjacency_list<
    boost::vecS, 
    boost::vecS, 
    boost::undirectedS,
    boost::property<boost::vertex_index_t, int>,
    boost::property<boost::edge_weight_t, double>
> IsogenyGraph;

/**
 * @brief Класс для геометрической проверки безопасности графа изогений
 * 
 * Выполняет анализ графа изогений на соответствие криптографическим требованиям.
 */
class GeometricValidator {
public:
    /**
     * @brief Конструктор
     */
    GeometricValidator();
    
    /**
     * @brief Инициализация параметров безопасности для указанного уровня
     * @param level Уровень безопасности
     */
    void initialize_security_parameters(SecurityConstants::SecurityLevel level);
    
    /**
     * @brief Построение подграфа изогений вокруг заданной кривой
     * @param curve Базовая кривая
     * @param radius Радиус подграфа
     * @return Подграф изогений
     */
    IsogenyGraph build_isogeny_subgraph(const MontgomeryCurve& curve, size_t radius);
    
    /**
     * @brief Вычисление цикломатического числа графа
     * @param graph Граф изогений
     * @return Цикломатическое число
     */
    double compute_cyclomatic_number(const IsogenyGraph& graph);
    
    /**
     * @brief Вычисление спектрального зазора графа
     * @param graph Граф изогений
     * @return Спектральный зазор
     */
    double compute_spectral_gap(const IsogenyGraph& graph);
    
    /**
     * @brief Вычисление коэффициента кластеризации графа
     * @param graph Граф изогений
     * @return Коэффициент кластеризации
     */
    double compute_clustering_coefficient(const IsogenyGraph& graph);
    
    /**
     * @brief Вычисление энтропии степеней узлов графа
     * @param graph Граф изогений
     * @return Энтропия степеней
     */
    double compute_degree_entropy(const IsogenyGraph& graph);
    
    /**
     * @brief Вычисление энтропии кратчайших путей графа
     * @param graph Граф изогений
     * @return Энтропия кратчайших путей
     */
    double compute_shortest_path_entropy(const IsogenyGraph& graph);
    
    /**
     * @brief Проверка безопасности кривой по геометрическим критериям
     * @param curve Кривая
     * @param subgraph Подграф изогений
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
    
private:
    SecurityConstants::SecurityLevel security_level;  ///< Уровень безопасности
};

GeometricValidator::GeometricValidator() : security_level(SecurityConstants::SecurityLevel::LEVEL_128) {
    SecurityConstants::initialize(security_level);
}

void GeometricValidator::initialize_security_parameters(SecurityConstants::SecurityLevel level) {
    security_level = level;
    SecurityConstants::initialize(security_level);
}

IsogenyGraph GeometricValidator::build_isogeny_subgraph(const MontgomeryCurve& curve, size_t radius) {
    IsogenyGraph subgraph;
    
    // В реальной системе здесь будет построение подграфа изогений
    // с использованием алгоритмов поиска в ширину вокруг заданной кривой
    
    // Для демонстрации добавим несколько вершин и ребер
    for (size_t i = 0; i < radius * 2; i++) {
        boost::add_vertex(subgraph);
    }
    
    // Добавляем ребра
    for (size_t i = 0; i < num_vertices(subgraph) - 1; i++) {
        boost::add_edge(i, i + 1, subgraph);
    }
    
    return subgraph;
}

double GeometricValidator::compute_cyclomatic_number(const IsogenyGraph& graph) {
    // Цикломатическое число = E - V + C, где
    // E - количество ребер
    // V - количество вершин
    // C - количество компонент связности
    
    size_t edges = num_edges(graph);
    size_t vertices = num_vertices(graph);
    size_t components = 1; // В реальной системе нужно вычислить
    
    return static_cast<double>(edges - vertices + components) / vertices;
}

double GeometricValidator::compute_spectral_gap(const IsogenyGraph& graph) {
    // Спектральный зазор = λ1 - λ2, где λ1 и λ2 - первые два собственных значения
    // матрицы Лапласа графа
    
    // Создаем матрицу Лапласа
    Eigen::MatrixXd laplacian = boost::laplacian_matrix(graph);
    
    // Вычисляем собственные значения
    Eigen::SelfAdjointEigenSolver<Eigen::MatrixXd> solver(laplacian);
    Eigen::VectorXd eigenvalues = solver.eigenvalues();
    
    // Сортируем собственные значения
    std::vector<double> sorted_eigenvalues;
    for (int i = 0; i < eigenvalues.size(); i++) {
        sorted_eigenvalues.push_back(eigenvalues(i));
    }
    std::sort(sorted_eigenvalues.begin(), sorted_eigenvalues.end());
    
    // Спектральный зазор = λ1 - λ0 (λ0 всегда 0)
    if (sorted_eigenvalues.size() < 2) {
        return 0.0;
    }
    
    return sorted_eigenvalues[1] - sorted_eigenvalues[0];
}

double GeometricValidator::compute_clustering_coefficient(const IsogenyGraph& graph) {
    // Коэффициент кластеризации = 3 * количество треугольников / количество связок
    
    size_t triangles = 0;
    size_t triples = 0;
    
    // Для каждой вершины
    for (auto v : boost::make_iterator_range(boost::vertices(graph))) {
        size_t degree = boost::degree(v, graph);
        if (degree < 2) continue;
        
        // Количество связок для вершины
        triples += degree * (degree - 1) / 2;
        
        // Подсчет треугольников
        for (auto u : boost::make_iterator_range(boost::adjacent_vertices(v, graph))) {
            for (auto w : boost::make_iterator_range(boost::adjacent_vertices(v, graph))) {
                if (u < w && boost::edge(u, w, graph).second) {
                    triangles++;
                }
            }
        }
    }
    
    if (triples == 0) return 0.0;
    
    return static_cast<double>(3 * triangles) / triples;
}

double GeometricValidator::compute_degree_entropy(const IsogenyGraph& graph) {
    // Энтропия степеней = -sum(p_i * log2(p_i)), где p_i - вероятность степени i
    
    std::map<size_t, size_t> degree_count;
    size_t total_vertices = num_vertices(graph);
    
    // Подсчет вершин каждой степени
    for (auto v : boost::make_iterator_range(boost::vertices(graph))) {
        size_t degree = boost::degree(v, graph);
        degree_count[degree]++;
    }
    
    // Вычисление энтропии
    double entropy = 0.0;
    for (const auto& entry : degree_count) {
        double p = static_cast<double>(entry.second) / total_vertices;
        if (p > 0) {
            entropy -= p * std::log2(p);
        }
    }
    
    return entropy;
}

double GeometricValidator::compute_shortest_path_entropy(const IsogenyGraph& graph) {
    // Энтропия кратчайших путей = -sum(p_d * log2(p_d)), где p_d - вероятность длины пути d
    
    std::map<size_t, size_t> path_length_count;
    size_t total_paths = 0;
    
    // Вычисляем все кратчайшие пути
    std::vector<std::vector<double>> distances(num_vertices(graph), 
                                            std::vector<double>(num_vertices(graph), 0));
    
    boost::floyd_warshall_all_pairs_shortest_paths(graph, distances);
    
    // Подсчет длин путей
    for (size_t i = 0; i < num_vertices(graph); i++) {
        for (size_t j = i + 1; j < num_vertices(graph); j++) {
            if (distances[i][j] < std::numeric_limits<double>::infinity()) {
                size_t length = static_cast<size_t>(distances[i][j]);
                path_length_count[length]++;
                total_paths++;
            }
        }
    }
    
    // Вычисление энтропии
    double entropy = 0.0;
    for (const auto& entry : path_length_count) {
        double p = static_cast<double>(entry.second) / total_paths;
        if (p > 0) {
            entropy -= p * std::log2(p);
        }
    }
    
    return entropy;
}

bool GeometricValidator::validate_curve(const MontgomeryCurve& curve,
                                      const IsogenyGraph& subgraph,
                                      double& cyclomatic_score,
                                      double& spectral_gap_score,
                                      double& clustering_score,
                                      double& degree_entropy_score,
                                      double& distance_entropy_score) {
    // Вычисляем все геометрические метрики
    cyclomatic_score = compute_cyclomatic_number(subgraph);
    spectral_gap_score = compute_spectral_gap(subgraph);
    clustering_score = compute_clustering_coefficient(subgraph);
    degree_entropy_score = compute_degree_entropy(subgraph);
    distance_entropy_score = compute_shortest_path_entropy(subgraph);
    
    // Проверка цикломатического числа
    if (cyclomatic_score > SecurityConstants::MAX_CYCLOMATIC) {
        return false;
    }
    
    // Проверка спектрального зазора
    if (spectral_gap_score < SecurityConstants::MIN_SPECTRAL_GAP) {
        return false;
    }
    
    // Проверка коэффициента кластеризации
    if (clustering_score < SecurityConstants::MIN_CLUSTERING_COEFF) {
        return false;
    }
    
    // Проверка энтропии степеней
    if (degree_entropy_score < SecurityConstants::MIN_DEGREE_ENTROPY) {
        return false;
    }
    
    // Проверка энтропии кратчайших путей
    if (distance_entropy_score < SecurityConstants::MIN_DISTANCE_ENTROPY) {
        return false;
    }
    
    return true;
}

#endif // GEOMETRIC_VALIDATOR_H
