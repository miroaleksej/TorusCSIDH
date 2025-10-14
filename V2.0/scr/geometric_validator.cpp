#include "geometric_validator.h"
#include <iostream>
#include <unordered_map>
#include <queue>
#include <stack>
#include <limits>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <boost/graph/connected_components.hpp>
#include <boost/graph/biconnected_components.hpp>
#include <boost/graph/dijkstra_shortest_paths.hpp>
#include <boost/graph/floyd_warshall_shortest.hpp>

namespace toruscsidh {

GeometricValidator::GeometricValidator(int security_bits) : security_bits_(security_bits) {
    // Инициализация параметров безопасности в зависимости от уровня
    if (security_bits == 128) {
        security_params_ = {
            MIN_CYCLOMATIC_NUMBER_128,
            MIN_SPECTRAL_GAP_128,
            MAX_PATH_LENGTH_RATIO_128
        };
    } else if (security_bits == 192) {
        security_params_ = {
            MIN_CYCLOMATIC_NUMBER_192,
            MIN_SPECTRAL_GAP_192,
            MAX_PATH_LENGTH_RATIO_192
        };
    } else { // 256 бит
        security_params_ = {
            MIN_CYCLOMATIC_NUMBER_256,
            MIN_SPECTRAL_GAP_256,
            MAX_PATH_LENGTH_RATIO_256
        };
    }
}

bool GeometricValidator::validate(const MontgomeryCurve& curve, 
                                 const std::vector<GmpRaii>& primes,
                                 int radius) const {
    // Проверка всех семи критериев безопасности
    return check_cyclomatic_number(curve, primes, radius) &&
           check_spectral_gap(curve, primes, radius) &&
           check_local_connectivity(curve, primes, radius) &&
           check_long_paths(curve, primes, radius) &&
           check_degenerate_topology(curve, primes, radius) &&
           check_graph_symmetry(curve, primes, radius) &&
           check_metric_consistency(curve, primes, radius);
}

bool GeometricValidator::check_cyclomatic_number(const MontgomeryCurve& curve,
                                               const std::vector<GmpRaii>& primes,
                                               int radius) const {
    Graph graph = build_local_isogeny_graph(curve, primes, radius);
    double cyclomatic_number = calculate_cyclomatic_number(graph);
    
    // Цикломатическое число должно быть достаточно большим для легитимных графов изогений
    double min_cyclomatic = security_params_[0];
    return cyclomatic_number >= min_cyclomatic;
}

bool GeometricValidator::check_spectral_gap(const MontgomeryCurve& curve,
                                          const std::vector<GmpRaii>& primes,
                                          int radius) const {
    Graph graph = build_local_isogeny_graph(curve, primes, radius);
    double spectral_gap = calculate_spectral_gap(graph);
    
    // Спектральный зазор должен быть в определенном диапазоне для легитимных графов
    double min_spectral_gap = security_params_[1];
    return spectral_gap >= min_spectral_gap;
}

bool GeometricValidator::check_local_connectivity(const MontgomeryCurve& curve,
                                                const std::vector<GmpRaii>& primes,
                                                int radius) const {
    Graph graph = build_local_isogeny_graph(curve, primes, radius);
    
    // Проверка 2-связности (бикомпонентности)
    std::vector<int> component(num_vertices(graph));
    int num_components = boost::biconnected_components(graph, &component[0]);
    
    // Для легитимного графа изогений должен быть как минимум один бикомпонент
    return num_components >= 1;
}

bool GeometricValidator::check_long_paths(const MontgomeryCurve& curve,
                                        const std::vector<GmpRaii>& primes,
                                        int radius) const {
    Graph graph = build_local_isogeny_graph(curve, primes, radius);
    int diameter = calculate_diameter(graph);
    int num_vertices = boost::num_vertices(graph);
    
    // Проверка на аномально длинные пути относительно количества вершин
    double path_length_ratio = static_cast<double>(diameter) / num_vertices;
    double max_path_ratio = security_params_[2];
    
    return path_length_ratio <= max_path_ratio;
}

bool GeometricValidator::check_degenerate_topology(const MontgomeryCurve& curve,
                                                 const std::vector<GmpRaii>& primes,
                                                 int radius) const {
    Graph graph = build_local_isogeny_graph(curve, primes, radius);
    
    // Легитимные графы изогений не должны быть деревьями (должны содержать циклы)
    bool is_tree = this->is_tree(graph);
    
    // Также проверяем, что граф не является просто циклом
    bool is_single_cycle = (boost::num_edges(graph) == boost::num_vertices(graph));
    
    return !is_tree && !is_single_cycle;
}

bool GeometricValidator::check_graph_symmetry(const MontgomeryCurve& curve,
                                            const std::vector<GmpRaii>& primes,
                                            int radius) const {
    Graph graph = build_local_isogeny_graph(curve, primes, radius);
    auto degree_dist = calculate_degree_distribution(graph);
    
    // Вычисляем энтропию распределения степеней
    double entropy = 0.0;
    int total = boost::num_vertices(graph);
    
    std::map<int, int> degree_count;
    for (int degree : degree_dist) {
        degree_count[degree]++;
    }
    
    for (const auto& entry : degree_count) {
        double p = static_cast<double>(entry.second) / total;
        if (p > 0) {
            entropy -= p * std::log2(p);
        }
    }
    
    // Для симметричных графов изогений энтропия должна быть достаточно высокой
    return entropy >= 1.5; // Эмпирический порог для симметрии
}

bool GeometricValidator::check_metric_consistency(const MontgomeryCurve& curve,
                                               const std::vector<GmpRaii>& primes,
                                               int radius) const {
    Graph graph = build_local_isogeny_graph(curve, primes, radius);
    
    // Проверка, что все кратчайшие пути имеют длину, соответствующую степени изогении
    // Для этого вычисляем матрицу кратчайших расстояний
    std::vector<std::vector<double>> distances;
    boost::floyd_warshall_all_pairs_shortest_paths(graph, distances);
    
    // Проверяем, что расстояния соответствуют ожидаемой структуре
    int num_vertices = boost::num_vertices(graph);
    for (int i = 0; i < num_vertices; ++i) {
        for (int j = i + 1; j < num_vertices; ++j) {
            double expected_distance = std::abs(i - j); // Упрощенная модель
            if (std::abs(distances[i][j] - expected_distance) > 1.5) {
                return false;
            }
        }
    }
    
    return true;
}

bool GeometricValidator::check_minimal_degree(const MontgomeryCurve& curve,
                                            const std::vector<GmpRaii>& primes,
                                            int radius) const {
    Graph graph = build_local_isogeny_graph(curve, primes, radius);
    int min_required_degree = primes.size() * MIN_DEGREE_MULTIPLIER;
    
    // Проверяем, что все вершины имеют достаточную степень
    for (auto v : boost::make_iterator_range(boost::vertices(graph))) {
        if (boost::degree(v, graph) < min_required_degree) {
            return false;
        }
    }
    
    return true;
}

const std::vector<double>& GeometricValidator::get_security_parameters() const {
    return security_params_;
}

GeometricValidator::Graph GeometricValidator::build_local_isogeny_graph(
    const MontgomeryCurve& center_curve,
    const std::vector<GmpRaii>& primes,
    int radius) const {
    
    Graph graph;
    std::unordered_map<GmpRaii, size_t> curve_to_index;
    std::queue<std::pair<MontgomeryCurve, int>> queue;
    std::unordered_set<GmpRaii> visited;
    
    // Добавляем центральную кривую
    size_t center_index = boost::add_vertex(graph);
    GmpRaii center_j = center_curve.compute_j_invariant();
    curve_to_index[center_j] = center_index;
    visited.insert(center_j);
    queue.push({center_curve, 0});
    
    // Обход в ширину для построения локального подграфа
    while (!queue.empty()) {
        auto [current_curve, current_radius] = queue.front();
        queue.pop();
        
        GmpRaii current_j = current_curve.compute_j_invariant();
        size_t current_index = curve_to_index[current_j];
        
        // Если достигли максимального радиуса, не идем дальше
        if (current_radius >= radius) {
            continue;
        }
        
        // Для каждого простого числа строим изогению
        for (const auto& prime : primes) {
            unsigned long degree = mpz_get_ui(prime.get_mpz_t());
            
            // Генерируем точку ядра для изогении
            EllipticCurvePoint kernel_point = current_curve.find_point_of_order(degree);
            
            // Вычисляем новую кривую через изогению
            MontgomeryCurve new_curve = current_curve.compute_isogeny(kernel_point, degree);
            GmpRaii new_j = new_curve.compute_j_invariant();
            
            // Проверяем, не посещали ли мы эту кривую ранее
            if (visited.find(new_j) == visited.end()) {
                // Добавляем новую вершину
                size_t new_index = boost::add_vertex(graph);
                curve_to_index[new_j] = new_index;
                visited.insert(new_j);
                
                // Добавляем ребро между текущей и новой кривой
                boost::add_edge(current_index, new_index, graph);
                
                // Добавляем новую кривую в очередь для дальнейшего обхода
                queue.push({new_curve, current_radius + 1});
            } else {
                // Если кривая уже посещена, добавляем ребро к существующей вершине
                size_t existing_index = curve_to_index[new_j];
                boost::add_edge(current_index, existing_index, graph);
            }
        }
    }
    
    return graph;
}

double GeometricValidator::calculate_cyclomatic_number(const Graph& graph) const {
    int num_edges = boost::num_edges(graph);
    int num_vertices = boost::num_vertices(graph);
    
    // Вычисляем количество компонент связности
    std::vector<int> component(num_vertices);
    int num_components = boost::connected_components(graph, &component[0]);
    
    // Цикломатическое число = E - V + C
    return static_cast<double>(num_edges) - num_vertices + num_components;
}

double GeometricValidator::calculate_spectral_gap(const Graph& graph) const {
    Eigen::MatrixXd laplacian = get_laplacian_matrix(graph);
    
    // Вычисляем собственные значения матрицы Лапласа
    Eigen::SelfAdjointEigenSolver<Eigen::MatrixXd> solver(laplacian);
    Eigen::VectorXd eigenvalues = solver.eigenvalues();
    
    // Сортируем собственные значения в порядке возрастания
    std::vector<double> sorted_eigenvalues;
    for (int i = 0; i < eigenvalues.size(); ++i) {
        sorted_eigenvalues.push_back(eigenvalues(i));
    }
    std::sort(sorted_eigenvalues.begin(), sorted_eigenvalues.end());
    
    // Спектральный зазор = λ₂ - λ₁
    // λ₀ = 0, λ₁ - первое ненулевое собственное значение
    for (size_t i = 1; i < sorted_eigenvalues.size(); ++i) {
        if (sorted_eigenvalues[i] > 1e-10) {
            return sorted_eigenvalues[i] - sorted_eigenvalues[i-1];
        }
    }
    
    // Если все собственные значения нулевые (вырожденный случай)
    return 0.0;
}

Eigen::MatrixXd GeometricValidator::get_laplacian_matrix(const Graph& graph) const {
    int n = boost::num_vertices(graph);
    Eigen::MatrixXd laplacian = Eigen::MatrixXd::Zero(n, n);
    
    // Заполняем матрицу смежности
    for (auto edge : boost::make_iterator_range(boost::edges(graph))) {
        auto u = boost::source(edge, graph);
        auto v = boost::target(edge, graph);
        
        laplacian(u, v) = -1.0;
        laplacian(v, u) = -1.0;
        laplacian(u, u) += 1.0;
        laplacian(v, v) += 1.0;
    }
    
    return laplacian;
}

std::vector<int> GeometricValidator::calculate_degree_distribution(const Graph& graph) const {
    std::vector<int> degrees;
    for (auto v : boost::make_iterator_range(boost::vertices(graph))) {
        degrees.push_back(boost::degree(v, graph));
    }
    return degrees;
}

int GeometricValidator::calculate_diameter(const Graph& graph) const {
    int n = boost::num_vertices(graph);
    if (n <= 1) return 0;
    
    // Вычисляем матрицу кратчайших расстояний
    std::vector<std::vector<double>> distances;
    boost::floyd_warshall_all_pairs_shortest_paths(graph, distances);
    
    // Находим максимальное расстояние между любыми двумя вершинами
    int diameter = 0;
    for (int i = 0; i < n; ++i) {
        for (int j = i + 1; j < n; ++j) {
            if (distances[i][j] < std::numeric_limits<double>::infinity()) {
                diameter = std::max(diameter, static_cast<int>(distances[i][j]));
            }
        }
    }
    
    return diameter;
}

bool GeometricValidator::is_tree(const Graph& graph) const {
    int num_edges = boost::num_edges(graph);
    int num_vertices = boost::num_vertices(graph);
    
    // Дерево имеет ровно V-1 ребер и является связным
    return (num_edges == num_vertices - 1) && 
           (boost::connected_components(graph, std::vector<int>(num_vertices)) == 1);
}

} // namespace toruscsidh
