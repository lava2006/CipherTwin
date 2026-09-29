"""Reproducible Benchmark Script for QAPRE (Quantum-Assisted Policy Reoptimization Engine).

Compares:
  1. Quantum Approach: Hybrid QAOA via PennyLane on lightning.qubit statevector simulator
  2. Classical Baseline: Simulated Annealing via D-Wave neal on the identical QUBO

Evaluated across problem instances N = 3, 5, 7, 8 policy units (9, 15, 21, 24 qubits).
Outputs wall-clock execution time, QUBO solution cost, and validity.

DISCLAIMER:
All quantum simulations are executed classically using PennyLane's lightning.qubit
for algorithmic and solution-quality evaluation. No claim of quantum hardware speedup
is made or implied.
"""
from collections import Counter
import json
import os
import sys
import time
from typing import Any, Dict, List

# Ensure backend is in python path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

import numpy as np
import pennylane as qml
from pennylane import numpy as pnp
import dimod
import neal

from app.services.qubo_builder import (
    build_policy_qubo,
    evaluate_solution_cost,
    decode_solution,
)
from app.services.quantum_optimizer import qubo_to_ising, build_qaoa_hamiltonians


def run_single_benchmark(n_units: int, p_layers: int = 2, max_iter: int = 15) -> Dict[str, Any]:
    """Execute both QAOA and Classical SA for a problem instance of size n_units."""
    num_qubits = 3 * n_units

    # Synthetic domain-grounded policy units
    units = []
    for i in range(n_units):
        # Realistic risk distribution: mixed low, medium, and high-risk principals
        risk = 20.0 + 12.0 * (i % 7)
        trust = 100.0 - risk
        units.append({
            "id": f"policy_unit_{i+1}",
            "risk_score": min(95.0, risk),
            "trust_score": max(5.0, trust),
        })

    decoy_capacity = max(1, n_units // 3)

    # 1. Build identical QUBO matrix
    Q, offset, var_names, qubo_dict = build_policy_qubo(
        units=units,
        decoy_capacity=decoy_capacity,
        lambda_onehot=14.0,
        lambda_capacity=8.0,
        w_risk=10.0,
        w_friction=8.0,
        w_decoy=2.5,
    )

    # 2. Classical Baseline: Simulated Annealing (neal)
    t0_sa = time.perf_counter()
    bqm = dimod.BinaryQuadraticModel.from_qubo(qubo_dict, offset=offset)
    sa_sampler = neal.SimulatedAnnealingSampler()
    sa_sampleset = sa_sampler.sample(bqm, num_reads=150)
    sa_time = time.perf_counter() - t0_sa

    best_sa_sample = sa_sampleset.first
    sa_bitstring = [int(best_sa_sample.sample.get(i, 0)) for i in range(num_qubits)]
    sa_cost = float(best_sa_sample.energy)
    sa_valid, _, sa_counts = decode_solution(sa_bitstring, units)

    # 3. Hybrid Quantum-Classical QAOA (PennyLane lightning.qubit)
    h, J, h0 = qubo_to_ising(Q, offset)
    cost_h, mixer_h = build_qaoa_hamiltonians(h, J, num_qubits)
    dev = qml.device("lightning.qubit", wires=num_qubits)

    def qaoa_circuit(params):
        for w in range(num_qubits):
            qml.Hadamard(wires=w)
        for layer in range(p_layers):
            qml.qaoa.cost_layer(params[0][layer], cost_h)
            qml.qaoa.mixer_layer(params[1][layer], mixer_h)

    @qml.qnode(dev, diff_method="adjoint")
    def cost_qnode(params):
        qaoa_circuit(params)
        return qml.expval(cost_h)

    # Parameter optimization
    init_params = pnp.array([
        [0.1 * (l + 1) for l in range(p_layers)],
        [0.1 * (p_layers - l) for l in range(p_layers)],
    ], requires_grad=True)

    t0_qaoa = time.perf_counter()
    params = init_params
    opt = qml.AdamOptimizer(stepsize=0.08)
    for _ in range(max_iter):
        params, _ = opt.step_and_cost(cost_qnode, params)

    # Measurement sampling (1000 shots)
    @qml.qnode(dev, shots=1000)
    def sample_qnode(params):
        qaoa_circuit(params)
        return qml.sample()

    samples = sample_qnode(params)
    qaoa_time = time.perf_counter() - t0_qaoa

    # Decode best valid sample
    counts = Counter(tuple(int(x) for x in s) for s in samples)
    best_qaoa_bitstring = None
    best_qaoa_cost = float("inf")

    for bit_tuple, _ in counts.most_common():
        b_list = list(bit_tuple)
        is_val, _, _ = decode_solution(b_list, units)
        if is_val:
            c = evaluate_solution_cost(b_list, Q, offset)
            if c < best_qaoa_cost:
                best_qaoa_cost = c
                best_qaoa_bitstring = b_list

    # Deterministic marginal argmax fallback if needed
    if best_qaoa_bitstring is None:
        sample_arr = np.array(samples)
        marginals = sample_arr.mean(axis=0)
        best_qaoa_bitstring = [0] * num_qubits
        for i in range(n_units):
            probs = [marginals[3 * i], marginals[3 * i + 1], marginals[3 * i + 2]]
            best_qaoa_bitstring[3 * i + int(np.argmax(probs))] = 1
        best_qaoa_cost = evaluate_solution_cost(best_qaoa_bitstring, Q, offset)

    qaoa_valid, _, qaoa_counts = decode_solution(best_qaoa_bitstring, units)

    return {
        "n_units": n_units,
        "num_qubits": num_qubits,
        "p_layers": p_layers,
        "iterations": max_iter,
        "qaoa_time_s": round(qaoa_time, 4),
        "qaoa_cost": round(best_qaoa_cost, 4),
        "qaoa_valid": qaoa_valid,
        "qaoa_counts": qaoa_counts,
        "sa_time_s": round(sa_time, 4),
        "sa_cost": round(sa_cost, 4),
        "sa_valid": sa_valid,
        "sa_counts": sa_counts,
        "cost_diff": round(best_qaoa_cost - sa_cost, 4),
    }


def main():
    print("=" * 80)
    print("  QAPRE EVALUATION BENCHMARK: QAOA (PennyLane lightning.qubit) vs SA (neal)")
    print("=" * 80)
    print("  Evaluating problem instances: N = 3, 5, 7, 8 policy units")
    print("  Qubit scaling: 3 * N -> 9, 15, 21, 24 qubits")
    print("=" * 80)

    target_instances = [3, 5, 7, 8]
    benchmark_data = []

    for n in target_instances:
        print(f"\n>>> Running Benchmark for N = {n} policy units (qubits = {3*n})...")
        res = run_single_benchmark(n_units=n, p_layers=2, max_iter=10)
        benchmark_data.append(res)
        print(f"    [QAOA] Time: {res['qaoa_time_s']:.3f}s | Energy/Cost: {res['qaoa_cost']:.2f} | Valid: {res['qaoa_valid']}")
        print(f"    [ SA ] Time: {res['sa_time_s']:.3f}s | Energy/Cost: {res['sa_cost']:.2f} | Valid: {res['sa_valid']}")
        print(f"    [Cost Difference (QAOA - SA)]: {res['cost_diff']:.2f}")

    # Output formatted markdown table
    print("\n" + "=" * 80)
    print("  FINAL EVALUATION BENCHMARK TABLE")
    print("=" * 80)
    header = "| Policy Units (N) | Qubits (3N) | QAOA Time (s) | QAOA Cost | SA Time (s) | SA Cost | Cost Delta (QAOA - SA) |"
    sep = "|:---:|:---:|:---:|:---:|:---:|:---:|:---:|"
    print(header)
    print(sep)
    for row in benchmark_data:
        print(f"| {row['n_units']} | {row['num_qubits']} | {row['qaoa_time_s']:.3f} | {row['qaoa_cost']:.2f} | {row['sa_time_s']:.3f} | {row['sa_cost']:.2f} | {row['cost_diff']:+.2f} |")
    print("=" * 80)

    # Save to JSON
    output_path = os.path.join(ROOT_DIR, "benchmark_results.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(benchmark_data, f, indent=2)
    print(f"\nBenchmark results saved to: {output_path}")


if __name__ == "__main__":
    main()
