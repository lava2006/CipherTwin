"""Bounded QAPRE benchmark: PennyLane QAOA vs deterministic SciPy baseline.

The benchmark only uses policy batches that fit the project's documented
qubit ceiling. If PennyLane is unavailable, the classical result is still
reported and QAOA is marked unavailable instead of being fabricated.
"""
import json
import os
import sys
import time
from typing import Any, Dict

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.services.qubo_builder import build_policy_qubo
from app.services.quantum_optimizer import QuantumOptimizer


def run_single_benchmark(n_units: int, p_layers: int = 2, max_iter: int = 10) -> Dict[str, Any]:
    if n_units < 1 or n_units > 5:
        raise ValueError("Benchmark supports 1-5 policy units to respect the configured QAOA ceiling")

    units = []
    for i in range(n_units):
        risk = min(95.0, 20.0 + 12.0 * (i % 7))
        units.append({"id": f"policy_unit_{i + 1}", "risk_score": risk, "trust_score": 100.0 - risk})

    capacity = max(1, n_units // 3)
    Q, offset, _names, qubo_dict = build_policy_qubo(units, decoy_capacity=capacity)
    optimizer = QuantumOptimizer(None)

    start = time.perf_counter()
    classical_bits, classical_cost, classical_elapsed = optimizer._solve_classical_baseline(
        qubo_dict, offset, units, num_variables=Q.shape[0], decoy_capacity=capacity
    )
    classical_valid = len(classical_bits) == Q.shape[0]

    qaoa_cost = None
    qaoa_elapsed = None
    qaoa_valid = False
    qaoa_error = None
    try:
        _bits, qaoa_cost_value, _steps, qaoa_elapsed_value, _history = optimizer._solve_qaoa(
            Q, offset, units, p_layers=p_layers, iterations=max_iter, decoy_capacity=capacity
        )
        qaoa_cost = round(float(qaoa_cost_value), 4)
        qaoa_elapsed = round(float(qaoa_elapsed_value), 4)
        qaoa_valid = True
    except Exception as exc:
        qaoa_error = f"{type(exc).__name__}: {exc}"

    return {
        "n_units": n_units,
        "qubo_variables_qubits": int(Q.shape[0]),
        "p_layers": p_layers,
        "iterations_requested": max_iter,
        "classical_method": "SciPy deterministic discrete-grid search",
        "classical_time_s": round(classical_elapsed, 4),
        "classical_cost": round(float(classical_cost), 4),
        "classical_feasible": classical_valid,
        "qaoa_time_s": qaoa_elapsed,
        "qaoa_cost": qaoa_cost,
        "qaoa_executed": qaoa_valid,
        "qaoa_unavailable_reason": qaoa_error,
        "cost_delta_qaoa_minus_classical": round(qaoa_cost - classical_cost, 4) if qaoa_cost is not None else None,
        "total_elapsed_s": round(time.perf_counter() - start, 4),
    }


def main():
    results = []
    for n_units in (3, 5):
        result = run_single_benchmark(n_units=n_units)
        results.append(result)
        print(json.dumps(result, indent=2))
    output = os.path.join(ROOT_DIR, "benchmark_results.json")
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)
    print(f"Results saved to {output}")


if __name__ == "__main__":
    main()
