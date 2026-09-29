"""QUBO formulation for Zero Trust Policy Reoptimization (QAPRE).

Formulates the access control and deception routing problem as a Quadratic
Unconstrained Binary Optimization (QUBO) problem:

Decision variables:
  For each policy unit i in {0, ..., N-1} and action a in {Allow, Restrict (decoy), Deny}:
  x_{i, a} in {0, 1}
  where:
    - a = 0: ALLOW (grant normal access)
    - a = 1: RESTRICT (route to deception / honeypot decoy)
    - a = 2: DENY (terminate / block access)

Total binary variables: 3 * N

Cost Terms:
  1. Breach risk cost: Penalizes Allow and Restrict on high-risk units
  2. Legitimate friction cost: Penalizes Restrict and Deny on high-trust units
  3. Deception operational cost: Cost of maintaining decoy interactions

Constraint Terms (Penalty Method):
  1. One-hot penalty: Exactly one action chosen per unit: sum_a x_{i,a} = 1
  2. Decoy capacity penalty: Restricts concurrent honeypot allocations within capacity C
"""
from typing import Any, Dict, List, Tuple
import numpy as np


ACTION_ALLOW = 0
ACTION_RESTRICT = 1
ACTION_DENY = 2
ACTIONS = ["allow", "restrict", "deny"]


def get_var_index(unit_idx: int, action_idx: int) -> int:
    """Return the flattened variable index for (unit, action)."""
    return 3 * unit_idx + action_idx


def build_policy_qubo(
    units: List[Dict[str, Any]],
    decoy_capacity: int = 2,
    lambda_onehot: float = 12.0,
    lambda_capacity: float = 6.0,
    w_risk: float = 10.0,
    w_friction: float = 8.0,
    w_decoy: float = 2.0,
) -> Tuple[np.ndarray, float, List[str], Dict[Tuple[int, int], float]]:
    """Build the QUBO Q-matrix and constant offset for the given policy units.

    Parameters
    ----------
    units : List[Dict[str, Any]]
        List of policy units (assets/principals or policy rules), each having:
        - "id" or "name": identifier
        - "risk_score": float in [0, 100] (from EZTE)
        - "trust_score": float in [0, 100] (from Digital Twin/EZTE)
    decoy_capacity : int
        Maximum simultaneous high-interaction honeypots available in ACDE.
    lambda_onehot : float
        Penalty weight enforcing sum_a x_{i, a} = 1.
    lambda_capacity : float
        Penalty weight enforcing sum_i x_{i, restrict} <= decoy_capacity.
    w_risk : float
        Weight for breach risk cost.
    w_friction : float
        Weight for user friction cost.
    w_decoy : float
        Weight for baseline decoy deployment cost.

    Returns
    -------
    Q : np.ndarray
        Upper-triangular QUBO matrix of shape (3N, 3N).
    offset : float
        Constant scalar energy offset.
    var_names : List[str]
        Human-readable variable names for each index.
    qubo_dict : Dict[Tuple[int, int], float]
        Dictionary representation {(i, j): weight} for dimod/neal solvers.
    """
    n_units = len(units)
    n_vars = 3 * n_units
    Q = np.zeros((n_vars, n_vars), dtype=np.float64)
    offset = 0.0

    var_names: List[str] = []
    for i, u in enumerate(units):
        uname = u.get("id") or u.get("name") or f"unit_{i}"
        for act in ACTIONS:
            var_names.append(f"{uname}:{act}")

    # 1. Cost terms & One-hot constraint per unit
    for i, u in enumerate(units):
        # Normalized risk and trust in [0, 1]
        r_i = float(u.get("risk_score", 50.0)) / 100.0
        t_i = float(u.get("trust_score", 100.0 * (1.0 - r_i))) / 100.0

        idx_allow = get_var_index(i, ACTION_ALLOW)
        idx_restrict = get_var_index(i, ACTION_RESTRICT)
        idx_deny = get_var_index(i, ACTION_DENY)

        # Cost terms:
        # Allow: High risk cost, 0 friction
        c_allow = w_risk * r_i
        # Restrict: Partial risk mitigation (30%), moderate friction (40%), baseline decoy cost
        c_restrict = (0.30 * w_risk * r_i) + (0.40 * w_friction * t_i) + w_decoy
        # Deny: 0 risk cost, maximum friction on trusted users
        c_deny = 1.0 * w_friction * t_i

        # One-hot penalty: lambda_onehot * (x_allow + x_restrict + x_deny - 1)^2
        # = lambda_onehot * [ (x_allow + x_restrict + x_deny)^2 - 2(x_allow + x_restrict + x_deny) + 1 ]
        # Linear terms: (c_action - lambda_onehot) * x_action
        Q[idx_allow, idx_allow] += c_allow - lambda_onehot
        Q[idx_restrict, idx_restrict] += c_restrict - lambda_onehot
        Q[idx_deny, idx_deny] += c_deny - lambda_onehot

        # Cross terms between actions for the same unit: +2 * lambda_onehot * x_a * x_b
        Q[idx_allow, idx_restrict] += 2.0 * lambda_onehot
        Q[idx_allow, idx_deny] += 2.0 * lambda_onehot
        Q[idx_restrict, idx_deny] += 2.0 * lambda_onehot

        # Constant term from one-hot penalty
        offset += lambda_onehot

    # 2. Decoy Capacity constraint across all units
    # Restrict action variables: R = sum_i x_{i, restrict}
    # Penalty on exceeding decoy_capacity: pairwise contention penalty
    # For pairs of distinct units (i < j): +lambda_capacity * x_{i, restrict} * x_{j, restrict}
    # If decoy_capacity == 0: forbid any decoy by heavy linear penalty
    if decoy_capacity <= 0:
        for i in range(n_units):
            idx_r = get_var_index(i, ACTION_RESTRICT)
            Q[idx_r, idx_r] += lambda_capacity * 5.0
    else:
        # Pairwise contention scaling: when more than decoy_capacity units choose restrict,
        # pairwise interactions penalize the surplus configurations.
        contention_factor = lambda_capacity / max(1.0, float(decoy_capacity))
        for i in range(n_units):
            idx_ri = get_var_index(i, ACTION_RESTRICT)
            for j in range(i + 1, n_units):
                idx_rj = get_var_index(j, ACTION_RESTRICT)
                Q[idx_ri, idx_rj] += contention_factor

    # Build dictionary for dimod/neal
    qubo_dict: Dict[Tuple[int, int], float] = {}
    for i in range(n_vars):
        for j in range(i, n_vars):
            val = float(Q[i, j])
            if abs(val) > 1e-9:
                qubo_dict[(i, j)] = val

    return Q, offset, var_names, qubo_dict


def evaluate_solution_cost(
    solution: List[int],
    Q: np.ndarray,
    offset: float,
) -> float:
    """Calculate the exact scalar QUBO cost for a binary solution vector."""
    x = np.array(solution, dtype=np.float64)
    return float(x.T @ Q @ x + offset)


def decode_solution(
    bitstring: List[int],
    units: List[Dict[str, Any]],
) -> Tuple[bool, List[Dict[str, Any]], Dict[str, int]]:
    """Decode a binary bitstring into per-unit policy actions.

    Returns
    -------
    is_valid : bool
        True if all units satisfy the one-hot constraint.
    assignments : List[Dict[str, Any]]
        Per-unit assignment details: unit_id, action, confidence.
    action_counts : Dict[str, int]
        Count of units in each action tier (allow, restrict, deny).
    """
    n_units = len(units)
    assignments = []
    action_counts = {"allow": 0, "restrict": 0, "deny": 0}
    all_valid = True

    for i in range(n_units):
        sub_vec = bitstring[3 * i : 3 * i + 3]
        unit = units[i]
        uname = unit.get("id") or unit.get("name") or f"unit_{i}"

        active_indices = [idx for idx, val in enumerate(sub_vec) if val == 1]
        if len(active_indices) == 1:
            chosen_action = ACTIONS[active_indices[0]]
            valid_unit = True
        else:
            # Violated one-hot constraint
            all_valid = False
            valid_unit = False
            # Fallback for display: pick based on lowest cost for this unit
            r_i = float(unit.get("risk_score", 50.0)) / 100.0
            if r_i > 0.70:
                chosen_action = "deny"
            elif r_i > 0.40:
                chosen_action = "restrict"
            else:
                chosen_action = "allow"

        action_counts[chosen_action] += 1
        assignments.append({
            "unit": uname,
            "action": chosen_action,
            "valid": valid_unit,
            "bitstring_segment": sub_vec,
            "risk_score": unit.get("risk_score", 50.0),
            "trust_score": unit.get("trust_score", 50.0),
        })

    return all_valid, assignments, action_counts
