"""
=============================================================================
Bayesian Attack Predictor — MITRE ATT&CK Chain Prediction
=============================================================================
Module: ml_engine/bayesian_attack_predictor.py
Agent:  Agent 3 — "The Brain"

Purpose:
    Uses a Bayesian Network to model the probabilistic relationships
    between MITRE ATT&CK tactics (kill chain stages) and predict the
    attacker's most likely next move given currently observed techniques.

Why Bayesian Networks?
    1. Encode expert knowledge via conditional probability distributions
    2. Handle uncertainty — compute P(next_attack | observed_evidence)
    3. Transparent reasoning — each prediction has an explainable chain
    4. Small data requirement — CPDs can be set from domain expertise
    5. Ideal for academic demonstration of probabilistic threat modeling

Model Structure:
    DAG nodes represent ATT&CK kill chain stages. Directed edges encode
    "attack progression" (e.g., Initial Access → Execution → Persistence).
    CPDs encode transition probabilities based on real-world attack patterns.

Dependencies: pgmpy, numpy

Usage:
    from ml_engine.bayesian_attack_predictor import AttackPredictor
    predictor = AttackPredictor()
    predictions = predictor.predict_next_stage(
        observed={"execution": 1, "discovery": 1})
=============================================================================
"""

import logging
from typing import Dict, List, Optional

import numpy as np

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("bayesian_predictor")

try:
    try:
        from pgmpy.models import DiscreteBayesianNetwork as BayesianNetwork
    except ImportError:
        from pgmpy.models import BayesianNetwork
    from pgmpy.factors.discrete import TabularCPD
    from pgmpy.inference import VariableElimination
    PGMPY_AVAILABLE = True
except ImportError:
    PGMPY_AVAILABLE = False
    logger.warning("pgmpy not installed. Bayesian predictor will use fallback mode.")


class AttackPredictor:
    """
    Bayesian Network-based attack chain predictor.

    Models the MITRE ATT&CK Container kill chain as a directed acyclic
    graph, where each node represents a tactic stage and edges represent
    likely attack progression paths.
    """

    # Kill chain stages (Bayesian network nodes)
    STAGES = [
        "initial_access",     # 0: Entry point (exploit, creds, etc.)
        "execution",          # 1: Code execution in container
        "persistence",        # 2: Maintain foothold
        "privilege_escalation",  # 3: Gain higher privileges
        "defense_evasion",    # 4: Avoid detection
        "credential_access",  # 5: Harvest credentials
        "discovery",          # 6: Reconnaissance
        "lateral_movement",   # 7: Spread to other containers
        "impact",             # 8: Final objective (DDoS, crypto, exfil)
    ]

    def __init__(self):
        if PGMPY_AVAILABLE:
            self.model = self._build_bayesian_network()
            self.inference = VariableElimination(self.model)
        else:
            self.model = None
            self.inference = None
        logger.info("AttackPredictor initialized")

    def _build_bayesian_network(self) -> 'BayesianNetwork':
        """
        Build the Bayesian Network DAG and define CPDs.

        DAG Structure (attack progression):
            initial_access → execution → persistence
                                      → privilege_escalation
            execution → discovery → lateral_movement → impact
            privilege_escalation → defense_evasion
            credential_access → lateral_movement
            discovery → credential_access

        CPD Design:
            Conditional probabilities are based on published attack chain
            analysis from MITRE and security vendor threat reports.
            Each CPD encodes P(child_stage = active | parent_stage).
        """
        # Define directed edges (attack progression paths)
        edges = [
            ("initial_access", "execution"),
            ("execution", "persistence"),
            ("execution", "privilege_escalation"),
            ("execution", "discovery"),
            ("discovery", "credential_access"),
            ("discovery", "lateral_movement"),
            ("credential_access", "lateral_movement"),
            ("privilege_escalation", "defense_evasion"),
            ("lateral_movement", "impact"),
        ]

        model = BayesianNetwork(edges)

        # Each node is binary: 0 = not observed, 1 = observed
        # CPDs encode transition probabilities

        # P(initial_access) — prior probability of initial compromise
        cpd_ia = TabularCPD("initial_access", 2, [[0.7], [0.3]])

        # P(execution | initial_access)
        cpd_exec = TabularCPD("execution", 2,
            [[0.9, 0.15],   # P(exec=0 | ia=0), P(exec=0 | ia=1)
             [0.1, 0.85]],  # P(exec=1 | ia=0), P(exec=1 | ia=1)
            evidence=["initial_access"], evidence_card=[2])

        # P(persistence | execution)
        cpd_pers = TabularCPD("persistence", 2,
            [[0.95, 0.35],
             [0.05, 0.65]],
            evidence=["execution"], evidence_card=[2])

        # P(privilege_escalation | execution)
        cpd_priv = TabularCPD("privilege_escalation", 2,
            [[0.92, 0.40],
             [0.08, 0.60]],
            evidence=["execution"], evidence_card=[2])

        # P(discovery | execution)
        cpd_disc = TabularCPD("discovery", 2,
            [[0.85, 0.20],
             [0.15, 0.80]],
            evidence=["execution"], evidence_card=[2])

        # P(defense_evasion | privilege_escalation)
        cpd_def = TabularCPD("defense_evasion", 2,
            [[0.90, 0.30],
             [0.10, 0.70]],
            evidence=["privilege_escalation"], evidence_card=[2])

        # P(credential_access | discovery)
        cpd_cred = TabularCPD("credential_access", 2,
            [[0.88, 0.35],
             [0.12, 0.65]],
            evidence=["discovery"], evidence_card=[2])

        # P(lateral_movement | discovery, credential_access)
        cpd_lat = TabularCPD("lateral_movement", 2,
            [[0.95, 0.55, 0.50, 0.15],
             [0.05, 0.45, 0.50, 0.85]],
            evidence=["discovery", "credential_access"],
            evidence_card=[2, 2])

        # P(impact | lateral_movement)
        cpd_imp = TabularCPD("impact", 2,
            [[0.90, 0.25],
             [0.10, 0.75]],
            evidence=["lateral_movement"], evidence_card=[2])

        # Add all CPDs to model
        for cpd in [cpd_ia, cpd_exec, cpd_pers, cpd_priv, cpd_disc,
                    cpd_def, cpd_cred, cpd_lat, cpd_imp]:
            model.add_cpds(cpd)

        assert model.check_model(), "Bayesian model validation failed!"
        logger.info("Bayesian Network model built and validated")
        return model

    def predict_next_stage(
        self, observed: Dict[str, int]
    ) -> List[Dict[str, float]]:
        """
        Predict the probability of each unobserved attack stage.

        Given evidence of which stages have been observed (value=1),
        computes P(stage=1 | evidence) for all unobserved stages.

        Args:
            observed: Dict mapping stage names to binary values
                      e.g., {"execution": 1, "discovery": 1}

        Returns:
            List of dicts with stage name and probability, sorted by
            descending probability (most likely next stages first)
        """
        if not PGMPY_AVAILABLE or self.inference is None:
            return self._fallback_prediction(observed)

        predictions = []
        unobserved = [s for s in self.STAGES if s not in observed]

        for stage in unobserved:
            try:
                result = self.inference.query([stage], evidence=observed)
                prob = result.values[1]  # P(stage=1)
                predictions.append({"stage": stage, "probability": float(prob)})
            except Exception as e:
                logger.warning(f"Inference failed for {stage}: {e}")

        predictions.sort(key=lambda x: x["probability"], reverse=True)
        return predictions

    def _fallback_prediction(self, observed: Dict[str, int]) -> List[Dict]:
        """
        Fallback prediction when pgmpy is not available.
        Uses a simple heuristic based on kill chain ordering.
        """
        max_stage_idx = -1
        for stage, val in observed.items():
            if val == 1 and stage in self.STAGES:
                idx = self.STAGES.index(stage)
                max_stage_idx = max(max_stage_idx, idx)

        predictions = []
        for i, stage in enumerate(self.STAGES):
            if stage not in observed:
                # Higher probability for stages just after observed ones
                if i == max_stage_idx + 1:
                    prob = 0.8
                elif i > max_stage_idx:
                    prob = max(0.1, 0.8 - 0.15 * (i - max_stage_idx - 1))
                else:
                    prob = 0.1
                predictions.append({"stage": stage, "probability": prob})

        predictions.sort(key=lambda x: x["probability"], reverse=True)
        return predictions

    def get_threat_assessment(
        self, observed: Dict[str, int]
    ) -> Dict:
        """
        Generate a comprehensive threat assessment report.

        Combines prediction with contextual information for the
        response engine (Agent 4) to make automated decisions.
        """
        predictions = self.predict_next_stage(observed)
        observed_stages = [s for s, v in observed.items() if v == 1]
        max_stage = max(
            (self.STAGES.index(s) for s in observed_stages),
            default=-1
        )

        # Risk level based on attack progression depth
        if max_stage >= 7:  # lateral_movement or impact
            risk_level = "CRITICAL"
        elif max_stage >= 5:  # credential_access or discovery
            risk_level = "HIGH"
        elif max_stage >= 2:  # persistence or privilege_escalation
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "observed_stages": observed_stages,
            "attack_progression": f"{max_stage + 1}/{len(self.STAGES)} stages",
            "risk_level": risk_level,
            "predictions": predictions[:3],  # Top 3 most likely next stages
            "recommended_action": self._recommend_action(risk_level),
        }

    def _recommend_action(self, risk_level: str) -> str:
        """Map risk level to recommended automated response."""
        actions = {
            "CRITICAL": "ISOLATE pod immediately and migrate workloads",
            "HIGH": "Apply restrictive NetworkPolicy and alert SOC",
            "MEDIUM": "Increase monitoring granularity and log collection",
            "LOW": "Continue normal monitoring",
        }
        return actions.get(risk_level, "Continue monitoring")


if __name__ == "__main__":
    predictor = AttackPredictor()

    # Example: attacker has gained execution and performed discovery
    observed = {"execution": 1, "discovery": 1}
    assessment = predictor.get_threat_assessment(observed)

    print("\n=== Threat Assessment ===")
    print(f"Observed Stages:  {assessment['observed_stages']}")
    print(f"Attack Progress:  {assessment['attack_progression']}")
    print(f"Risk Level:       {assessment['risk_level']}")
    print(f"Action:           {assessment['recommended_action']}")
    print("\nPredicted Next Stages:")
    for pred in assessment["predictions"]:
        print(f"  {pred['stage']:25s}  P={pred['probability']:.4f}")
