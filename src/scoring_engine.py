from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


# ============================================================
# JSONL Helpers
# ============================================================

def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_num} of {path}: {exc}") from exc


def write_jsonl(path: Path, records: Iterable[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, separators=(",", ":")) + "\n")


# ============================================================
# Small Math Helpers
# ============================================================

def clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def fraction_from_count(count: int, cap: int) -> float:
    if cap <= 0:
        return 0.0
    return clamp(count / cap)


# ============================================================
# Scoring Output
# ============================================================

@dataclass
class ScoredClusterWindow:
    cluster_id: int
    window_start: str
    window_end: str

    exposure_score: float
    confidence_score: float
    exposure_tier: str

    attack_surface_score: float
    identifiability_score: float
    trackability_score: float
    service_sensitivity_score: float

    high_exposure_indicator: bool
    high_exposure_reasons: List[str]

    score_drivers: List[Dict[str, Any]]
    score_components: Dict[str, float]


# ============================================================
# Scoring Engine
# ============================================================

class BLEExposureScoringEngine:
    """
    Explainable, rule-based exposure scoring model for BLE cluster-window features.

    Score design:
    - attack surface      : connectable / discoverable / scannable posture
    - identifiability     : names, stable signatures, public address behavior,
                            and best-effort device identification confidence
    - trackability        : persistence + stable signatures across time / address behavior
    - service sensitivity : advertised sensitive service classes

    Output:
    - exposure_score (0-100)
    - confidence_score (0-100)
    - score drivers
    - simple high-exposure indicator baseline
    """

    def score_record(self, features: Dict[str, Any]) -> Dict[str, Any]:
        cluster_id = int(features["cluster_id"])
        window_start = features["window_start"]
        window_end = features["window_end"]

        observation_count = int(features.get("observation_count", 0))

        connectable_fraction = safe_float(features.get("connectable_fraction"))
        discoverable_fraction = safe_float(features.get("discoverable_fraction"))
        scannable_fraction = safe_float(features.get("scannable_fraction"))

        public_addr_fraction = safe_float(features.get("public_addr_fraction"))
        random_addr_fraction = safe_float(features.get("random_addr_fraction"))

        local_name_present_fraction = safe_float(features.get("local_name_present_fraction"))
        local_name_stability = safe_float(features.get("local_name_stability"))

        probable_device_label = features.get("probable_device_label")
        probable_device_label_stability = safe_float(features.get("probable_device_label_stability"))
        probable_device_type = features.get("probable_device_type")
        probable_device_type_stability = safe_float(features.get("probable_device_type_stability"))
        identity_confidence = safe_float(features.get("identity_confidence"))
        identification_basis = list(features.get("identification_basis", []) or [])

        dominant_uuid_signature_fraction = safe_float(features.get("dominant_uuid_signature_fraction"))
        dominant_company_signature_fraction = safe_float(features.get("dominant_company_signature_fraction"))
        dominant_address_fraction = safe_float(features.get("dominant_address_fraction"))

        unique_addresses = int(features.get("unique_addresses", 0))
        address_change_events = int(features.get("address_change_events", 0))

        cluster_presence_fraction_all_windows = safe_float(
            features.get("cluster_presence_fraction_all_windows")
        )

        sensitive_service_count = int(features.get("sensitive_service_count", 0))
        sensitive_service_categories = list(features.get("sensitive_service_categories", []) or [])

        unique_service_uuid_count = int(features.get("unique_service_uuid_count", 0))
        unique_manufacturer_company_count = int(features.get("unique_manufacturer_company_count", 0))
        sparse_observation_fraction = safe_float(features.get("sparse_observation_fraction"))

        attack_surface_score, attack_drivers = self._score_attack_surface(
            connectable_fraction=connectable_fraction,
            discoverable_fraction=discoverable_fraction,
            scannable_fraction=scannable_fraction,
        )

        identifiability_score, ident_drivers = self._score_identifiability(
            public_addr_fraction=public_addr_fraction,
            random_addr_fraction=random_addr_fraction,
            local_name_present_fraction=local_name_present_fraction,
            local_name_stability=local_name_stability,
            probable_device_label=probable_device_label,
            probable_device_label_stability=probable_device_label_stability,
            probable_device_type=probable_device_type,
            probable_device_type_stability=probable_device_type_stability,
            identity_confidence=identity_confidence,
            identification_basis=identification_basis,
            dominant_uuid_signature_fraction=dominant_uuid_signature_fraction,
            dominant_company_signature_fraction=dominant_company_signature_fraction,
            unique_service_uuid_count=unique_service_uuid_count,
            unique_manufacturer_company_count=unique_manufacturer_company_count,
        )

        trackability_score, track_drivers = self._score_trackability(
            cluster_presence_fraction_all_windows=cluster_presence_fraction_all_windows,
            unique_addresses=unique_addresses,
            address_change_events=address_change_events,
            dominant_address_fraction=dominant_address_fraction,
            dominant_uuid_signature_fraction=dominant_uuid_signature_fraction,
            dominant_company_signature_fraction=dominant_company_signature_fraction,
        )

        service_sensitivity_score, service_drivers = self._score_service_sensitivity(
            sensitive_service_count=sensitive_service_count,
            sensitive_service_categories=sensitive_service_categories,
            unique_service_uuid_count=unique_service_uuid_count,
        )

        confidence_score = self._score_confidence(
            observation_count=observation_count,
            sparse_observation_fraction=sparse_observation_fraction,
            cluster_presence_fraction_all_windows=cluster_presence_fraction_all_windows,
            identity_confidence=identity_confidence,
        )

        weighted_exposure = (
            0.30 * attack_surface_score
            + 0.30 * identifiability_score
            + 0.20 * trackability_score
            + 0.20 * service_sensitivity_score
        )

        confidence_factor = 0.60 + 0.40 * (confidence_score / 100.0)
        exposure_score = round(weighted_exposure * confidence_factor, 2)

        exposure_tier = self._tier(exposure_score)

        high_exposure_indicator, high_exposure_reasons = self._high_exposure_indicator(
            connectable_fraction=connectable_fraction,
            local_name_present_fraction=local_name_present_fraction,
            public_addr_fraction=public_addr_fraction,
            identity_confidence=identity_confidence,
            probable_device_label=probable_device_label,
            probable_device_type=probable_device_type,
            dominant_uuid_signature_fraction=dominant_uuid_signature_fraction,
            dominant_company_signature_fraction=dominant_company_signature_fraction,
            cluster_presence_fraction_all_windows=cluster_presence_fraction_all_windows,
            sensitive_service_count=sensitive_service_count,
        )

        score_components = {
            "attack_surface_score": round(attack_surface_score, 2),
            "identifiability_score": round(identifiability_score, 2),
            "trackability_score": round(trackability_score, 2),
            "service_sensitivity_score": round(service_sensitivity_score, 2),
        }

        score_drivers = self._top_drivers(
            attack_drivers + ident_drivers + track_drivers + service_drivers
        )

        scored = ScoredClusterWindow(
            cluster_id=cluster_id,
            window_start=window_start,
            window_end=window_end,
            exposure_score=exposure_score,
            confidence_score=round(confidence_score, 2),
            exposure_tier=exposure_tier,
            attack_surface_score=round(attack_surface_score, 2),
            identifiability_score=round(identifiability_score, 2),
            trackability_score=round(trackability_score, 2),
            service_sensitivity_score=round(service_sensitivity_score, 2),
            high_exposure_indicator=high_exposure_indicator,
            high_exposure_reasons=high_exposure_reasons,
            score_drivers=score_drivers,
            score_components=score_components,
        )

        output = dict(features)
        output.update(asdict(scored))
        return output

    # --------------------------------------------------------
    # Component scorers
    # --------------------------------------------------------

    def _score_attack_surface(
        self,
        *,
        connectable_fraction: float,
        discoverable_fraction: float,
        scannable_fraction: float,
    ) -> Tuple[float, List[Dict[str, Any]]]:
        raw = (
            0.55 * clamp(connectable_fraction)
            + 0.30 * clamp(discoverable_fraction)
            + 0.15 * clamp(scannable_fraction)
        )
        score = raw * 100.0

        drivers = [
            self._driver("connectable_fraction", connectable_fraction, 55.0, "Connectable advertising observed"),
            self._driver("discoverable_fraction", discoverable_fraction, 30.0, "Discoverable advertising posture observed"),
            self._driver("scannable_fraction", scannable_fraction, 15.0, "Scannable advertising observed"),
        ]
        return score, drivers

    def _score_identifiability(
        self,
        *,
        public_addr_fraction: float,
        random_addr_fraction: float,
        local_name_present_fraction: float,
        local_name_stability: float,
        probable_device_label: Any,
        probable_device_label_stability: float,
        probable_device_type: Any,
        probable_device_type_stability: float,
        identity_confidence: float,
        identification_basis: List[str],
        dominant_uuid_signature_fraction: float,
        dominant_company_signature_fraction: float,
        unique_service_uuid_count: int,
        unique_manufacturer_company_count: int,
    ) -> Tuple[float, List[Dict[str, Any]]]:
        public_ident = clamp(public_addr_fraction)
        stable_name = clamp(local_name_present_fraction * local_name_stability)
        stable_uuid_sig = clamp(dominant_uuid_signature_fraction)
        stable_company_sig = clamp(dominant_company_signature_fraction)
        uuid_surface_bonus = fraction_from_count(unique_service_uuid_count, 8)
        company_surface_bonus = fraction_from_count(unique_manufacturer_company_count, 3)

        identity_label_strength = clamp(identity_confidence * probable_device_label_stability)
        identity_type_strength = clamp(identity_confidence * probable_device_type_stability)
        identity_basis_strength = fraction_from_count(len(identification_basis), 4)

        raw = (
            0.22 * public_ident
            + 0.20 * stable_name
            + 0.18 * stable_uuid_sig
            + 0.12 * stable_company_sig
            + 0.12 * identity_label_strength
            + 0.08 * identity_type_strength
            + 0.04 * identity_basis_strength
            + 0.03 * uuid_surface_bonus
            + 0.01 * company_surface_bonus
        )

        if random_addr_fraction > 0.8 and stable_name < 0.1 and public_ident < 0.1:
            raw *= 0.85

        score = raw * 100.0

        identity_label_desc = "Stable probable device label inferred" if probable_device_label else "No probable device label inferred"
        identity_type_desc = "Stable probable device type inferred" if probable_device_type else "No probable device type inferred"

        drivers = [
            self._driver("public_addr_fraction", public_addr_fraction, 22.0, "Public address behavior increases identifiability"),
            self._driver("stable_local_name", stable_name, 20.0, "Stable local name observed"),
            self._driver("dominant_uuid_signature_fraction", dominant_uuid_signature_fraction, 18.0, "Stable service UUID signature observed"),
            self._driver("dominant_company_signature_fraction", dominant_company_signature_fraction, 12.0, "Stable manufacturer signature observed"),
            self._driver("identity_label_strength", identity_label_strength, 12.0, identity_label_desc),
            self._driver("identity_type_strength", identity_type_strength, 8.0, identity_type_desc),
            self._driver("identification_basis", identity_basis_strength, 4.0, "Multiple identification bases available"),
            self._driver("unique_service_uuid_count", uuid_surface_bonus, 3.0, "Broader advertised service surface"),
            self._driver("unique_manufacturer_company_count", company_surface_bonus, 1.0, "Manufacturer/company artifacts present"),
        ]
        return score, drivers

    def _score_trackability(
        self,
        *,
        cluster_presence_fraction_all_windows: float,
        unique_addresses: int,
        address_change_events: int,
        dominant_address_fraction: float,
        dominant_uuid_signature_fraction: float,
        dominant_company_signature_fraction: float,
    ) -> Tuple[float, List[Dict[str, Any]]]:
        persistence = clamp(cluster_presence_fraction_all_windows)
        stable_tokens = clamp(max(dominant_uuid_signature_fraction, dominant_company_signature_fraction))
        address_stability = clamp(dominant_address_fraction)

        if unique_addresses > 1 or address_change_events > 0:
            rotation_with_stability = clamp(0.6 * stable_tokens + 0.4 * persistence)
            raw = (
                0.45 * persistence
                + 0.45 * rotation_with_stability
                + 0.10 * clamp(fraction_from_count(address_change_events, 5))
            )
        else:
            raw = (
                0.55 * persistence
                + 0.30 * stable_tokens
                + 0.15 * address_stability
            )

        score = raw * 100.0

        drivers = [
            self._driver("cluster_presence_fraction_all_windows", persistence, 45.0, "Persistent presence over time"),
            self._driver("stable_payload_signatures", stable_tokens, 35.0, "Stable payload signatures across observations"),
            self._driver("address_change_events", fraction_from_count(address_change_events, 5), 10.0, "Address changes observed"),
            self._driver("dominant_address_fraction", address_stability, 10.0, "Stable dominant address within window"),
        ]
        return score, drivers

    def _score_service_sensitivity(
        self,
        *,
        sensitive_service_count: int,
        sensitive_service_categories: List[str],
        unique_service_uuid_count: int,
    ) -> Tuple[float, List[Dict[str, Any]]]:
        sensitive_count_norm = fraction_from_count(sensitive_service_count, 4)
        category_diversity_norm = fraction_from_count(len(sensitive_service_categories), 3)
        service_surface_norm = fraction_from_count(unique_service_uuid_count, 10)

        raw = (
            0.65 * sensitive_count_norm
            + 0.20 * category_diversity_norm
            + 0.15 * service_surface_norm
        )
        score = raw * 100.0

        drivers = [
            self._driver("sensitive_service_count", sensitive_count_norm, 65.0, "Sensitive advertised service classes present"),
            self._driver("sensitive_service_categories", category_diversity_norm, 20.0, "Diverse sensitive service categories present"),
            self._driver("unique_service_uuid_count", service_surface_norm, 15.0, "Broad service advertising surface"),
        ]
        return score, drivers

    def _score_confidence(
        self,
        *,
        observation_count: int,
        sparse_observation_fraction: float,
        cluster_presence_fraction_all_windows: float,
        identity_confidence: float,
    ) -> float:
        obs_strength = fraction_from_count(observation_count, 20)
        persistence_strength = clamp(cluster_presence_fraction_all_windows)
        sparsity_penalty = clamp(1.0 - sparse_observation_fraction)
        identity_strength = clamp(identity_confidence)

        raw = (
            0.45 * obs_strength
            + 0.20 * persistence_strength
            + 0.20 * sparsity_penalty
            + 0.15 * identity_strength
        )
        return raw * 100.0

    # --------------------------------------------------------
    # High Exposure Baseline
    # --------------------------------------------------------

    def _high_exposure_indicator(
        self,
        *,
        connectable_fraction: float,
        local_name_present_fraction: float,
        public_addr_fraction: float,
        identity_confidence: float,
        probable_device_label: Any,
        probable_device_type: Any,
        dominant_uuid_signature_fraction: float,
        dominant_company_signature_fraction: float,
        cluster_presence_fraction_all_windows: float,
        sensitive_service_count: int,
    ) -> Tuple[bool, List[str]]:
        reasons: List[str] = []

        if connectable_fraction >= 0.5:
            reasons.append("connectable_advertising")

        if local_name_present_fraction >= 0.5:
            reasons.append("local_name_exposed")

        if public_addr_fraction >= 0.5:
            reasons.append("public_address_behavior")

        if max(dominant_uuid_signature_fraction, dominant_company_signature_fraction) >= 0.7:
            reasons.append("stable_payload_tokens")

        if cluster_presence_fraction_all_windows >= 0.4:
            reasons.append("persistent_presence")

        if sensitive_service_count >= 1:
            reasons.append("sensitive_service_advertised")

        if identity_confidence >= 0.7:
            reasons.append("strong_identity_inference")

        if probable_device_label:
            reasons.append("probable_device_label")

        if probable_device_type:
            reasons.append(f"probable_device_type:{probable_device_type}")

        indicator = (
            ("connectable_advertising" in reasons and len(reasons) >= 2)
            or len(reasons) >= 3
        )

        return indicator, reasons

    # --------------------------------------------------------
    # Driver Formatting
    # --------------------------------------------------------

    def _driver(self, field: str, normalized_value: float, max_points: float, description: str) -> Dict[str, Any]:
        normalized_value = clamp(normalized_value)
        return {
            "field": field,
            "description": description,
            "normalized_value": round(normalized_value, 3),
            "points_contributed": round(normalized_value * max_points, 2),
            "max_points": round(max_points, 2),
        }

    def _top_drivers(self, drivers: List[Dict[str, Any]], top_k: int = 5) -> List[Dict[str, Any]]:
        ranked = sorted(drivers, key=lambda d: d["points_contributed"], reverse=True)
        return ranked[:top_k]

    def _tier(self, score: float) -> str:
        if score >= 75:
            return "high"
        if score >= 45:
            return "medium"
        return "low"


# ============================================================
# Convenience Functions
# ============================================================

def score_features_jsonl(input_path: str | Path, output_path: str | Path) -> List[Dict[str, Any]]:
    engine = BLEExposureScoringEngine()
    input_path = Path(input_path)
    output_path = Path(output_path)

    scored_rows = [engine.score_record(row) for row in read_jsonl(input_path)]
    write_jsonl(output_path, scored_rows)
    return scored_rows


def rank_latest_by_cluster(scored_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Keep the latest scored row per cluster, then rank by exposure score descending.
    Useful for reporting the current top-N devices.
    """
    latest: Dict[int, Dict[str, Any]] = {}
    for row in scored_rows:
        cid = int(row["cluster_id"])
        current = latest.get(cid)
        if current is None or row["window_end"] > current["window_end"]:
            latest[cid] = row

    ranked = sorted(
        latest.values(),
        key=lambda r: (safe_float(r.get("exposure_score")), safe_float(r.get("confidence_score"))),
        reverse=True,
    )
    return ranked


# ============================================================
# CLI
# ============================================================

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Score BLE cluster-window features and produce explainable exposure scores."
    )
    parser.add_argument("input", help="Path to feature JSONL input file")
    parser.add_argument("output", help="Path to scored JSONL output file")
    parser.add_argument(
        "--print-top",
        type=int,
        default=0,
        help="Print the latest top-N ranked clusters after scoring",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    scored_rows = score_features_jsonl(args.input, args.output)
    print(f"Scored {len(scored_rows)} feature rows to {args.output}")

    if args.print_top > 0:
        ranked = rank_latest_by_cluster(scored_rows)[: args.print_top]
        print("\nTop ranked clusters (latest window per cluster):")
        for row in ranked:
            label = row.get("probable_device_label") or "unknown"
            dtype = row.get("probable_device_type") or "unknown"
            print(
                f"cluster={row['cluster_id']} "
                f"label={label} "
                f"type={dtype} "
                f"score={row['exposure_score']:.2f} "
                f"confidence={row['confidence_score']:.2f} "
                f"tier={row['exposure_tier']} "
                f"high_exposure={row['high_exposure_indicator']}"
            )


if __name__ == "__main__":
    main()
