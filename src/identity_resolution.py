from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


# ============================================================
# Helpers
# ============================================================

def parse_iso_ts(ts: str) -> datetime:
    """
    Parse ISO-8601 timestamps, accepting trailing 'Z'.
    """
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# (https://www.ibm.com/think/topics/jaccard-similarity#:~:text=Jaccard%20similarity%20is%20a%20statistical,that%20the%20sets%20are%20identical.)
# Ranges from 0.0 (no overlap) to 1.0 (identical sets)
def jaccard(a: Set[Any], b: Set[Any]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def safe_ratio(a: Optional[str], b: Optional[str]) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


# For RSSI, we want a similarity that is high for small differences and decays as the gap grows.
# The purpose of finding RSSI similarity is to help link records that are close in time and have similar signal strength, which can be a strong signal of being the same device, especially when other stable identifiers are missing.
def bounded_rssi_similarity(a: Optional[int], b: Optional[int]) -> float:
    if a is None or b is None:
        return 0.0
    diff = abs(a - b)
    if diff <= 6:
        return 1.0
    if diff <= 12:
        return 0.75
    if diff <= 20:
        return 0.4
    return 0.0


# Temporal similarity is a crucial component of the overall similarity score.
# It helps to ensure that we are more likely to link records that are close together in time, which is a strong signal that they may be from the same device.
# The function uses an exponential decay to smoothly reduce the similarity score as the time gap increases, with a configurable maximum gap after which the similarity drops to zero.
def temporal_similarity(delta_seconds: float, max_gap_seconds: float) -> float:
    """
    Smooth decay from 1.0 (immediate) toward 0.0 as the gap approaches/exceeds max_gap.
    """
    if delta_seconds < 0:
        return 0.0
    if delta_seconds >= max_gap_seconds:
        return 0.0
    # Gentle exponential decay
    return math.exp(-delta_seconds / (max_gap_seconds / 3.0))


# Simple address normalization: strip whitespace and lowercase.
# This helps to ensure that we are comparing addresses in a consistent format, which can help to improve the accuracy of our clustering.
def normalize_addr(addr: Optional[str]) -> Optional[str]:
    if not addr:
        return None
    return addr.strip().lower()


BASE_UUID_SUFFIX = "-0000-1000-8000-00805f9b34fb"
GENERIC_NAME_TOKENS = {
    "iphone", "ipad", "airpods", "macbook", "windows pc", "android", "phone",
    "tablet", "laptop", "watch", "keyboard", "mouse", "speaker", "headphones",
    "earbuds", "beacon", "tile", "tracker", "unknown", "device", "ble", "bluetooth",
}

DEVICE_NAME_KEYWORDS = {
    "airpods": "audio_wearable",
    "earbud": "audio_wearable",
    "earbuds": "audio_wearable",
    "headphone": "audio_wearable",
    "headphones": "audio_wearable",
    "speaker": "audio_wearable",
    "iphone": "smartphone",
    "ipad": "tablet",
    "pixel": "smartphone",
    "galaxy": "smartphone",
    "phone": "smartphone",
    "watch": "smartwatch",
    "fitbit": "fitness_tracker",
    "garmin": "fitness_tracker",
    "keyboard": "human_interface",
    "mouse": "human_interface",
    "trackpad": "human_interface",
    "beacon": "location_beacon",
    "tile": "location_beacon",
    "tag": "location_beacon",
    "thermometer": "medical_health",
    "glucose": "medical_health",
    "pulse": "medical_health",
    "oximeter": "medical_health",
    "sensor": "sensor",
    "printer": "peripheral",
}

SERVICE_UUID_TYPE_MAP: Dict[str, str] = {
    f"00001812{BASE_UUID_SUFFIX}": "human_interface",
    f"00001808{BASE_UUID_SUFFIX}": "medical_health",
    f"00001809{BASE_UUID_SUFFIX}": "medical_health",
    f"00001810{BASE_UUID_SUFFIX}": "medical_health",
    f"0000181f{BASE_UUID_SUFFIX}": "medical_health",
    f"00001822{BASE_UUID_SUFFIX}": "medical_health",
    f"0000180d{BASE_UUID_SUFFIX}": "fitness_tracker",
    f"00001816{BASE_UUID_SUFFIX}": "fitness_tracker",
    f"00001819{BASE_UUID_SUFFIX}": "location_navigation",
    f"00001815{BASE_UUID_SUFFIX}": "industrial_control",
    f"00001820{BASE_UUID_SUFFIX}": "network_proxy",
    f"00001823{BASE_UUID_SUFFIX}": "network_proxy",
    f"0000181a{BASE_UUID_SUFFIX}": "sensor",
    f"0000180f{BASE_UUID_SUFFIX}": "general_peripheral",
    f"0000180a{BASE_UUID_SUFFIX}": "general_peripheral",
}


def normalize_uuid(uuid: Any) -> Optional[str]:
    if uuid is None:
        return None

    s = str(uuid).strip().lower()
    if not s:
        return None

    if len(s) == 36 and "-" in s:
        return s

    if len(s) == 4:
        try:
            int(s, 16)
            return f"0000{s}{BASE_UUID_SUFFIX}"
        except ValueError:
            return s

    if len(s) == 8:
        try:
            int(s, 16)
            return f"{s}{BASE_UUID_SUFFIX}"
        except ValueError:
            return s

    return s


def stable_fraction(counter: Counter) -> float:
    if not counter:
        return 0.0
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    return counter.most_common(1)[0][1] / total


def top_counter_value(counter: Counter) -> Optional[str]:
    if not counter:
        return None
    return counter.most_common(1)[0][0]


def is_generic_name(name: Optional[str]) -> bool:
    if not name:
        return True
    lowered = name.strip().lower()
    return lowered in GENERIC_NAME_TOKENS


def infer_type_from_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    lowered = name.lower()
    for keyword, device_type in DEVICE_NAME_KEYWORDS.items():
        if keyword in lowered:
            return device_type
    return None


def infer_type_from_uuids(service_uuids: Iterable[str]) -> Optional[str]:
    type_counter: Counter[str] = Counter()
    for uuid in service_uuids:
        normalized = normalize_uuid(uuid)
        if normalized and normalized in SERVICE_UUID_TYPE_MAP:
            type_counter[SERVICE_UUID_TYPE_MAP[normalized]] += 1
    return top_counter_value(type_counter)


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class LinkEvidence:
    reason: str
    score: float
    details: Dict[str, Any]


@dataclass
class IdentityHints:
    probable_device_label: Optional[str]
    probable_device_type: Optional[str]
    identity_confidence: float
    identification_basis: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "probable_device_label": self.probable_device_label,
            "probable_device_type": self.probable_device_type,
            "identity_confidence": round(self.identity_confidence, 3),
            "identification_basis": self.identification_basis,
        }


@dataclass
class ClusterState:
    cluster_id: int
    first_seen: str
    last_seen: str
    seen_count: int = 0

    addresses: Set[str] = field(default_factory=set)
    addr_types: Counter = field(default_factory=Counter)
    local_names: Counter = field(default_factory=Counter)
    service_uuid_counter: Counter = field(default_factory=Counter)
    service_data_uuid_counter: Counter = field(default_factory=Counter)
    manufacturer_company_counter: Counter = field(default_factory=Counter)
    adv_type_counter: Counter = field(default_factory=Counter)

    avg_rssi: Optional[float] = None
    last_rssi: Optional[int] = None

    # Useful for temporal analysis later
    address_change_count: int = 0

    def to_summary(self) -> Dict[str, Any]:
        identity_hints = build_identity_hints(self)
        return {
            "cluster_id": self.cluster_id,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "seen_count": self.seen_count,
            "addresses": sorted(self.addresses),
            "addr_types": dict(self.addr_types),
            "local_names": dict(self.local_names),
            "top_service_uuids": dict(self.service_uuid_counter.most_common(10)),
            "top_service_data_uuids": dict(self.service_data_uuid_counter.most_common(10)),
            "top_manufacturer_companies": dict(self.manufacturer_company_counter.most_common(10)),
            "adv_types": dict(self.adv_type_counter),
            "avg_rssi": self.avg_rssi,
            "last_rssi": self.last_rssi,
            "address_change_count": self.address_change_count,
            **identity_hints.to_dict(),
        }

# ============================================================
# Identity Hint Builder
# ============================================================

def build_identity_hints(cluster: ClusterState) -> IdentityHints:
    '''
    Build best-effort identity hints for a cluster based on its stable attributes.
    This is separate from the clustering logic and is meant to provide human-readable insights about the probable device type/label without affecting the core clustering decisions.
    '''
    top_name = top_counter_value(cluster.local_names)
    name_stability = stable_fraction(cluster.local_names)
    top_uuid_type = infer_type_from_uuids(cluster.service_uuid_counter.keys())
    top_name_type = infer_type_from_name(top_name)
    top_company = top_counter_value(cluster.manufacturer_company_counter)

    probable_device_label: Optional[str] = None
    probable_device_type: Optional[str] = top_name_type or top_uuid_type
    identification_basis: List[str] = []
    confidence = 0.0

    if top_name:
        probable_device_label = top_name
        if name_stability >= 0.75 and not is_generic_name(top_name):
            confidence += 0.45
            identification_basis.append("stable_local_name")
        elif not is_generic_name(top_name):
            confidence += 0.30
            identification_basis.append("local_name")
        else:
            confidence += 0.12
            identification_basis.append("generic_local_name")

    if top_name_type:
        confidence += 0.20
        identification_basis.append("name_keyword_inference")

    if top_uuid_type:
        confidence += 0.25
        identification_basis.append("service_uuid_inference")
        if probable_device_label is None:
            probable_device_label = f"probable_{top_uuid_type}_device"

    company_stability = stable_fraction(cluster.manufacturer_company_counter)
    if top_company is not None:
        confidence += 0.10 if company_stability >= 0.7 else 0.05
        identification_basis.append("manufacturer_company_id")
        if probable_device_label is None:
            probable_device_label = f"company_{top_company}_device"

    addr_type = top_counter_value(cluster.addr_types)
    if addr_type == "public":
        confidence += 0.10
        identification_basis.append("public_address_behavior")

    if len(cluster.addresses) == 1:
        confidence += 0.08
        identification_basis.append("single_observed_address")

    uuid_signature_stability = stable_fraction(cluster.service_uuid_counter)
    if uuid_signature_stability >= 0.7 and cluster.service_uuid_counter:
        confidence += 0.05
        identification_basis.append("stable_service_uuid_signature")

    identification_basis = list(dict.fromkeys(identification_basis))
    confidence = min(confidence, 0.95)

    return IdentityHints(
        probable_device_label=probable_device_label,
        probable_device_type=probable_device_type,
        identity_confidence=confidence,
        identification_basis=identification_basis,
    )


# ============================================================
# Identity Resolver
# ============================================================

class IdentityResolver:
    """
    Best-effort identity resolution / clustering for advertising-only BLE observations.

    Design goals:
    - Conservative matching: avoid false merges when evidence is weak
    - Explainability: return score components and reason for each cluster assignment
    - Rolling state: keep recent clusters active for temporal linkage
    - Enrichment: attach best-effort device identification hints without replacing clustering
    """

    def __init__(
        self,
        *,
        max_gap_seconds: float = 600.0,
        min_link_score: float = 0.68,
        direct_address_reuse_score: float = 0.99,
        max_active_clusters: int = 5000,
    ) -> None:
        self.max_gap_seconds = max_gap_seconds
        self.min_link_score = min_link_score
        self.direct_address_reuse_score = direct_address_reuse_score
        self.max_active_clusters = max_active_clusters

        self._next_cluster_id = 1
        self.clusters: Dict[int, ClusterState] = {}
        self.address_to_cluster: Dict[str, int] = {}

    # --------------------------------------------------------
    # Public API
    # --------------------------------------------------------

    def process_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assign a normalized advertisement record to a cluster and return
        an enriched record with cluster metadata and best-effort identification hints.
        """
        ts = record.get("ts")
        if not ts:
            raise ValueError("Record is missing required field: ts")

        now = parse_iso_ts(ts)
        self._expire_inactive_clusters(now)

        addr = normalize_addr(record.get("addr"))

        # 1) Fast path: same address seen before
        if addr and addr in self.address_to_cluster:
            cluster_id = self.address_to_cluster[addr]
            cluster = self.clusters.get(cluster_id)
            if cluster is not None:
                self._update_cluster(cluster, record)
                evidence = LinkEvidence(
                    reason="exact_address_match",
                    score=self.direct_address_reuse_score,
                    details={"addr": addr},
                )
                return self._annotate_record(record, cluster, evidence, action="linked")

        # 2) Similarity-based linking
        best_cluster, best_score, best_details = self._find_best_cluster(record)

        if best_cluster is not None and best_score >= self.min_link_score:
            previous_addresses = set(best_cluster.addresses)
            self._update_cluster(best_cluster, record)

            if addr and addr not in previous_addresses and previous_addresses:
                best_cluster.address_change_count += 1

            evidence = LinkEvidence(
                reason="heuristic_link",
                score=best_score,
                details=best_details,
            )
            return self._annotate_record(record, best_cluster, evidence, action="linked")

        # 3) No sufficiently strong candidate -> create new cluster
        new_cluster = self._create_cluster(record)
        evidence = LinkEvidence(
            reason="new_cluster",
            score=1.0,
            details={"message": "No existing cluster exceeded the link threshold."},
        )
        return self._annotate_record(record, new_cluster, evidence, action="created")

    def process_records(self, records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self.process_record(r) for r in records]

    def get_cluster_summaries(self) -> List[Dict[str, Any]]:
        return [cluster.to_summary() for cluster in sorted(self.clusters.values(), key=lambda c: c.cluster_id)]

    # --------------------------------------------------------
    # Internal Methods
    # --------------------------------------------------------

    def _create_cluster(self, record: Dict[str, Any]) -> ClusterState:
        cluster = ClusterState(
            cluster_id=self._next_cluster_id,
            first_seen=record["ts"],
            last_seen=record["ts"],
        )
        self._next_cluster_id += 1
        self._update_cluster(cluster, record)
        self.clusters[cluster.cluster_id] = cluster
        return cluster

    def _update_cluster(self, cluster: ClusterState, record: Dict[str, Any]) -> None:
        addr = normalize_addr(record.get("addr"))
        addr_type = record.get("addr_type")
        local_name = record.get("local_name")
        rssi = record.get("rssi")
        adv_type = record.get("adv_type")

        service_uuids = {normalize_uuid(uuid) for uuid in (record.get("service_uuids") or []) if normalize_uuid(uuid)}
        service_data = record.get("service_data") or []
        manufacturer_data = record.get("manufacturer_data") or []

        cluster.last_seen = record["ts"]
        if cluster.seen_count == 0:
            cluster.first_seen = record["ts"]
        cluster.seen_count += 1

        if addr:
            cluster.addresses.add(addr)
            self.address_to_cluster[addr] = cluster.cluster_id

        if addr_type:
            cluster.addr_types[str(addr_type).lower()] += 1

        if local_name:
            cluster.local_names[str(local_name)] += 1

        if adv_type:
            cluster.adv_type_counter[str(adv_type)] += 1

        for uuid in service_uuids:
            cluster.service_uuid_counter[uuid] += 1

        for entry in service_data:
            uuid = normalize_uuid(entry.get("uuid"))
            if uuid:
                cluster.service_data_uuid_counter[uuid] += 1

        for entry in manufacturer_data:
            company_id = entry.get("company_id")
            if company_id is not None:
                cluster.manufacturer_company_counter[str(company_id)] += 1

        if isinstance(rssi, int):
            cluster.last_rssi = rssi
            if cluster.avg_rssi is None:
                cluster.avg_rssi = float(rssi)
            else:
                # Incremental average
                n = cluster.seen_count
                cluster.avg_rssi = ((cluster.avg_rssi * (n - 1)) + rssi) / n

    def _find_best_cluster(
        self,
        record: Dict[str, Any],
    ) -> Tuple[Optional[ClusterState], float, Dict[str, Any]]:
        best_cluster: Optional[ClusterState] = None
        best_score = -1.0
        best_details: Dict[str, Any] = {}

        for cluster in self.clusters.values():
            score, details = self._score_candidate(cluster, record)
            if score > best_score:
                best_score = score
                best_cluster = cluster
                best_details = details

        return best_cluster, best_score, best_details

    def _score_candidate(
        self,
        cluster: ClusterState,
        record: Dict[str, Any],
    ) -> Tuple[float, Dict[str, Any]]:
        """
        Weighted similarity between a new record and an existing cluster.
        Conservative by design:
        - weak evidence should not cause a merge
        - missing fields do not automatically imply similarity
        """
        now = parse_iso_ts(record["ts"])
        cluster_last_seen = parse_iso_ts(cluster.last_seen)
        delta_seconds = (now - cluster_last_seen).total_seconds()

        if delta_seconds < 0 or delta_seconds > self.max_gap_seconds:
            return 0.0, {"rejected": "outside_time_window", "delta_seconds": delta_seconds}

        addr = normalize_addr(record.get("addr"))
        local_name = record.get("local_name")
        rssi = record.get("rssi")
        addr_type = record.get("addr_type")
        adv_type = record.get("adv_type")

        record_uuids = {normalize_uuid(uuid) for uuid in (record.get("service_uuids") or []) if normalize_uuid(uuid)}
        cluster_uuids = set(cluster.service_uuid_counter.keys())

        record_service_data_uuids = {
            normalize_uuid(entry.get("uuid"))
            for entry in (record.get("service_data") or [])
            if normalize_uuid(entry.get("uuid")) is not None
        }
        cluster_service_data_uuids = set(cluster.service_data_uuid_counter.keys())

        record_companies = {
            str(entry.get("company_id"))
            for entry in (record.get("manufacturer_data") or [])
            if entry.get("company_id") is not None
        }
        cluster_companies = set(cluster.manufacturer_company_counter.keys())

        top_name = top_counter_value(cluster.local_names)
        top_addr_type = top_counter_value(cluster.addr_types)
        top_adv_type = top_counter_value(cluster.adv_type_counter)

        feature_scores = {
            "temporal": temporal_similarity(delta_seconds, self.max_gap_seconds),
            "rssi": bounded_rssi_similarity(rssi, cluster.last_rssi),
            "local_name": safe_ratio(local_name, top_name),
            "service_uuids": jaccard(record_uuids, cluster_uuids),
            "service_data_uuids": jaccard(record_service_data_uuids, cluster_service_data_uuids),
            "manufacturer_companies": jaccard(record_companies, cluster_companies),
            "addr_type": 1.0 if addr_type and top_addr_type and str(addr_type).lower() == top_addr_type else 0.0,
            "adv_type": 1.0 if adv_type and top_adv_type and str(adv_type) == top_adv_type else 0.0,
        }

        # Strong evidence bonus: exact repeated address would normally have hit fast path,
        # but keep it here defensively in case the address map was pruned/reset.
        if addr and addr in cluster.addresses:
            feature_scores["address_reuse"] = 1.0
        else:
            feature_scores["address_reuse"] = 0.0

        # Conservative weights emphasizing stable broadcast artifacts.
        # Local name weight is slightly higher now because we are also using it for best-effort identification,
        # but it still is not strong enough by itself to replace clustering.
        weights = {
            "address_reuse": 0.38,
            "service_uuids": 0.18,
            "manufacturer_companies": 0.14,
            "service_data_uuids": 0.12,
            "local_name": 0.10,
            "temporal": 0.04,
            "rssi": 0.02,
            "addr_type": 0.01,
            "adv_type": 0.01,
        }

        weighted_sum = sum(feature_scores[k] * weights[k] for k in weights)

        # Penalize merges when there is little stable evidence.
        stable_evidence_count = 0
        if feature_scores["address_reuse"] > 0:
            stable_evidence_count += 1
        if feature_scores["service_uuids"] >= 0.5 and record_uuids and cluster_uuids:
            stable_evidence_count += 1
        if feature_scores["manufacturer_companies"] >= 0.5 and record_companies and cluster_companies:
            stable_evidence_count += 1
        if feature_scores["service_data_uuids"] >= 0.5 and record_service_data_uuids and cluster_service_data_uuids:
            stable_evidence_count += 1
        if feature_scores["local_name"] >= 0.92 and local_name and top_name:
            stable_evidence_count += 1

        # Require at least one meaningful stable signal; otherwise heavily down-rank.
        if stable_evidence_count == 0:
            weighted_sum *= 0.45

        # If both observations are almost empty, avoid merging on time/RSSI alone.
        sparse_record = not (record_uuids or record_companies or record_service_data_uuids or local_name)
        sparse_cluster = not (cluster_uuids or cluster_companies or cluster_service_data_uuids or top_name)
        if sparse_record and sparse_cluster:
            weighted_sum *= 0.25

        details = {
            "delta_seconds": round(delta_seconds, 3),
            "feature_scores": {k: round(v, 3) for k, v in feature_scores.items()},
            "stable_evidence_count": stable_evidence_count,
            "cluster_id": cluster.cluster_id,
            "top_cluster_name": top_name,
            "cluster_addresses": sorted(cluster.addresses),
            "cluster_uuid_count": len(cluster_uuids),
            "cluster_company_count": len(cluster_companies),
        }

        return weighted_sum, details

    def _expire_inactive_clusters(self, now: datetime) -> None:
        """
        Drop stale clusters from active consideration if they have not been seen
        for too long. This keeps matching bounded and reduces accidental long-gap merges.
        """
        if len(self.clusters) <= self.max_active_clusters:
            # Still prune based on time, just not based on count pressure
            stale_ids = []
            for cid, cluster in self.clusters.items():
                last_seen = parse_iso_ts(cluster.last_seen)
                if (now - last_seen).total_seconds() > self.max_gap_seconds:
                    stale_ids.append(cid)

            for cid in stale_ids:
                self._remove_cluster_addresses(cid)
                del self.clusters[cid]
            return

        # If too many active clusters, prune oldest first
        clusters_by_age = sorted(
            self.clusters.items(),
            key=lambda item: parse_iso_ts(item[1].last_seen)
        )
        while len(self.clusters) > self.max_active_clusters:
            cid, _ = clusters_by_age.pop(0)
            self._remove_cluster_addresses(cid)
            del self.clusters[cid]

    def _remove_cluster_addresses(self, cluster_id: int) -> None:
        to_delete = [addr for addr, cid in self.address_to_cluster.items() if cid == cluster_id]
        for addr in to_delete:
            del self.address_to_cluster[addr]

    def _annotate_record(
        self,
        record: Dict[str, Any],
        cluster: ClusterState,
        evidence: LinkEvidence,
        *,
        action: str,
    ) -> Dict[str, Any]:
        identity_hints = build_identity_hints(cluster)
        enriched = dict(record)
        enriched["cluster_id"] = cluster.cluster_id
        enriched["cluster_action"] = action
        enriched["link_reason"] = evidence.reason
        enriched["link_confidence"] = round(evidence.score, 3)
        enriched["link_details"] = evidence.details
        enriched.update(identity_hints.to_dict())
        return enriched


# ============================================================
# JSONL Utilities
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
            f.write(json.dumps(record, separators=(",", ":")) + "\n")


def resolve_jsonl(
    input_path: str | Path,
    output_path: str | Path,
    *,
    max_gap_seconds: float = 600.0,
    min_link_score: float = 0.68,
) -> List[Dict[str, Any]]:
    resolver = IdentityResolver(
        max_gap_seconds=max_gap_seconds,
        min_link_score=min_link_score,
    )

    input_path = Path(input_path)
    output_path = Path(output_path)

    results = []
    for record in read_jsonl(input_path):
        results.append(resolver.process_record(record))

    write_jsonl(output_path, results)
    return resolver.get_cluster_summaries()


# ============================================================
# Example CLI-like usage
# ============================================================

if __name__ == "__main__":
    # Example usage:
    # python identity_resolution.py
    #
    # Assumes you already have a JSONL file of normalized ads.
    sample_in = Path("ble_capture.jsonl")
    sample_out = Path("ble_capture_resolved.jsonl")

    if sample_in.exists():
        summaries = resolve_jsonl(sample_in, sample_out)
        print(f"Wrote resolved records to: {sample_out}")
        print("Cluster summaries:")
        print(json.dumps(summaries[:10], indent=2))
    else:
        print("No ble_capture.jsonl found. Create a capture first.")
