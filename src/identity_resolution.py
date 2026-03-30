from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import dataclass, field, asdict
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


def normalize_addr(addr: Optional[str]) -> Optional[str]:
    if not addr:
        return None
    return addr.strip().lower()


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class LinkEvidence:
    reason: str
    score: float
    details: Dict[str, Any]


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
        }


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
        an enriched record with cluster metadata.
        """
        ts = record.get("ts")
        if not ts:
            raise ValueError("Record is missing required field: ts")

        now = parse_iso_ts(ts)
        self._expire_inactive_clusters(now)

        addr = normalize_addr(record.get("addr"))
        addr_type = record.get("addr_type")

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
                return self._annotate_record(record, cluster_id, evidence, action="linked")

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
            return self._annotate_record(record, best_cluster.cluster_id, evidence, action="linked")

        # 3) No sufficiently strong candidate -> create new cluster
        new_cluster = self._create_cluster(record)
        evidence = LinkEvidence(
            reason="new_cluster",
            score=1.0,
            details={"message": "No existing cluster exceeded the link threshold."},
        )
        return self._annotate_record(record, new_cluster.cluster_id, evidence, action="created")

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

        service_uuids = set(record.get("service_uuids") or [])
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
            cluster.addr_types[addr_type] += 1

        if local_name:
            cluster.local_names[local_name] += 1

        if adv_type:
            cluster.adv_type_counter[adv_type] += 1

        for uuid in service_uuids:
            cluster.service_uuid_counter[uuid] += 1

        for entry in service_data:
            uuid = entry.get("uuid")
            if uuid:
                cluster.service_data_uuid_counter[str(uuid).lower()] += 1

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

        record_uuids = set(record.get("service_uuids") or [])
        cluster_uuids = set(cluster.service_uuid_counter.keys())

        record_service_data_uuids = {
            str(entry.get("uuid")).lower()
            for entry in (record.get("service_data") or [])
            if entry.get("uuid") is not None
        }
        cluster_service_data_uuids = set(cluster.service_data_uuid_counter.keys())

        record_companies = {
            str(entry.get("company_id"))
            for entry in (record.get("manufacturer_data") or [])
            if entry.get("company_id") is not None
        }
        cluster_companies = set(cluster.manufacturer_company_counter.keys())

        top_name = cluster.local_names.most_common(1)[0][0] if cluster.local_names else None
        top_addr_type = cluster.addr_types.most_common(1)[0][0] if cluster.addr_types else None
        top_adv_type = cluster.adv_type_counter.most_common(1)[0][0] if cluster.adv_type_counter else None

        feature_scores = {
            "temporal": temporal_similarity(delta_seconds, self.max_gap_seconds),
            "rssi": bounded_rssi_similarity(rssi, cluster.last_rssi),
            "local_name": safe_ratio(local_name, top_name),
            "service_uuids": jaccard(record_uuids, cluster_uuids),
            "service_data_uuids": jaccard(record_service_data_uuids, cluster_service_data_uuids),
            "manufacturer_companies": jaccard(record_companies, cluster_companies),
            "addr_type": 1.0 if addr_type and top_addr_type and addr_type == top_addr_type else 0.0,
            "adv_type": 1.0 if adv_type and top_adv_type and adv_type == top_adv_type else 0.0,
        }

        # Strong evidence bonus: exact repeated address would normally have hit fast path,
        # but keep it here defensively in case the address map was pruned/reset.
        if addr and addr in cluster.addresses:
            feature_scores["address_reuse"] = 1.0
        else:
            feature_scores["address_reuse"] = 0.0

        # Conservative weights emphasizing stable broadcast artifacts
        weights = {
            "address_reuse": 0.40,
            "service_uuids": 0.18,
            "manufacturer_companies": 0.14,
            "service_data_uuids": 0.12,
            "local_name": 0.08,
            "temporal": 0.04,
            "rssi": 0.02,
            "addr_type": 0.01,
            "adv_type": 0.01,
        }

        weighted_sum = sum(feature_scores[k] * weights[k] for k in weights)

        # Penalize merges when there is little stable evidence
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

        # Require at least one meaningful stable signal; otherwise heavily down-rank
        if stable_evidence_count == 0:
            weighted_sum *= 0.45

        # If both observations are almost empty, avoid merging on time/RSSI alone
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
        cluster_id: int,
        evidence: LinkEvidence,
        *,
        action: str,
    ) -> Dict[str, Any]:
        enriched = dict(record)
        enriched["cluster_id"] = cluster_id
        enriched["cluster_action"] = action
        enriched["link_reason"] = evidence.reason
        enriched["link_confidence"] = round(evidence.score, 3)
        enriched["link_details"] = evidence.details
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