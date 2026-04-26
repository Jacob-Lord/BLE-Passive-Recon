from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


# ============================================================
# Helpers
# ============================================================

CONNECTABLE_ADV_TYPES = {"ADV_IND", "ADV_DIRECT_IND", "connectable"}
SCANNABLE_ADV_TYPES = {"ADV_IND", "ADV_SCAN_IND", "scannable"}

BASE_UUID_SUFFIX = "-0000-1000-8000-00805f9b34fb"

SENSITIVE_SERVICE_MAP: Dict[str, str] = {
    # Human interface / input
    f"00001812{BASE_UUID_SUFFIX}": "human_interface",

    # Medical / health
    f"00001808{BASE_UUID_SUFFIX}": "medical_health",
    f"00001809{BASE_UUID_SUFFIX}": "medical_health",
    f"00001810{BASE_UUID_SUFFIX}": "medical_health",
    f"0000181f{BASE_UUID_SUFFIX}": "medical_health",
    f"00001822{BASE_UUID_SUFFIX}": "medical_health",

    # Industrial / physical control
    f"00001815{BASE_UUID_SUFFIX}": "industrial_control",

    # Location / movement context
    f"00001819{BASE_UUID_SUFFIX}": "location_navigation",

    # Networking / bridging
    f"00001820{BASE_UUID_SUFFIX}": "network_proxy",
    f"00001823{BASE_UUID_SUFFIX}": "network_proxy",
}


def parse_iso_ts(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def floor_to_window(dt: datetime, window_seconds: int) -> datetime:
    epoch = int(dt.timestamp())
    floored = epoch - (epoch % window_seconds)
    return datetime.fromtimestamp(floored, tz=timezone.utc)


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


def mean(values: Sequence[float]) -> Optional[float]:
    if not values:
        return None
    return sum(values) / len(values)


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


def is_connectable_adv(adv_type: Optional[str]) -> bool:
    if not adv_type:
        return False
    return adv_type in CONNECTABLE_ADV_TYPES


def is_scannable_adv(adv_type: Optional[str]) -> bool:
    if not adv_type:
        return False
    return adv_type in SCANNABLE_ADV_TYPES


def get_flag_bool(flags: Optional[Dict[str, Any]], key: str) -> bool:
    if not isinstance(flags, dict):
        return False
    return bool(flags.get(key, False))


def counter_top_fraction(counter: Counter[str]) -> float:
    if not counter:
        return 0.0
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    return counter.most_common(1)[0][1] / total


# ============================================================
# Dataclass
# ============================================================

@dataclass
class ClusterWindowFeatures:
    cluster_id: int
    window_start: str
    window_end: str

    observation_count: int
    coverage_seconds: float
    avg_interarrival_seconds: Optional[float]

    avg_rssi: Optional[float]
    min_rssi: Optional[int]
    max_rssi: Optional[int]

    unique_addresses: int
    address_change_events: int
    dominant_address_fraction: float

    public_addr_fraction: float
    random_addr_fraction: float
    unknown_addr_type_fraction: float

    connectable_fraction: float
    scannable_fraction: float

    discoverable_fraction: float
    general_discoverable_fraction: float
    limited_discoverable_fraction: float

    local_name_present_fraction: float
    top_local_name: Optional[str]
    local_name_stability: float

    probable_device_label: Optional[str]
    probable_device_label_stability: float
    probable_device_type: Optional[str]
    probable_device_type_stability: float
    identity_confidence: float
    identification_basis: List[str]

    # Optional synthetic evaluation metadata
    eval_expected_high_exposure: bool
    eval_truth_device_type: Optional[str]
    eval_truth_device_type_stability: float
    eval_scenario_name: Optional[str]

    unique_service_uuid_count: int
    top_service_uuids: List[str]
    dominant_service_uuid_fraction: float
    dominant_uuid_signature_fraction: float

    unique_service_data_uuid_count: int
    top_service_data_uuids: List[str]

    unique_manufacturer_company_count: int
    top_manufacturer_companies: List[str]
    dominant_company_fraction: float
    dominant_company_signature_fraction: float

    sensitive_service_count: int
    sensitive_service_categories: List[str]

    sparse_observation_fraction: float

    cluster_windows_seen: int
    total_windows_in_capture: int
    cluster_presence_fraction_all_windows: float


# ============================================================
# Feature Extractor
# ============================================================

class FeatureExtractor:
    def __init__(self, *, window_seconds: int = 300, top_k: int = 5) -> None:
        self.window_seconds = window_seconds
        self.top_k = top_k

    def extract(self, records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        records_list = list(records)
        if not records_list:
            return []

        records_list.sort(key=lambda r: (r.get("cluster_id", -1), r.get("ts", "")))

        grouped: Dict[Tuple[int, str], List[Dict[str, Any]]] = defaultdict(list)
        all_window_starts: Set[str] = set()
        cluster_to_windows: Dict[int, Set[str]] = defaultdict(set)

        for record in records_list:
            cluster_id = record.get("cluster_id")
            ts = record.get("ts")
            if cluster_id is None or ts is None:
                continue

            dt = parse_iso_ts(ts)
            w_start = to_iso(floor_to_window(dt, self.window_seconds))
            key = (int(cluster_id), w_start)

            grouped[key].append(record)
            all_window_starts.add(w_start)
            cluster_to_windows[int(cluster_id)].add(w_start)

        total_windows_in_capture = len(all_window_starts)
        feature_rows: List[Dict[str, Any]] = []

        for (cluster_id, window_start), group in sorted(grouped.items(), key=lambda item: (item[0][0], item[0][1])):
            features = self._extract_single_window(
                cluster_id=cluster_id,
                window_start=window_start,
                group=group,
                cluster_windows_seen=len(cluster_to_windows[cluster_id]),
                total_windows_in_capture=total_windows_in_capture,
            )
            feature_rows.append(asdict(features))

        return feature_rows

    def _extract_single_window(
        self,
        *,
        cluster_id: int,
        window_start: str,
        group: List[Dict[str, Any]],
        cluster_windows_seen: int,
        total_windows_in_capture: int,
    ) -> ClusterWindowFeatures:
        group = sorted(group, key=lambda r: r["ts"])
        obs_count = len(group)

        ts_list = [parse_iso_ts(r["ts"]) for r in group]
        first_ts = ts_list[0]
        last_ts = ts_list[-1]
        window_start_dt = parse_iso_ts(window_start)
        window_end_dt = window_start_dt.timestamp() + self.window_seconds
        window_end = datetime.fromtimestamp(window_end_dt, tz=timezone.utc)

        coverage_seconds = max(0.0, (last_ts - first_ts).total_seconds())

        interarrivals = []
        for i in range(1, len(ts_list)):
            interarrivals.append((ts_list[i] - ts_list[i - 1]).total_seconds())

        rssis = [r["rssi"] for r in group if isinstance(r.get("rssi"), int)]

        address_counter: Counter[str] = Counter()
        addr_type_counter: Counter[str] = Counter()
        adv_type_counter: Counter[str] = Counter()
        name_counter: Counter[str] = Counter()
        probable_label_counter: Counter[str] = Counter()
        probable_type_counter: Counter[str] = Counter()
        eval_truth_device_type_counter: Counter[str] = Counter()
        eval_scenario_counter: Counter[str] = Counter()
        identification_basis_counter: Counter[str] = Counter()
        identity_confidences: List[float] = []

        service_uuid_counter: Counter[str] = Counter()
        service_data_uuid_counter: Counter[str] = Counter()
        manufacturer_company_counter: Counter[str] = Counter()

        uuid_signature_counter: Counter[str] = Counter()
        company_signature_counter: Counter[str] = Counter()

        sensitive_categories: Set[str] = set()
        sparse_observation_count = 0
        address_change_events = 0
        eval_expected_high_exposure = False

        prev_addr: Optional[str] = None

        for record in group:
            addr = record.get("addr")
            addr_type = record.get("addr_type")
            adv_type = record.get("adv_type")
            local_name = record.get("local_name")

            probable_label = record.get("probable_device_label")
            probable_type = record.get("probable_device_type")
            eval_truth_device_type = record.get("truth_device_type")
            eval_scenario_name = record.get("scenario_name")
            identity_confidence = record.get("identity_confidence")
            identification_basis = record.get("identification_basis") or []

            eval_expected_high_exposure = eval_expected_high_exposure or bool(record.get("expected_high_exposure", False))

            service_uuids = {
                normalize_uuid(u)
                for u in (record.get("service_uuids") or [])
                if normalize_uuid(u) is not None
            }
            service_data_uuids = {
                normalize_uuid(entry.get("uuid"))
                for entry in (record.get("service_data") or [])
                if normalize_uuid(entry.get("uuid")) is not None
            }
            manufacturer_companies = {
                str(entry.get("company_id"))
                for entry in (record.get("manufacturer_data") or [])
                if entry.get("company_id") is not None
            }

            if addr:
                address_counter[str(addr).lower()] += 1
                if prev_addr is not None and str(addr).lower() != prev_addr:
                    address_change_events += 1
                prev_addr = str(addr).lower()

            if addr_type:
                addr_type_counter[str(addr_type).lower()] += 1

            if adv_type:
                adv_type_counter[str(adv_type)] += 1

            if local_name:
                name_counter[str(local_name)] += 1

            if probable_label:
                probable_label_counter[str(probable_label)] += 1

            if probable_type:
                probable_type_counter[str(probable_type)] += 1

            if eval_truth_device_type:
                eval_truth_device_type_counter[str(eval_truth_device_type)] += 1

            if eval_scenario_name:
                eval_scenario_counter[str(eval_scenario_name)] += 1

            try:
                if identity_confidence is not None:
                    identity_confidences.append(float(identity_confidence))
            except (TypeError, ValueError):
                pass

            for basis in identification_basis:
                if basis:
                    identification_basis_counter[str(basis)] += 1

            for uuid in service_uuids:
                service_uuid_counter[uuid] += 1
                if uuid in SENSITIVE_SERVICE_MAP:
                    sensitive_categories.add(SENSITIVE_SERVICE_MAP[uuid])

            for uuid in service_data_uuids:
                service_data_uuid_counter[uuid] += 1

            for company_id in manufacturer_companies:
                manufacturer_company_counter[company_id] += 1

            uuid_signature = "|".join(sorted(service_uuids))
            company_signature = "|".join(sorted(manufacturer_companies))
            uuid_signature_counter[uuid_signature] += 1
            company_signature_counter[company_signature] += 1

            has_any_identifier_signal = bool(
                local_name or service_uuids or service_data_uuids or manufacturer_companies
            )
            if not has_any_identifier_signal:
                sparse_observation_count += 1

        top_local_name = name_counter.most_common(1)[0][0] if name_counter else None
        top_probable_label = probable_label_counter.most_common(1)[0][0] if probable_label_counter else None
        top_probable_type = probable_type_counter.most_common(1)[0][0] if probable_type_counter else None
        top_eval_truth_device_type = eval_truth_device_type_counter.most_common(1)[0][0] if eval_truth_device_type_counter else None
        top_eval_scenario_name = eval_scenario_counter.most_common(1)[0][0] if eval_scenario_counter else None

        top_service_uuids = [u for u, _ in service_uuid_counter.most_common(self.top_k)]
        top_service_data_uuids = [u for u, _ in service_data_uuid_counter.most_common(self.top_k)]
        top_manufacturer_companies = [c for c, _ in manufacturer_company_counter.most_common(self.top_k)]
        top_identification_basis = [b for b, _ in identification_basis_counter.most_common(self.top_k)]

        connectable_count = sum(1 for r in group if is_connectable_adv(r.get("adv_type")))
        scannable_count = sum(1 for r in group if is_scannable_adv(r.get("adv_type")))

        discoverable_count = 0
        general_discoverable_count = 0
        limited_discoverable_count = 0
        for r in group:
            flags = r.get("flags")
            if get_flag_bool(flags, "general_discoverable") or get_flag_bool(flags, "limited_discoverable"):
                discoverable_count += 1
            if get_flag_bool(flags, "general_discoverable"):
                general_discoverable_count += 1
            if get_flag_bool(flags, "limited_discoverable"):
                limited_discoverable_count += 1

        public_count = addr_type_counter.get("public", 0)
        random_count = addr_type_counter.get("random", 0)
        unknown_count = obs_count - public_count - random_count

        dominant_address_fraction = (
            address_counter.most_common(1)[0][1] / obs_count if address_counter else 0.0
        )
        local_name_stability = counter_top_fraction(name_counter)
        probable_label_stability = counter_top_fraction(probable_label_counter)
        probable_type_stability = counter_top_fraction(probable_type_counter)
        eval_truth_device_type_stability = counter_top_fraction(eval_truth_device_type_counter)
        dominant_service_uuid_fraction = (
            service_uuid_counter.most_common(1)[0][1] / obs_count if service_uuid_counter else 0.0
        )
        dominant_uuid_signature_fraction = (
            uuid_signature_counter.most_common(1)[0][1] / obs_count if uuid_signature_counter else 0.0
        )
        dominant_company_fraction = (
            manufacturer_company_counter.most_common(1)[0][1] / obs_count if manufacturer_company_counter else 0.0
        )
        dominant_company_signature_fraction = (
            company_signature_counter.most_common(1)[0][1] / obs_count if company_signature_counter else 0.0
        )

        return ClusterWindowFeatures(
            cluster_id=cluster_id,
            window_start=window_start,
            window_end=to_iso(window_end),

            observation_count=obs_count,
            coverage_seconds=round(coverage_seconds, 3),
            avg_interarrival_seconds=round(mean(interarrivals), 3) if interarrivals else None,

            avg_rssi=round(mean(rssis), 3) if rssis else None,
            min_rssi=min(rssis) if rssis else None,
            max_rssi=max(rssis) if rssis else None,

            unique_addresses=len(address_counter),
            address_change_events=address_change_events,
            dominant_address_fraction=round(dominant_address_fraction, 3),

            public_addr_fraction=round(public_count / obs_count, 3),
            random_addr_fraction=round(random_count / obs_count, 3),
            unknown_addr_type_fraction=round(unknown_count / obs_count, 3),

            connectable_fraction=round(connectable_count / obs_count, 3),
            scannable_fraction=round(scannable_count / obs_count, 3),

            discoverable_fraction=round(discoverable_count / obs_count, 3),
            general_discoverable_fraction=round(general_discoverable_count / obs_count, 3),
            limited_discoverable_fraction=round(limited_discoverable_count / obs_count, 3),

            local_name_present_fraction=round(sum(name_counter.values()) / obs_count, 3),
            top_local_name=top_local_name,
            local_name_stability=round(local_name_stability, 3),

            probable_device_label=top_probable_label,
            probable_device_label_stability=round(probable_label_stability, 3),
            probable_device_type=top_probable_type,
            probable_device_type_stability=round(probable_type_stability, 3),
            identity_confidence=round(mean(identity_confidences) or 0.0, 3),
            identification_basis=top_identification_basis,

            eval_expected_high_exposure=eval_expected_high_exposure,
            eval_truth_device_type=top_eval_truth_device_type,
            eval_truth_device_type_stability=round(eval_truth_device_type_stability, 3),
            eval_scenario_name=top_eval_scenario_name,

            unique_service_uuid_count=len(service_uuid_counter),
            top_service_uuids=top_service_uuids,
            dominant_service_uuid_fraction=round(dominant_service_uuid_fraction, 3),
            dominant_uuid_signature_fraction=round(dominant_uuid_signature_fraction, 3),

            unique_service_data_uuid_count=len(service_data_uuid_counter),
            top_service_data_uuids=top_service_data_uuids,

            unique_manufacturer_company_count=len(manufacturer_company_counter),
            top_manufacturer_companies=top_manufacturer_companies,
            dominant_company_fraction=round(dominant_company_fraction, 3),
            dominant_company_signature_fraction=round(dominant_company_signature_fraction, 3),

            sensitive_service_count=len(sensitive_categories),
            sensitive_service_categories=sorted(sensitive_categories),

            sparse_observation_fraction=round(sparse_observation_count / obs_count, 3),

            cluster_windows_seen=cluster_windows_seen,
            total_windows_in_capture=total_windows_in_capture,
            cluster_presence_fraction_all_windows=round(
                cluster_windows_seen / total_windows_in_capture, 3
            ) if total_windows_in_capture else 0.0,
        )


# ============================================================
# Convenience Function
# ============================================================

def extract_features_jsonl(
    input_path: str | Path,
    output_path: str | Path,
    *,
    window_seconds: int = 300,
    top_k: int = 5,
) -> List[Dict[str, Any]]:
    extractor = FeatureExtractor(window_seconds=window_seconds, top_k=top_k)
    input_path = Path(input_path)
    output_path = Path(output_path)

    records = list(read_jsonl(input_path))
    feature_rows = extractor.extract(records)
    write_jsonl(output_path, feature_rows)
    return feature_rows


# ============================================================
# CLI
# ============================================================

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Extract time-windowed BLE features from identity-resolved JSONL records."
    )
    parser.add_argument("input", help="Path to resolved JSONL input file")
    parser.add_argument("output", help="Path to feature JSONL output file")
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=300,
        help="Tumbling window size in seconds (default: 300)",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=5,
        help="How many top UUIDs/company IDs to keep per window (default: 5)",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    features = extract_features_jsonl(
        args.input,
        args.output,
        window_seconds=args.window_seconds,
        top_k=args.top_k,
    )

    print(f"Extracted {len(features)} feature rows to {args.output}")


if __name__ == "__main__":
    main()
