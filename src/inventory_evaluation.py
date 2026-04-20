from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


# ============================================================
# Helpers
# ============================================================


def parse_iso_ts(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt



def to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()



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



def write_json(path: Path, data: Any) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)



def normalize_addr(addr: Optional[str]) -> Optional[str]:
    if not addr:
        return None
    return str(addr).strip().lower()



def normalize_uuid(uuid: Any) -> Optional[str]:
    if uuid is None:
        return None
    s = str(uuid).strip().lower()
    return s or None



def record_service_uuids(record: Dict[str, Any]) -> Set[str]:
    return {
        u for u in (normalize_uuid(x) for x in (record.get("service_uuids") or []))
        if u is not None
    }



def record_company_ids(record: Dict[str, Any]) -> Set[str]:
    companies = set()
    for entry in (record.get("manufacturer_data") or []):
        company_id = entry.get("company_id")
        if company_id is not None:
            companies.add(str(company_id))
    return companies


# ============================================================
# Data classes
# ============================================================


@dataclass
class DeviceEvalResult:
    device_id: str
    introduced_at: str
    first_seen_at: Optional[str]
    time_to_first_seen_seconds: Optional[float]
    observed_within_windows: Dict[str, bool]
    matched_by: Optional[str]


# ============================================================
# Matching
# ============================================================


def record_matches(record: Dict[str, Any], matcher: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Supported match fields:
      - addr
      - addr_any
      - local_name
      - local_name_contains
      - service_uuids_any
      - service_uuids_all
      - manufacturer_company_ids_any

    All provided fields are ANDed together.
    """
    reasons: List[str] = []

    if "addr" in matcher:
        target = normalize_addr(matcher["addr"])
        if normalize_addr(record.get("addr")) != target:
            return False, None
        reasons.append("addr")

    if "addr_any" in matcher:
        targets = {normalize_addr(x) for x in matcher["addr_any"] if normalize_addr(x) is not None}
        if normalize_addr(record.get("addr")) not in targets:
            return False, None
        reasons.append("addr_any")

    if "local_name" in matcher:
        if str(record.get("local_name") or "") != str(matcher["local_name"]):
            return False, None
        reasons.append("local_name")

    if "local_name_contains" in matcher:
        needle = str(matcher["local_name_contains"]).lower()
        hay = str(record.get("local_name") or "").lower()
        if needle not in hay:
            return False, None
        reasons.append("local_name_contains")

    if "service_uuids_any" in matcher:
        record_uuids = record_service_uuids(record)
        targets = {u for u in (normalize_uuid(x) for x in matcher["service_uuids_any"]) if u is not None}
        if not (record_uuids & targets):
            return False, None
        reasons.append("service_uuids_any")

    if "service_uuids_all" in matcher:
        record_uuids = record_service_uuids(record)
        targets = {u for u in (normalize_uuid(x) for x in matcher["service_uuids_all"]) if u is not None}
        if not targets.issubset(record_uuids):
            return False, None
        reasons.append("service_uuids_all")

    if "manufacturer_company_ids_any" in matcher:
        record_companies = record_company_ids(record)
        targets = {str(x) for x in matcher["manufacturer_company_ids_any"]}
        if not (record_companies & targets):
            return False, None
        reasons.append("manufacturer_company_ids_any")

    if not matcher:
        return False, None

    return True, ",".join(reasons) if reasons else None


# ============================================================
# Evaluation
# ============================================================


class InventoryEvaluator:
    def __init__(self, windows_seconds: Sequence[int]) -> None:
        self.windows_seconds = list(windows_seconds)

    def evaluate(
        self,
        records: List[Dict[str, Any]],
        manifest: Dict[str, Any],
    ) -> Dict[str, Any]:
        if not records:
            raise ValueError("No observation records were provided.")

        records = sorted(records, key=lambda r: r.get("ts", ""))
        capture_start = parse_iso_ts(records[0]["ts"])
        capture_end = parse_iso_ts(records[-1]["ts"])


    
        if isinstance(manifest, dict):
            devices = manifest.get("devices")
        elif isinstance(manifest, list):
            devices = manifest
        else:
            raise ValueError("Manifest must be either a dict with a 'devices' key or a list of device entries.")

        per_device: List[DeviceEvalResult] = []
        recalled_counts = {str(w): 0 for w in self.windows_seconds}
        ttf_values: List[float] = []

        for device in devices:
            device_id = str(device["device_id"])
            matcher = dict(device.get("match") or {})
            introduced_at = self._resolve_introduced_at(device, capture_start)

            first_seen_at: Optional[datetime] = None
            matched_by: Optional[str] = None

            for record in records:
                ts = parse_iso_ts(record["ts"])
                if ts < introduced_at:
                    continue

                matched, reason = record_matches(record, matcher)
                if matched:
                    first_seen_at = ts
                    matched_by = reason
                    break

            observed_within_windows: Dict[str, bool] = {}
            ttf_seconds: Optional[float] = None

            if first_seen_at is not None:
                ttf_seconds = (first_seen_at - introduced_at).total_seconds()
                ttf_values.append(ttf_seconds)
                for w in self.windows_seconds:
                    hit = ttf_seconds <= w
                    observed_within_windows[str(w)] = hit
                    if hit:
                        recalled_counts[str(w)] += 1
            else:
                for w in self.windows_seconds:
                    observed_within_windows[str(w)] = False

            per_device.append(
                DeviceEvalResult(
                    device_id=device_id,
                    introduced_at=to_iso(introduced_at),
                    first_seen_at=to_iso(first_seen_at) if first_seen_at is not None else None,
                    time_to_first_seen_seconds=round(ttf_seconds, 3) if ttf_seconds is not None else None,
                    observed_within_windows=observed_within_windows,
                    matched_by=matched_by,
                )
            )

        total_devices = len(devices)
        recall_by_window = {
            str(w): round(recalled_counts[str(w)] / total_devices, 4)
            for w in self.windows_seconds
        }

        median_ttf = self._median(ttf_values)

        return {
            "capture_start": to_iso(capture_start),
            "capture_end": to_iso(capture_end),
            "capture_duration_seconds": round((capture_end - capture_start).total_seconds(), 3),
            "total_devices_in_manifest": total_devices,
            "devices_observed_at_least_once": sum(1 for d in per_device if d.first_seen_at is not None),
            "recall_by_window": recall_by_window,
            "median_time_to_first_seen_seconds": round(median_ttf, 3) if median_ttf is not None else None,
            "per_device": [asdict(x) for x in per_device],
        }

    def _resolve_introduced_at(self, device: Dict[str, Any], capture_start: datetime) -> datetime:
        if "introduced_at" in device:
            return parse_iso_ts(str(device["introduced_at"]))
        if "introduced_offset_seconds" in device:
            return capture_start + timedelta(seconds=float(device["introduced_offset_seconds"]))
        return capture_start

    @staticmethod
    def _median(values: Sequence[float]) -> Optional[float]:
        if not values:
            return None
        values = sorted(values)
        n = len(values)
        mid = n // 2
        if n % 2 == 1:
            return values[mid]
        return (values[mid - 1] + values[mid]) / 2.0


# ============================================================
# CLI output
# ============================================================


def print_report(result: Dict[str, Any], windows_seconds: Sequence[int]) -> None:
    print("Inventory Evaluation")
    print("--------------------")
    print(f"Capture start:             {result['capture_start']}")
    print(f"Capture end:               {result['capture_end']}")
    print(f"Capture duration (sec):    {result['capture_duration_seconds']}")
    print(f"Devices in manifest:       {result['total_devices_in_manifest']}")
    print(f"Devices observed:          {result['devices_observed_at_least_once']}")
    print(f"Median time-to-first-seen: {result['median_time_to_first_seen_seconds']}")
    print()
    print("Detection Recall")
    print("----------------")
    for w in windows_seconds:
        key = str(w)
        print(f"Recall @ {w:>4}s:           {result['recall_by_window'][key]:.4f}")
    print()
    print("Per-device Results")
    print("------------------")
    for device in result["per_device"]:
        print(f"device_id:                 {device['device_id']}")
        print(f"  introduced_at:           {device['introduced_at']}")
        print(f"  first_seen_at:           {device['first_seen_at']}")
        print(f"  time_to_first_seen_sec:  {device['time_to_first_seen_seconds']}")
        print(f"  matched_by:              {device['matched_by']}")
        print(f"  observed_within_windows: {device['observed_within_windows']}")


# ============================================================
# CLI
# ============================================================


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate passive inventory quality against a controlled manifest. "
            "Computes detection recall at fixed windows and median time-to-first-seen."
        )
    )
    parser.add_argument("input", help="Path to capture JSONL (raw or resolved observations)")
    parser.add_argument("manifest", help="Path to inventory manifest JSON")
    parser.add_argument(
        "--windows",
        nargs="+",
        type=int,
        default=[60, 300, 900],
        help="Recall windows in seconds (default: 60 300 900)",
    )
    parser.add_argument(
        "--output-json",
        help="Optional path to write the full evaluation result as JSON",
    )
    return parser



def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    input_path = Path(args.input)
    manifest_path = Path(args.manifest)

    records = list(read_jsonl(input_path))
    with manifest_path.open("r", encoding="utf-8") as f:
        manifest = json.load(f)

    evaluator = InventoryEvaluator(args.windows)
    result = evaluator.evaluate(records, manifest)
    print_report(result, args.windows)

    if args.output_json:
        write_json(Path(args.output_json), result)
        print(f"\nWrote JSON metrics to {args.output_json}")


if __name__ == "__main__":
    main()
