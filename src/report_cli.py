from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


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


def write_json(path: Path, data: Any) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ============================================================
# Ranking / Selection
# ============================================================

def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def latest_by_cluster(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    latest: Dict[int, Dict[str, Any]] = {}

    for row in rows:
        cluster_id = int(row["cluster_id"])
        current = latest.get(cluster_id)

        if current is None or row["window_end"] > current["window_end"]:
            latest[cluster_id] = row

    ranked = sorted(
        latest.values(),
        key=lambda r: (
            safe_float(r.get("exposure_score")),
            safe_float(r.get("confidence_score")),
        ),
        reverse=True,
    )
    return ranked


def filter_by_tier(rows: List[Dict[str, Any]], tier: Optional[str]) -> List[Dict[str, Any]]:
    if not tier:
        return rows
    tier = tier.lower()
    return [row for row in rows if str(row.get("exposure_tier", "")).lower() == tier]


def find_cluster_history(rows: List[Dict[str, Any]], cluster_id: int) -> List[Dict[str, Any]]:
    history = [row for row in rows if int(row["cluster_id"]) == cluster_id]
    history.sort(key=lambda r: r["window_start"])
    return history


# ============================================================
# Formatting Helpers
# ============================================================

def fmt(value: Any, width: int) -> str:
    text = str(value)
    if len(text) > width:
        return text[: width - 3] + "..."
    return text.ljust(width)


def fmt_score(value: Any) -> str:
    return f"{safe_float(value):.2f}"


def format_driver_list(drivers: List[Dict[str, Any]], limit: int = 3) -> str:
    items = []
    for driver in drivers[:limit]:
        desc = driver.get("description", driver.get("field", "unknown"))
        pts = safe_float(driver.get("points_contributed"))
        items.append(f"{desc} ({pts:.1f})")
    return "; ".join(items)


def print_divider(width: int = 110) -> None:
    print("-" * width)


# ============================================================
# Report Rendering
# ============================================================

def print_summary(rows: List[Dict[str, Any]], ranked_latest: List[Dict[str, Any]]) -> None:
    total_windows = len(rows)
    total_clusters = len(ranked_latest)

    tier_counts = {"high": 0, "medium": 0, "low": 0}
    high_exposure_count = 0

    scores = []
    confidences = []

    for row in ranked_latest:
        tier = str(row.get("exposure_tier", "low")).lower()
        if tier in tier_counts:
            tier_counts[tier] += 1

        if bool(row.get("high_exposure_indicator")):
            high_exposure_count += 1

        scores.append(safe_float(row.get("exposure_score")))
        confidences.append(safe_float(row.get("confidence_score")))

    avg_score = sum(scores) / len(scores) if scores else 0.0
    avg_conf = sum(confidences) / len(confidences) if confidences else 0.0

    print("BLE Exposure Report")
    print_divider()
    print(f"Scored windows:           {total_windows}")
    print(f"Unique clusters (latest): {total_clusters}")
    print(f"Average exposure score:   {avg_score:.2f}")
    print(f"Average confidence:       {avg_conf:.2f}")
    print(f"High tier clusters:       {tier_counts['high']}")
    print(f"Medium tier clusters:     {tier_counts['medium']}")
    print(f"Low tier clusters:        {tier_counts['low']}")
    print(f"High-exposure baseline:   {high_exposure_count}")
    print()


def print_top_n(rows: List[Dict[str, Any]], top_n: int) -> None:
    print(f"Top {min(top_n, len(rows))} Clusters")
    print_divider()

    header = (
        f"{fmt('Rank', 6)}"
        f"{fmt('Cluster', 10)}"
        f"{fmt('Score', 8)}"
        f"{fmt('Conf', 8)}"
        f"{fmt('Tier', 8)}"
        f"{fmt('HighExp', 10)}"
        f"{fmt('Obs', 8)}"
        f"{fmt('Window Start', 27)}"
        f"Top Drivers"
    )
    print(header)
    print_divider()

    for idx, row in enumerate(rows[:top_n], start=1):
        drivers = row.get("score_drivers", []) or []
        line = (
            f"{fmt(idx, 6)}"
            f"{fmt(row.get('cluster_id'), 10)}"
            f"{fmt_score(row.get('exposure_score')).ljust(8)}"
            f"{fmt_score(row.get('confidence_score')).ljust(8)}"
            f"{fmt(row.get('exposure_tier', ''), 8)}"
            f"{fmt(str(bool(row.get('high_exposure_indicator'))), 10)}"
            f"{fmt(row.get('observation_count', ''), 8)}"
            f"{fmt(row.get('window_start', ''), 27)}"
            f"{format_driver_list(drivers, limit=3)}"
        )
        print(line)

    print()


def print_cluster_detail(history: List[Dict[str, Any]]) -> None:
    if not history:
        print("No records found for that cluster.")
        return

    latest = history[-1]

    print(f"Cluster Detail: {latest['cluster_id']}")
    print_divider()
    print(f"Latest score:         {fmt_score(latest.get('exposure_score'))}")
    print(f"Latest confidence:    {fmt_score(latest.get('confidence_score'))}")
    print(f"Exposure tier:        {latest.get('exposure_tier')}")
    print(f"High exposure flag:   {bool(latest.get('high_exposure_indicator'))}")
    print(f"Reasons:              {', '.join(latest.get('high_exposure_reasons', [])) or 'None'}")
    print(f"Sensitive categories: {', '.join(latest.get('sensitive_service_categories', [])) or 'None'}")
    print(f"Top local name:       {latest.get('top_local_name') or 'None'}")
    print(f"Observation count:    {latest.get('observation_count')}")
    print(f"Windows seen:         {latest.get('cluster_windows_seen')} / {latest.get('total_windows_in_capture')}")
    print()

    print("Component Scores")
    print_divider()
    print(f"Attack surface:       {fmt_score(latest.get('attack_surface_score'))}")
    print(f"Identifiability:      {fmt_score(latest.get('identifiability_score'))}")
    print(f"Trackability:         {fmt_score(latest.get('trackability_score'))}")
    print(f"Service sensitivity:  {fmt_score(latest.get('service_sensitivity_score'))}")
    print()

    print("Latest Top Score Drivers")
    print_divider()
    for driver in latest.get("score_drivers", []) or []:
        print(
            f"- {driver.get('description', driver.get('field'))}: "
            f"{safe_float(driver.get('points_contributed')):.2f}/"
            f"{safe_float(driver.get('max_points')):.2f}"
        )
    print()

    print("Score History")
    print_divider()
    hist_header = (
        f"{fmt('Window Start', 27)}"
        f"{fmt('Window End', 27)}"
        f"{fmt('Score', 8)}"
        f"{fmt('Conf', 8)}"
        f"{fmt('Tier', 8)}"
        f"{fmt('Obs', 8)}"
    )
    print(hist_header)
    print_divider()

    for row in history:
        line = (
            f"{fmt(row.get('window_start', ''), 27)}"
            f"{fmt(row.get('window_end', ''), 27)}"
            f"{fmt_score(row.get('exposure_score')).ljust(8)}"
            f"{fmt_score(row.get('confidence_score')).ljust(8)}"
            f"{fmt(row.get('exposure_tier', ''), 8)}"
            f"{fmt(row.get('observation_count', ''), 8)}"
        )
        print(line)

    print()


# ============================================================
# Export Helpers
# ============================================================

def build_export_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    export_rows = []

    for row in rows:
        export_rows.append({
            "cluster_id": row.get("cluster_id"),
            "window_start": row.get("window_start"),
            "window_end": row.get("window_end"),
            "exposure_score": row.get("exposure_score"),
            "confidence_score": row.get("confidence_score"),
            "exposure_tier": row.get("exposure_tier"),
            "high_exposure_indicator": row.get("high_exposure_indicator"),
            "high_exposure_reasons": row.get("high_exposure_reasons", []),
            "top_local_name": row.get("top_local_name"),
            "sensitive_service_categories": row.get("sensitive_service_categories", []),
            "top_score_drivers": row.get("score_drivers", []),
        })

    return export_rows


# ============================================================
# CLI
# ============================================================

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate CLI reports from BLE exposure scoring output."
    )
    parser.add_argument(
        "input",
        help="Path to ble_scores.jsonl",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="How many top clusters to display (default: 10)",
    )
    parser.add_argument(
        "--tier",
        choices=["high", "medium", "low"],
        help="Only show clusters from this exposure tier",
    )
    parser.add_argument(
        "--cluster-id",
        type=int,
        help="Show detailed history for a specific cluster ID",
    )
    parser.add_argument(
        "--export-json",
        help="Optional path to export the latest ranked rows as JSON",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    input_path = Path(args.input)
    rows = list(read_jsonl(input_path))

    if not rows:
        print("No scored rows found.")
        return

    ranked_latest = latest_by_cluster(rows)
    ranked_latest = filter_by_tier(ranked_latest, args.tier)

    print_summary(rows, ranked_latest)
    print_top_n(ranked_latest, args.top)

    if args.cluster_id is not None:
        history = find_cluster_history(rows, args.cluster_id)
        print_cluster_detail(history)

    if args.export_json:
        export_rows = build_export_rows(ranked_latest)
        export_path = Path(args.export_json)
        write_json(export_path, export_rows)
        print(f"Exported latest ranked rows to {export_path}")


if __name__ == "__main__":
    main()