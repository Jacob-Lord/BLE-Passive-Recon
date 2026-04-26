from __future__ import annotations

import argparse
import json
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from inventory_evaluation import InventoryEvaluator, read_jsonl as read_inventory_jsonl
from evaluate_clustering import evaluate_rows as evaluate_clustering_rows
from evaluation.coverage_at_n import compute_coverage, read_jsonl as read_scores_jsonl
from evaluation.spearman_rank_stability import compare_two_files
from scoring_engine import score_features_jsonl


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



def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)



def write_json(path: Path, data: Any) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)



def compute_storage_growth_mb_per_hour(capture_path: Path) -> Dict[str, Any]:
    rows = list(read_inventory_jsonl(capture_path))
    if not rows:
        raise ValueError("No capture rows found for practicality evaluation.")

    start = parse_iso_ts(rows[0]["ts"])
    end = parse_iso_ts(rows[-1]["ts"])
    duration_seconds = max((end - start).total_seconds(), 1e-9)
    size_bytes = capture_path.stat().st_size
    mb = size_bytes / (1024 * 1024)
    mb_per_hour = mb / (duration_seconds / 3600.0)

    return {
        "capture_file": str(capture_path),
        "capture_duration_seconds": round(duration_seconds, 3),
        "capture_size_bytes": size_bytes,
        "capture_size_mb": round(mb, 6),
        "storage_growth_mb_per_hour": round(mb_per_hour, 6),
    }



def measure_scoring_latency(features_path: Path, repeats: int = 3) -> Dict[str, Any]:
    latencies_ms: List[float] = []

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        for i in range(repeats):
            tmp_output = tmpdir_path / f"scoring_latency_{i}.jsonl"

            start = time.perf_counter()
            score_features_jsonl(features_path, tmp_output)
            end = time.perf_counter()

            latencies_ms.append((end - start) * 1000.0)

    latencies_ms.sort()
    avg_ms = sum(latencies_ms) / len(latencies_ms)
    median_ms = latencies_ms[len(latencies_ms) // 2]

    return {
        "features_file": str(features_path),
        "repeats": repeats,
        "latencies_ms": [round(x, 3) for x in latencies_ms],
        "average_latency_ms": round(avg_ms, 3),
        "median_latency_ms": round(median_ms, 3),
    }

# ============================================================
# Evaluation runners
# ============================================================


def run_inventory_evaluation(capture_path: Path, manifest_path: Path, windows: List[int]) -> Dict[str, Any]:
    records = list(read_inventory_jsonl(capture_path))
    manifest = read_json(manifest_path)
    evaluator = InventoryEvaluator(windows)
    return evaluator.evaluate(records, manifest)



def run_clustering_evaluation(resolved_path: Path) -> Dict[str, Any]:
    rows = list(read_inventory_jsonl(resolved_path))
    return evaluate_clustering_rows(rows)



def run_coverage_evaluation(scores_path: Path, baseline_field: str, ns: List[int]) -> Dict[str, Any]:
    rows = list(read_scores_jsonl(scores_path))
    return compute_coverage(rows, baseline_field, ns)



def run_spearman_evaluation(path_a: Path, path_b: Path, match_fields: List[str]) -> Dict[str, Any]:
    return compare_two_files(path_a, path_b, match_fields)


# ============================================================
# Printing
# ============================================================


def divider(title: str) -> None:
    print()
    print(title)
    print("-" * len(title))



def print_inventory_summary(metrics: Dict[str, Any], windows: List[int]) -> None:
    divider("Inventory Evaluation")
    print(f"Devices in manifest:       {metrics['total_devices_in_manifest']}")
    print(f"Devices observed:          {metrics['devices_observed_at_least_once']}")
    print(f"Median time-to-first-seen: {metrics['median_time_to_first_seen_seconds']}")
    for w in windows:
        print(f"Recall @ {w:>4}s:           {metrics['recall_by_window'][str(w)]:.4f}")



def print_clustering_summary(metrics: Dict[str, Any]) -> None:
    overall = metrics["overall"] if "overall" in metrics else metrics
    divider("Clustering Evaluation")
    print(f"Observations:            {overall['observations']}")
    print(f"Truth devices:           {overall['truth_devices']}")
    print(f"Predicted clusters:      {overall['predicted_clusters']}")
    print(f"Pairwise precision:      {overall['precision']:.4f}")
    print(f"Pairwise recall:         {overall['recall']:.4f}")
    print(f"Pairwise F1:             {overall['f1']:.4f}")
    print(f"False merge clusters:    {overall['false_merge_cluster_count']}")
    print(f"False split devices:     {overall['false_split_device_count']}")



def print_coverage_summary(metrics: Dict[str, Any]) -> None:
    divider("Coverage@N Evaluation")
    print(f"Baseline field:          {metrics['baseline_field']}")
    print(f"Total devices:           {metrics['total_devices']}")
    print(f"High-exposure devices:   {metrics['high_exposure_total']}")
    for row in metrics['results']:
        print(f"Coverage@{row['N']:>3}:           {row['coverage_at_n']:.4f}"
              f"   Precision@N: {row['precision_at_n']:.4f}"
              f"   Effort reduction: {row['analyst_effort_reduction']:.4f}")



def print_spearman_summary(metrics: Dict[str, Any]) -> None:
    divider("Spearman Rank Stability")
    print(f"Entities in A:          {metrics['entities_in_a']}")
    print(f"Entities in B:          {metrics['entities_in_b']}")
    print(f"Shared entities:        {metrics['count_shared_entities']}")
    print(f"Spearman rho:           {metrics.get('spearman_rho')}")
    if metrics.get('message'):
        print(f"Note:                   {metrics['message']}")



def print_practicality_summary(metrics: Dict[str, Any]) -> None:
    divider("Practicality Metrics")
    storage = metrics.get("storage")
    scoring = metrics.get("scoring_latency")
    if storage:
        print(f"Capture size (MB):       {storage['capture_size_mb']}")
        print(f"Capture duration (sec):  {storage['capture_duration_seconds']}")
        print(f"Storage growth (MB/hr):  {storage['storage_growth_mb_per_hour']}")
    if scoring:
        print(f"Scoring repeats:         {scoring['repeats']}")
        print(f"Average latency (ms):    {scoring['average_latency_ms']}")
        print(f"Median latency (ms):     {scoring['median_latency_ms']}")


# ============================================================
# CLI
# ============================================================


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run any combination of inventory, clustering, coverage@N, Spearman rank stability, "
            "and practicality evaluations for the passive BLE recon pipeline."
        )
    )

    # inventory
    parser.add_argument("--capture-input", help="Capture JSONL for inventory and/or storage growth evaluation")
    parser.add_argument("--inventory-manifest", help="Manifest JSON for inventory evaluation")
    parser.add_argument(
        "--inventory-windows",
        nargs="+",
        type=int,
        default=[60, 300, 900],
        help="Inventory recall windows in seconds (default: 60 300 900)",
    )

    # clustering
    parser.add_argument("--resolved-input", help="Resolved JSONL for clustering evaluation")

    # coverage
    parser.add_argument("--scores-input", help="Scored JSONL for Coverage@N evaluation")
    parser.add_argument(
        "--coverage-baseline-field",
        default="high_exposure_indicator",
        help="Boolean baseline field for Coverage@N (default: high_exposure_indicator)",
    )
    parser.add_argument(
        "--coverage-ns",
        nargs="+",
        type=int,
        default=[5, 10, 20],
        help="N values for Coverage@N (default: 5 10 20)",
    )

    # spearman
    parser.add_argument("--spearman-input-a", help="First scored JSONL for rank stability")
    parser.add_argument("--spearman-input-b", help="Second scored JSONL for rank stability")
    parser.add_argument(
        "--spearman-match-fields",
        nargs="+",
        default=["probable_device_label"],
        help="Fields used to align entities across captures (default: probable_device_label)",
    )

    # practicality
    parser.add_argument("--features-input", help="Feature JSONL for scoring latency evaluation")
    parser.add_argument(
        "--latency-repeats",
        type=int,
        default=3,
        help="How many times to repeat scoring latency measurement (default: 3)",
    )

    # output
    parser.add_argument("--output-json", help="Optional path to write all metrics as JSON")

    return parser



def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    results: Dict[str, Any] = {}

    # inventory
    if args.capture_input and args.inventory_manifest:
        results["inventory"] = run_inventory_evaluation(
            Path(args.capture_input),
            Path(args.inventory_manifest),
            args.inventory_windows,
        )
        print_inventory_summary(results["inventory"], args.inventory_windows)

    # clustering
    if args.resolved_input:
        results["clustering"] = run_clustering_evaluation(Path(args.resolved_input))
        print_clustering_summary(results["clustering"])

    # coverage
    if args.scores_input:
        results["coverage_at_n"] = run_coverage_evaluation(
            Path(args.scores_input),
            args.coverage_baseline_field,
            args.coverage_ns,
        )
        print_coverage_summary(results["coverage_at_n"])

    # spearman
    if args.spearman_input_a and args.spearman_input_b:
        results["spearman_rank_stability"] = run_spearman_evaluation(
            Path(args.spearman_input_a),
            Path(args.spearman_input_b),
            args.spearman_match_fields,
        )
        print_spearman_summary(results["spearman_rank_stability"])

    # practicality
    practicality: Dict[str, Any] = {}
    if args.capture_input:
        practicality["storage"] = compute_storage_growth_mb_per_hour(Path(args.capture_input))
    if args.features_input:
        practicality["scoring_latency"] = measure_scoring_latency(Path(args.features_input), args.latency_repeats)
    if practicality:
        results["practicality"] = practicality
        print_practicality_summary(practicality)

    if not results:
        parser.error(
            "No evaluations were run. Provide at least one of: --capture-input/--inventory-manifest, --resolved-input, --scores-input, --spearman-input-a and --spearman-input-b, or --features-input."
        )

    if args.output_json:
        out_path = Path(args.output_json)
        write_json(out_path, results)
        print(f"\nWrote combined JSON metrics to {out_path}")


if __name__ == "__main__":
    main()
