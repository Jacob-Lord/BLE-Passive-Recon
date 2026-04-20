from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from math import comb
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


TRUTH_FIELD = "device_truth_id"
PRED_FIELD = "cluster_id"
SCENARIO_FIELD = "scenario_name"


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


def safe_comb2(n: int) -> int:
    return comb(n, 2) if n >= 2 else 0


def contingency_counts(rows: List[Dict[str, Any]]) -> Tuple[Counter, Counter, Counter]:
    truth_counts: Counter[str] = Counter()
    pred_counts: Counter[str] = Counter()
    pair_counts: Counter[Tuple[str, str]] = Counter()

    for row in rows:
        truth = str(row[TRUTH_FIELD])
        pred = str(row[PRED_FIELD])
        truth_counts[truth] += 1
        pred_counts[pred] += 1
        pair_counts[(truth, pred)] += 1

    return truth_counts, pred_counts, pair_counts


def pairwise_metrics(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    truth_counts, pred_counts, pair_counts = contingency_counts(rows)

    tp = sum(safe_comb2(n) for n in pair_counts.values())
    pred_pairs = sum(safe_comb2(n) for n in pred_counts.values())
    truth_pairs = sum(safe_comb2(n) for n in truth_counts.values())

    fp = pred_pairs - tp
    fn = truth_pairs - tp

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    # Cluster-level false merges: predicted clusters containing >1 truth ID
    pred_to_truths: Dict[str, set[str]] = defaultdict(set)
    truth_to_preds: Dict[str, set[str]] = defaultdict(set)

    for row in rows:
        truth = str(row[TRUTH_FIELD])
        pred = str(row[PRED_FIELD])
        pred_to_truths[pred].add(truth)
        truth_to_preds[truth].add(pred)

    false_merge_clusters = {pred: sorted(list(truths)) for pred, truths in pred_to_truths.items() if len(truths) > 1}
    false_split_devices = {truth: sorted(list(preds)) for truth, preds in truth_to_preds.items() if len(preds) > 1}

    return {
        "observations": len(rows),
        "truth_devices": len(truth_counts),
        "predicted_clusters": len(pred_counts),
        "pairwise_tp": tp,
        "pairwise_fp": fp,
        "pairwise_fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_merge_pairs": fp,
        "false_split_pairs": fn,
        "false_merge_cluster_count": len(false_merge_clusters),
        "false_split_device_count": len(false_split_devices),
        "false_merge_clusters": false_merge_clusters,
        "false_split_devices": false_split_devices,
    }


def filter_valid_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    valid = []
    for row in rows:
        if TRUTH_FIELD not in row:
            continue
        if PRED_FIELD not in row:
            continue
        valid.append(row)
    return valid


def per_scenario_metrics(rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        scenario = str(row.get(SCENARIO_FIELD, "unknown"))
        grouped[scenario].append(row)

    return {scenario: pairwise_metrics(group_rows) for scenario, group_rows in sorted(grouped.items())}


def print_summary(label: str, metrics: Dict[str, Any]) -> None:
    print(f"\n{label}")
    print("-" * len(label))
    print(f"Observations:            {metrics['observations']}")
    print(f"Truth devices:           {metrics['truth_devices']}")
    print(f"Predicted clusters:      {metrics['predicted_clusters']}")
    print(f"Pairwise precision:      {metrics['precision']:.4f}")
    print(f"Pairwise recall:         {metrics['recall']:.4f}")
    print(f"Pairwise F1:             {metrics['f1']:.4f}")
    print(f"False merge pairs:       {metrics['false_merge_pairs']}")
    print(f"False split pairs:       {metrics['false_split_pairs']}")
    print(f"False merge clusters:    {metrics['false_merge_cluster_count']}")
    print(f"False split devices:     {metrics['false_split_device_count']}")

    if metrics["false_merge_clusters"]:
        print("False merge cluster details:")
        for pred, truths in metrics["false_merge_clusters"].items():
            print(f"  cluster {pred}: merged truths {truths}")

    if metrics["false_split_devices"]:
        print("False split device details:")
        for truth, preds in metrics["false_split_devices"].items():
            print(f"  truth {truth}: split into clusters {preds}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate clustering quality on synthetic BLE traces.")
    parser.add_argument("input", help="Resolved JSONL file containing cluster_id and device_truth_id")
    parser.add_argument("--output-json", help="Optional JSON path for metric output")
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    rows = filter_valid_rows(list(read_jsonl(Path(args.input))))
    if not rows:
        raise ValueError("No rows found with both device_truth_id and cluster_id.")

    overall = pairwise_metrics(rows)
    per_scenario = per_scenario_metrics(rows)

    print_summary("Overall Clustering Metrics", overall)
    for scenario, metrics in per_scenario.items():
        print_summary(f"Scenario: {scenario}", metrics)

    if args.output_json:
        output = {
            "overall": overall,
            "per_scenario": per_scenario,
        }
        with Path(args.output_json).open("w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        print(f"\nWrote JSON metrics to {args.output_json}")


if __name__ == "__main__":
    main()
