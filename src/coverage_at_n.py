from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open('r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_num} of {path}: {exc}") from exc


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
        cluster_id = int(row['cluster_id'])
        current = latest.get(cluster_id)
        if current is None or row['window_end'] > current['window_end']:
            latest[cluster_id] = row
    return sorted(
        latest.values(),
        key=lambda r: (safe_float(r.get('exposure_score')), safe_float(r.get('confidence_score'))),
        reverse=True,
    )


def truth_flag(row: Dict[str, Any], baseline_field: str) -> bool:
    value = row.get(baseline_field)
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {'1', 'true', 'yes', 'y'}
    return False


def compute_coverage(rows: List[Dict[str, Any]], baseline_field: str, ns: List[int]) -> Dict[str, Any]:
    ranked = latest_by_cluster(rows)
    total_devices = len(ranked)
    high_exposure_rows = [row for row in ranked if truth_flag(row, baseline_field)]
    high_exposure_ids = {int(row['cluster_id']) for row in high_exposure_rows}

    results: List[Dict[str, Any]] = []
    for n in ns:
        top_n_rows = ranked[: min(n, total_devices)]
        top_n_ids = {int(row['cluster_id']) for row in top_n_rows}
        captured = len(high_exposure_ids & top_n_ids)
        high_total = len(high_exposure_ids)
        coverage = captured / high_total if high_total else 0.0
        effort_reduction = 1.0 - (min(n, total_devices) / total_devices) if total_devices else 0.0
        precision_at_n = captured / min(n, total_devices) if total_devices and min(n, total_devices) > 0 else 0.0
        results.append(
            {
                'N': n,
                'top_n_size': min(n, total_devices),
                'captured_high_exposure': captured,
                'high_exposure_total': high_total,
                'coverage_at_n': round(coverage, 4),
                'precision_at_n': round(precision_at_n, 4),
                'analyst_effort_reduction': round(effort_reduction, 4),
            }
        )

    return {
        'baseline_field': baseline_field,
        'total_devices': total_devices,
        'high_exposure_total': len(high_exposure_ids),
        'ranked_latest_clusters': [int(row['cluster_id']) for row in ranked],
        'high_exposure_clusters': sorted(high_exposure_ids),
        'results': results,
    }


def print_report(metrics: Dict[str, Any]) -> None:
    print('Coverage@N Evaluation')
    print('---------------------')
    print(f"Baseline field:           {metrics['baseline_field']}")
    print(f"Total devices:            {metrics['total_devices']}")
    print(f"High-exposure devices:    {metrics['high_exposure_total']}")
    print()
    print('Results')
    print('-------')
    for row in metrics['results']:
        print(f"Coverage@{row['N']:>3}:           {row['coverage_at_n']:.4f}")
        print(f"  captured high-exposure:  {row['captured_high_exposure']} / {row['high_exposure_total']}")
        print(f"  precision@N:             {row['precision_at_n']:.4f}")
        print(f"  analyst effort reduction:{row['analyst_effort_reduction']:.4f}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Compute Coverage@N and analyst effort reduction from ble_scores.jsonl.'
    )
    parser.add_argument('input', help='Path to ble_scores.jsonl')
    parser.add_argument(
        '--baseline-field',
        default='high_exposure_indicator',
        help='Boolean field used as the high-exposure baseline (default: high_exposure_indicator)',
    )
    parser.add_argument(
        '--ns',
        nargs='+',
        type=int,
        default=[5, 10, 20],
        help='N values to evaluate (default: 5 10 20)',
    )
    parser.add_argument('--output-json', help='Optional path to write metrics as JSON')
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    rows = list(read_jsonl(Path(args.input)))
    if not rows:
        raise ValueError('No scored rows found in input file.')

    metrics = compute_coverage(rows, args.baseline_field, args.ns)
    print_report(metrics)

    if args.output_json:
        out_path = Path(args.output_json)
        with out_path.open('w', encoding='utf-8') as f:
            json.dump(metrics, f, indent=2)
        print(f"\nWrote JSON metrics to {out_path}")


if __name__ == '__main__':
    main()
