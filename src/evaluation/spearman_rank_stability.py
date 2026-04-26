from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


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


def latest_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    latest: Dict[int, Dict[str, Any]] = {}
    for row in rows:
        cid = int(row['cluster_id'])
        current = latest.get(cid)
        if current is None or row['window_end'] > current['window_end']:
            latest[cid] = row
    return sorted(
        latest.values(),
        key=lambda r: (safe_float(r.get('exposure_score')), safe_float(r.get('confidence_score'))),
        reverse=True,
    )


def build_match_key(row: Dict[str, Any], fields: List[str]) -> Optional[str]:
    values: List[str] = []
    for field in fields:
        value = row.get(field)
        if value is None:
            return None
        text = str(value).strip()
        if text == '' or text.lower() == 'none':
            return None
        values.append(text)
    return ' | '.join(values)


def ranks_by_key(rows: List[Dict[str, Any]], match_fields: List[str]) -> Dict[str, int]:
    ranked = latest_rows(rows)
    mapping: Dict[str, int] = {}
    rank = 1
    for row in ranked:
        key = build_match_key(row, match_fields)
        if key is None:
            continue
        if key not in mapping:
            mapping[key] = rank
            rank += 1
    return mapping


def spearman_from_ranks(rank_a: Dict[str, int], rank_b: Dict[str, int]) -> Dict[str, Any]:
    shared = sorted(set(rank_a) & set(rank_b))
    n = len(shared)
    if n < 2:
        return {
            'shared_entities': shared,
            'count_shared_entities': n,
            'spearman_rho': None,
            'message': 'Need at least 2 shared entities to compute Spearman correlation.',
        }

    diffs_sq = 0
    pairs = []
    for key in shared:
        ra = rank_a[key]
        rb = rank_b[key]
        d = ra - rb
        diffs_sq += d * d
        pairs.append({'entity': key, 'rank_a': ra, 'rank_b': rb, 'rank_diff': d})

    rho = 1 - (6 * diffs_sq) / (n * (n * n - 1))
    return {
        'shared_entities': shared,
        'count_shared_entities': n,
        'spearman_rho': round(rho, 6),
        'rank_pairs': pairs,
    }


def compare_two_files(path_a: Path, path_b: Path, match_fields: List[str]) -> Dict[str, Any]:
    rows_a = list(read_jsonl(path_a))
    rows_b = list(read_jsonl(path_b))

    ranks_a = ranks_by_key(rows_a, match_fields)
    ranks_b = ranks_by_key(rows_b, match_fields)
    result = spearman_from_ranks(ranks_a, ranks_b)
    result.update(
        {
            'file_a': str(path_a),
            'file_b': str(path_b),
            'match_fields': match_fields,
            'entities_in_a': len(ranks_a),
            'entities_in_b': len(ranks_b),
        }
    )
    return result


def print_report(metrics: Dict[str, Any]) -> None:
    print('Spearman Rank Stability Evaluation')
    print('----------------------------------')
    print(f"File A:                 {metrics['file_a']}")
    print(f"File B:                 {metrics['file_b']}")
    print(f"Match fields:           {', '.join(metrics['match_fields'])}")
    print(f"Entities in A:          {metrics['entities_in_a']}")
    print(f"Entities in B:          {metrics['entities_in_b']}")
    print(f"Shared entities:        {metrics['count_shared_entities']}")
    rho = metrics.get('spearman_rho')
    print(f"Spearman rho:           {rho if rho is not None else 'None'}")
    if 'message' in metrics:
        print(f"Note:                   {metrics['message']}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Compare two scored BLE captures using Spearman rank correlation.'
    )
    parser.add_argument('input_a', help='First ble_scores.jsonl file')
    parser.add_argument('input_b', help='Second ble_scores.jsonl file')
    parser.add_argument(
        '--match-fields',
        nargs='+',
        default=['probable_device_label'],
        help=(
            'Fields used to align entities across captures. '
            'Default: probable_device_label. '
            'Examples: --match-fields probable_device_label or '
            '--match-fields probable_device_label probable_device_type'
        ),
    )
    parser.add_argument('--output-json', help='Optional path to write metrics as JSON')
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    metrics = compare_two_files(Path(args.input_a), Path(args.input_b), args.match_fields)
    print_report(metrics)

    if args.output_json:
        out_path = Path(args.output_json)
        with out_path.open('w', encoding='utf-8') as f:
            json.dump(metrics, f, indent=2)
        print(f"\nWrote JSON metrics to {out_path}")


if __name__ == '__main__':
    main()
