from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from advertisement_parser import BLEAdvertisementParser
from identity_resolution import resolve_jsonl
from feature_extraction import extract_features_jsonl
from scoring_engine import score_features_jsonl, rank_latest_by_cluster
from report_cli import (
    read_jsonl as report_read_jsonl,
    write_json as report_write_json,
    latest_by_cluster as report_latest_by_cluster,
    filter_by_tier as report_filter_by_tier,
    find_cluster_history as report_find_cluster_history,
    print_summary as report_print_summary,
    print_top_n as report_print_top_n,
    print_cluster_detail as report_print_cluster_detail,
    build_export_rows as report_build_export_rows,
)


# ============================================================
# Capture
# ============================================================

def append_jsonl(path: Path, record: Dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")


async def run_capture(
    output_path: Path,
    *,
    duration: Optional[int] = None,
    scanning_mode: str = "passive",
    quiet: bool = False,
) -> None:
    try:
        from bleak import BleakScanner
        from bleak.backends.device import BLEDevice
        from bleak.backends.scanner import AdvertisementData
    except ImportError as exc:
        raise RuntimeError(
            "Bleak is required for capture. Install it with: pip install bleak"
        ) from exc

    def handle_advertisement(device: "BLEDevice", adv: "AdvertisementData") -> None:
        record = BLEAdvertisementParser.normalize_from_bleak(
            adv,
            addr=device.address,
            rssi=getattr(adv, "rssi", None),
            addr_type=None,
            adv_type=None,
        )

        append_jsonl(output_path, record)

        if not quiet:
            print(
                f"[{record['ts']}] "
                f"{record.get('addr')} "
                f"RSSI={record.get('rssi')} "
                f"name={record.get('local_name')} "
                f"uuids={record.get('service_uuids')}"
            )

    scanner = BleakScanner(
        detection_callback=handle_advertisement,
        scanning_mode=scanning_mode,
    )

    print(f"Capturing BLE advertisements to {output_path}")
    print(f"Scanning mode: {scanning_mode}")
    if duration:
        print(f"Duration: {duration} seconds")
    else:
        print("Duration: until interrupted (Ctrl+C)")

    await scanner.start()
    try:
        if duration:
            await asyncio.sleep(duration)
        else:
            while True:
                await asyncio.sleep(1)
    finally:
        await scanner.stop()
        print("Capture stopped.")


# ============================================================
# Commands
# ============================================================

def cmd_capture(args: argparse.Namespace) -> None:
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        asyncio.run(
            run_capture(
                output_path,
                duration=args.duration,
                scanning_mode=args.scanning_mode,
                quiet=args.quiet,
            )
        )
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")


def cmd_resolve(args: argparse.Namespace) -> None:
    summaries = resolve_jsonl(
        args.input,
        args.output,
        max_gap_seconds=args.max_gap_seconds,
        min_link_score=args.min_link_score,
    )
    print(f"Resolved records written to {args.output}")
    print(f"Active cluster summaries produced: {len(summaries)}")


def cmd_extract(args: argparse.Namespace) -> None:
    rows = extract_features_jsonl(
        args.input,
        args.output,
        window_seconds=args.window_seconds,
        top_k=args.top_k,
    )
    print(f"Extracted {len(rows)} feature rows to {args.output}")


def cmd_score(args: argparse.Namespace) -> None:
    rows = score_features_jsonl(args.input, args.output)
    print(f"Scored {len(rows)} rows to {args.output}")

    if args.print_top > 0:
        ranked = rank_latest_by_cluster(rows)[: args.print_top]
        print("\nTop ranked clusters:")
        for row in ranked:
            print(
                f"cluster={row['cluster_id']} "
                f"score={row['exposure_score']:.2f} "
                f"confidence={row['confidence_score']:.2f} "
                f"tier={row['exposure_tier']} "
                f"high_exposure={row['high_exposure_indicator']}"
            )


def cmd_report(args: argparse.Namespace) -> None:
    rows = list(report_read_jsonl(Path(args.input)))

    if not rows:
        print("No scored rows found.")
        return

    ranked_latest = report_latest_by_cluster(rows)
    ranked_latest = report_filter_by_tier(ranked_latest, args.tier)

    report_print_summary(rows, ranked_latest)
    report_print_top_n(ranked_latest, args.top)

    if args.cluster_id is not None:
        history = report_find_cluster_history(rows, args.cluster_id)
        report_print_cluster_detail(history)

    if args.export_json:
        export_rows = report_build_export_rows(ranked_latest)
        report_write_json(Path(args.export_json), export_rows)
        print(f"Exported latest ranked rows to {args.export_json}")


def cmd_run_all(args: argparse.Namespace) -> None:
    input_path = Path(args.input)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    resolved_path = out_dir / "ble_capture_resolved.jsonl"
    features_path = out_dir / "ble_features.jsonl"
    scores_path = out_dir / "ble_scores.jsonl"

    print("Step 1/3: Resolving identities...")
    resolve_jsonl(
        input_path,
        resolved_path,
        max_gap_seconds=args.max_gap_seconds,
        min_link_score=args.min_link_score,
    )

    print("Step 2/3: Extracting features...")
    extract_features_jsonl(
        resolved_path,
        features_path,
        window_seconds=args.window_seconds,
        top_k=args.top_k,
    )

    print("Step 3/3: Scoring exposure...")
    scored_rows = score_features_jsonl(features_path, scores_path)

    print("\nPipeline complete.")
    print(f"Resolved file: {resolved_path}")
    print(f"Feature file:  {features_path}")
    print(f"Score file:    {scores_path}")

    if args.print_top > 0:
        ranked = rank_latest_by_cluster(scored_rows)[: args.print_top]
        print("\nTop ranked clusters:")
        for row in ranked:
            print(
                f"cluster={row['cluster_id']} "
                f"score={row['exposure_score']:.2f} "
                f"confidence={row['confidence_score']:.2f} "
                f"tier={row['exposure_tier']} "
                f"high_exposure={row['high_exposure_indicator']}"
            )


# ============================================================
# Parser
# ============================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Passive BLE reconnaissance pipeline CLI"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # capture
    p_capture = subparsers.add_parser(
        "capture",
        help="Capture BLE advertisements to JSONL",
    )
    p_capture.add_argument("output", help="Output JSONL file path")
    p_capture.add_argument(
        "--duration",
        type=int,
        default=None,
        help="Capture duration in seconds (default: run until interrupted)",
    )
    p_capture.add_argument(
        "--scanning-mode",
        choices=["passive", "active"],
        default="passive",
        help="Bleak scanning mode (default: passive)",
    )
    p_capture.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-advertisement console output",
    )
    p_capture.set_defaults(func=cmd_capture)

    # resolve
    p_resolve = subparsers.add_parser(
        "resolve",
        help="Run identity resolution on captured JSONL",
    )
    p_resolve.add_argument("input", help="Input capture JSONL")
    p_resolve.add_argument("output", help="Output resolved JSONL")
    p_resolve.add_argument(
        "--max-gap-seconds",
        type=float,
        default=600.0,
        help="Maximum time gap for linking records (default: 600)",
    )
    p_resolve.add_argument(
        "--min-link-score",
        type=float,
        default=0.68,
        help="Minimum heuristic link score (default: 0.68)",
    )
    p_resolve.set_defaults(func=cmd_resolve)

    # extract
    p_extract = subparsers.add_parser(
        "extract",
        help="Extract time-windowed features from resolved JSONL",
    )
    p_extract.add_argument("input", help="Input resolved JSONL")
    p_extract.add_argument("output", help="Output feature JSONL")
    p_extract.add_argument(
        "--window-seconds",
        type=int,
        default=300,
        help="Feature window size in seconds (default: 300)",
    )
    p_extract.add_argument(
        "--top-k",
        type=int,
        default=5,
        help="Number of top UUIDs/company IDs to retain (default: 5)",
    )
    p_extract.set_defaults(func=cmd_extract)

    # score
    p_score = subparsers.add_parser(
        "score",
        help="Score extracted features",
    )
    p_score.add_argument("input", help="Input feature JSONL")
    p_score.add_argument("output", help="Output scored JSONL")
    p_score.add_argument(
        "--print-top",
        type=int,
        default=0,
        help="Print latest top-N ranked clusters after scoring",
    )
    p_score.set_defaults(func=cmd_score)

    # report
    p_report = subparsers.add_parser(
        "report",
        help="Generate a CLI report from scored JSONL",
    )
    p_report.add_argument("input", help="Input scored JSONL")
    p_report.add_argument(
        "--top",
        type=int,
        default=10,
        help="How many top clusters to display (default: 10)",
    )
    p_report.add_argument(
        "--tier",
        choices=["high", "medium", "low"],
        help="Only show clusters from this exposure tier",
    )
    p_report.add_argument(
        "--cluster-id",
        type=int,
        help="Show detailed history for a specific cluster ID",
    )
    p_report.add_argument(
        "--export-json",
        help="Export latest ranked rows as JSON",
    )
    p_report.set_defaults(func=cmd_report)

    # run-all
    p_run_all = subparsers.add_parser(
        "run-all",
        help="Run resolve -> extract -> score on an existing capture file",
    )
    p_run_all.add_argument("input", help="Input capture JSONL")
    p_run_all.add_argument(
        "--out-dir",
        default="pipeline_output",
        help="Directory for resolved/features/scores outputs",
    )
    p_run_all.add_argument(
        "--max-gap-seconds",
        type=float,
        default=600.0,
        help="Maximum time gap for linking records (default: 600)",
    )
    p_run_all.add_argument(
        "--min-link-score",
        type=float,
        default=0.68,
        help="Minimum heuristic link score (default: 0.68)",
    )
    p_run_all.add_argument(
        "--window-seconds",
        type=int,
        default=300,
        help="Feature window size in seconds (default: 300)",
    )
    p_run_all.add_argument(
        "--top-k",
        type=int,
        default=5,
        help="Number of top UUIDs/company IDs to retain (default: 5)",
    )
    p_run_all.add_argument(
        "--print-top",
        type=int,
        default=10,
        help="Print latest top-N ranked clusters after scoring",
    )
    p_run_all.set_defaults(func=cmd_run_all)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        args.func(args)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()