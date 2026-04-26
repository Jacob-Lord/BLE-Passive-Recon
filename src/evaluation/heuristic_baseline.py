import json
import argparse
from pathlib import Path


def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, separators=(",", ":")) + "\n")


def latest_by_cluster(rows):
    latest = {}
    for r in rows:
        cid = r["cluster_id"]
        cur = latest.get(cid)
        if cur is None or r["window_end"] > cur["window_end"]:
            latest[cid] = r
    return list(latest.values())


parser = argparse.ArgumentParser()
parser.add_argument("input")
parser.add_argument("output")
args = parser.parse_args()

rows = list(read_jsonl(args.input))
latest = latest_by_cluster(rows)

out = []
for r in latest:
    connectable = float(r.get("connectable_fraction", 0.0) or 0.0)
    sensitive = 1.0 if int(r.get("sensitive_service_count", 0) or 0) > 0 else 0.0

    heuristic_score = (0.7 * connectable + 0.3 * sensitive) * 100.0

    rr = dict(r)
    rr["exposure_score"] = round(heuristic_score, 2)
    rr["exposure_tier"] = (
        "high" if heuristic_score >= 75 else
        "medium" if heuristic_score >= 45 else
        "low"
    )
    out.append(rr)

write_jsonl(args.output, out)
print(f"Wrote {len(out)} heuristic baseline rows to {args.output}")