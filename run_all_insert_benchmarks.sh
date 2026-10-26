#!/usr/bin/env bash
# Run all 11 independent append-insertion benchmarks.
# Usage:
#   bash run_all_insert_benchmarks.sh
#   bash run_all_insert_benchmarks.sh --runs 1000
#   bash run_all_insert_benchmarks.sh --runs 10 --only 5_3
#   bash run_all_insert_benchmarks.sh --python python3
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PYTHON="python3"
RUNS=1000
ONLY=""
CONFIGS=(5_3 5_6 5_9 6_3 6_6 6_9 7_3 7_6 7_9 8_3 8_6)

usage() {
  cat <<'EOF'
Usage: bash run_all_insert_benchmarks.sh [--runs N] [--only B_D] [--python COMMAND]

  --runs N          Independent insertions per tree (default: 1000; N >= 2)
  --only B_D        Run one configuration, e.g. 5_3, 6_9, or 7_9
  --python COMMAND  Python executable (default: python3)
  -h, --help        Show help

Execute from any directory. Place this script and benchmark_insert.py in
baselines/. For 5_3 the files are directly in baselines/; the other trees
are under baselines/B_D/. Existing benchmark CSVs are archived before
being replaced. Original tree pickles and JSONL files are not changed.
EOF
}

while (($# > 0)); do
  case "$1" in
    --runs)
      [[ $# -ge 2 ]] || { echo 'ERROR: --runs requires a number' >&2; exit 2; }
      RUNS="$2"; shift 2 ;;
    --only)
      [[ $# -ge 2 ]] || { echo 'ERROR: --only requires B_D' >&2; exit 2; }
      ONLY="$2"; shift 2 ;;
    --python)
      [[ $# -ge 2 ]] || { echo 'ERROR: --python requires an executable' >&2; exit 2; }
      PYTHON="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if ! [[ "$RUNS" =~ ^[0-9]+$ ]] || ((RUNS < 2)); then
  echo 'ERROR: --runs must be an integer >= 2.' >&2
  exit 2
fi

if [[ -n "$ONLY" ]]; then
  found=0
  for cfg in "${CONFIGS[@]}"; do
    if [[ "$cfg" == "$ONLY" ]]; then found=1; break; fi
  done
  if (( ! found )); then
    echo "ERROR: Unknown config '$ONLY'. Allowed: ${CONFIGS[*]}" >&2
    exit 2
  fi
  CONFIGS=("$ONLY")
fi

command -v "$PYTHON" >/dev/null 2>&1 || { echo "ERROR: Python '$PYTHON' not found" >&2; exit 1; }
[[ -f "$ROOT/benchmark_insert.py" ]] || { echo "ERROR: Missing $ROOT/benchmark_insert.py" >&2; exit 1; }

# Preflight every selected configuration before changing or running anything.
for cfg in "${CONFIGS[@]}"; do
  if [[ "$cfg" == '5_3' ]]; then
    DIR="$ROOT"
  else
    DIR="$ROOT/$cfg"
  fi
  [[ -d "$DIR" ]] || { echo "ERROR: Missing directory $DIR" >&2; exit 1; }
  for required in "merkle_${cfg}.py" "merkle_tree_${cfg}.pkl" "leaf_values_${cfg}.jsonl"; do
    [[ -f "$DIR/$required" ]] || { echo "ERROR: Missing $DIR/$required" >&2; exit 1; }
  done
done

HOST="$(hostname -s 2>/dev/null || hostname)"
HOST="${HOST//[^a-zA-Z0-9_.-]/_}"
RUN_ID="${HOST}_$(date +%Y%m%d_%H%M%S)_$$"
OUT="$ROOT/benchmark_runs/$RUN_ID"
mkdir -p "$OUT/previous_csvs"

{
  echo "run_id=$RUN_ID"
  echo "start_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "base_directory=$ROOT"
  echo "hostname=$HOST"
  echo "runs_per_tree=$RUNS"
  echo "python_executable=$PYTHON"
  "$PYTHON" --version 2>&1
  echo "git_commit=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unavailable)"
  uname -a
} > "$OUT/environment.txt"

echo "Benchmark root: $ROOT"
echo "Trials per tree: $RUNS"
echo "Results archive: $OUT"
echo "Selected trees: ${CONFIGS[*]}"

for cfg in "${CONFIGS[@]}"; do
  if [[ "$cfg" == '5_3' ]]; then
    DIR="$ROOT"
  else
    DIR="$ROOT/$cfg"
    # __file__ is used to find its matching tree data and Python module.
    # Copying is intentional; running ../benchmark_insert.py would be wrong.
    cp "$ROOT/benchmark_insert.py" "$DIR/benchmark_insert.py"
  fi

  CSV="$DIR/insert_benchmark_${cfg}.csv"
  if [[ -f "$CSV" ]]; then
    cp "$CSV" "$OUT/previous_csvs/insert_benchmark_${cfg}.csv"
  fi

  echo
  echo "========== ${cfg} : $(date) =========="
  (
    cd "$DIR"
    "$PYTHON" benchmark_insert.py --runs "$RUNS"
  ) 2>&1 | tee "$OUT/${cfg}.log"

  [[ -s "$CSV" ]] || { echo "ERROR: CSV missing/empty: $CSV" >&2; exit 1; }
  cp "$CSV" "$OUT/insert_benchmark_${cfg}.csv"
  echo "Saved $OUT/insert_benchmark_${cfg}.csv"
done

# Aggregate results from this run only (no external Python libraries needed).
"$PYTHON" - "$OUT" "$RUNS" <<'PY'
import csv
import statistics
import sys
from pathlib import Path

folder = Path(sys.argv[1])
expected_runs = int(sys.argv[2])
columns = (
    'search_ms', 'jsonl_append_ms', 'proof_ms',
    'total_insert_ms', 'verification_ms', 'proof_bytes'
)
summary = []
for file in sorted(folder.glob('insert_benchmark_*.csv')):
    with file.open(newline='', encoding='utf-8') as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) != expected_runs:
        raise SystemExit(f'{file}: expected {expected_runs} rows, got {len(rows)}')
    if any(row.get('verified', '').lower() != 'true' for row in rows):
        raise SystemExit(f'{file}: at least one proof was not verified')
    first = rows[0]
    report = {
        'configuration': file.stem[len('insert_benchmark_'):] ,
        'fanout': first['fanout'],
        'old_depth': first['old_depth'],
        'old_leaf_count': first['old_leaf_count'],
        'runs': len(rows),
    }
    for col in columns:
        values = [float(row[col]) for row in rows]
        report[f'{col}_mean'] = f'{statistics.mean(values):.9f}'
        report[f'{col}_sd'] = f'{statistics.stdev(values):.9f}'
    summary.append(report)

if not summary:
    raise SystemExit('No insertion CSVs found')
path = folder / 'insert_summary.csv'
with path.open('w', newline='', encoding='utf-8') as stream:
    writer = csv.DictWriter(stream, fieldnames=list(summary[0]))
    writer.writeheader()
    writer.writerows(summary)
print(f'\nALL SELECTED INSERT BENCHMARKS PASSED: {len(summary)} configuration(s)')
print(f'Consolidated summary: {path}')
PY

echo "Detailed logs and CSVs: $OUT"
