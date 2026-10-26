#!/usr/bin/env bash
# End-to-end Merkle baseline workflow. Python 3 standard library only.
# Builds each MISSING tree, runs read / sequential update / independent insert,
# snapshots every original trial CSV, then consolidates all recorded fields.
# Existing JSONL and pickle files are NEVER overwritten by this runner.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PYTHON=python3
RUNS=1000
ONLY=()
STAGES=build,read,update,insert
RESUME=""
ALL_CONFIGS=(5_3 5_6 5_9 6_3 6_6 6_9 7_3 7_6 7_9 8_3 8_6)

usage() {
  cat <<'EOF'
Usage: bash run_full_merkle_suite.sh [options]
  --runs N                 Per-tree trial count (default 1000; multiple of 8, >= 16)
  --only B_D               Run only one tree (may be repeated)
  --stages S               Comma-separated subset: build,read,update,insert
  --resume DIRECTORY       Resume an interrupted run directory
  --python PYTHON          Python 3 executable (default python3)
  -h, --help               Show this help

Build is nondestructive: generate both JSONL/pickle only when BOTH are absent.
If both exist, reuse them; if only one exists, fail rather than corrupt a tree.
Updates always use --no-save, preserving the same starting tree for every
operation. Reads and insertions also preserve original datasets. Each raw CSV
is snapshotted under benchmark_runs/<run_id>/raw/<tree>/, then consolidated.

WARNING: construction and 1000 update runs for 7^9 may take a long time and
require >10 GiB RAM and substantial temporary disk write capacity.
Only load locally generated/trusted pickles.
EOF
}

while (( $# )); do
  case "$1" in
    --runs) [[ $# -ge 2 ]] || exit 2; RUNS="$2"; shift 2 ;;
    --only) [[ $# -ge 2 ]] || exit 2; ONLY+=("$2"); shift 2 ;;
    --stages) [[ $# -ge 2 ]] || exit 2; STAGES="$2"; shift 2 ;;
    --resume) [[ $# -ge 2 ]] || exit 2; RESUME="$2"; shift 2 ;;
    --python) [[ $# -ge 2 ]] || exit 2; PYTHON="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown argument '$1'" >&2; usage >&2; exit 2 ;;
  esac
done

if ! [[ "$RUNS" =~ ^[0-9]+$ ]] || ((RUNS < 16 || RUNS % 8 != 0)); then
  echo 'ERROR: --runs must be an integer multiple of 8, >=16' >&2; exit 2
fi
command -v "$PYTHON" >/dev/null || { echo "ERROR: Python $PYTHON not found" >&2; exit 2; }
[[ -f "$ROOT/consolidate_merkle_results.py" ]] || { echo 'ERROR: missing consolidator' >&2; exit 1; }
[[ -f "$ROOT/benchmark_insert.py" ]] || { echo 'ERROR: missing shared benchmark_insert.py' >&2; exit 1; }

if (( ${#ONLY[@]} )); then
  CONFIGS=()
  for cfg in "${ONLY[@]}"; do
    found=0
    for valid in "${ALL_CONFIGS[@]}"; do [[ "$cfg" == "$valid" ]] && found=1; done
    (( found )) || { echo "ERROR: unknown config $cfg" >&2; exit 2; }
    found=0
    for prior in "${CONFIGS[@]:-}"; do [[ "$prior" == "$cfg" ]] && found=1; done
    (( found )) || CONFIGS+=("$cfg")
  done
else
  CONFIGS=("${ALL_CONFIGS[@]}")
fi
IFS=',' read -r -a SELECTED_STAGES <<< "$STAGES"
(( ${#SELECTED_STAGES[@]} )) || { echo 'ERROR: empty --stages' >&2; exit 2; }
for stage in "${SELECTED_STAGES[@]}"; do
  case "$stage" in build|read|update|insert) ;; *) echo "ERROR: unknown stage $stage" >&2; exit 2;; esac
done
has_stage() {
  local candidate="$1" p
  for p in "${SELECTED_STAGES[@]}"; do [[ "$p" == "$candidate" ]] && return 0; done
  return 1
}

for cfg in "${CONFIGS[@]}"; do
  if [[ "$cfg" == 5_3 ]]; then dir="$ROOT"; else dir="$ROOT/$cfg"; fi
  [[ -d "$dir" ]] || { echo "ERROR: missing directory $dir" >&2; exit 1; }
  [[ -f "$dir/merkle_${cfg}.py" ]] || { echo "ERROR: missing construction script for $cfg" >&2; exit 1; }
  for op in read update; do
    has_stage "$op" || continue
    if [[ "$op" == read ]]; then script="read_${cfg}.py"; else script="benchmark_update_${cfg}.py"; fi
    [[ -f "$dir/$script" ]] || { echo "ERROR: missing $dir/$script" >&2; exit 1; }
  done
  if ! has_stage build; then
    [[ -f "$dir/merkle_tree_${cfg}.pkl" && -f "$dir/leaf_values_${cfg}.jsonl" ]] || {
      echo "ERROR: missing dataset for $cfg; include build stage" >&2; exit 1;
    }
  fi
done

if [[ -z "$RESUME" ]]; then
  host="$(hostname -s 2>/dev/null || hostname)"
  host="${host//[^a-zA-Z0-9_.-]/_}"
  RUN_DIR="$ROOT/benchmark_runs/${host}_$(date +%Y%m%d_%H%M%S)_$$"
  mkdir -p "$RUN_DIR"
  printf '%s\n' "runs=$RUNS" "configs=${CONFIGS[*]}" "stages=$STAGES" > "$RUN_DIR/run_plan.txt"
  {
    echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "project_root=$ROOT"
    echo "run_directory=$RUN_DIR"
    echo "python=$PYTHON"
    "$PYTHON" --version
    echo "hostname=$(hostname)"
    echo "git_sha=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unavailable)"
    uname -a
    if command -v free >/dev/null; then free -h; fi
    if command -v sysctl >/dev/null; then sysctl -n hw.memsize 2>/dev/null || true; fi
  } > "$RUN_DIR/environment.txt"
else
  RUN_DIR="$(cd "$RESUME" && pwd -P)"
  [[ -f "$RUN_DIR/run_plan.txt" ]] || { echo 'ERROR: invalid --resume dir' >&2; exit 2; }
  printf '%s\n' "runs=$RUNS" "configs=${CONFIGS[*]}" "stages=$STAGES" | cmp -s - "$RUN_DIR/run_plan.txt" || {
    echo 'ERROR: resume arguments do not match original run plan' >&2; exit 2;
  }
fi
mkdir -p "$RUN_DIR"/{logs,raw,construction,status,previous_csvs}
echo "PROJECT: $ROOT"
echo "RUN: $RUN_DIR"
echo "CONFIGURATIONS: ${CONFIGS[*]}"
echo "STAGES: $STAGES; TRIALS PER OPERATION: $RUNS"

# Capture construction metadata, including timing of actual new tree creation.
write_construction_record() {
  local cfg="$1" status="$2" elapsed="$3" log="$4" dir="$5"
  "$PYTHON" - "$cfg" "$status" "$elapsed" "$log" "$dir" "$RUN_DIR/construction/$cfg.json" <<'PY'
import json, re, sys
from datetime import datetime, timezone
from pathlib import Path
cfg, status, elapsed, log_path, dir_path, target = sys.argv[1:]
log = Path(log_path).read_text(encoding='utf-8') if Path(log_path).exists() else ''
root_matches = re.findall(r'(?:MERKLE ROOT|Merkle root):\s*([0-9a-fA-F]{64})', log)
hashing_matches = re.findall(r'Construction(?: \([^\n]*?\))? (?:time:|:)\s*([0-9.]+)\s*(?:seconds|s)\b', log)
# Alternative wording from older build scripts.
if not hashing_matches:
    hashing_matches = re.findall(r'Construction \([^\n]*\):\s*([0-9.]+)\s*s', log)
b, d = (int(x) for x in cfg.split('_'))
record = {
    'configuration': cfg, 'fanout': b, 'depth': d, 'leaf_count': b**d,
    'status': status, 'constructed_this_run': status == 'created',
    'construction_wall_seconds': float(elapsed) if status == 'created' else None,
    'construction_hashing_seconds': float(hashing_matches[-1]) if status == 'created' and hashing_matches else None,
    'merkle_root_if_logged': root_matches[-1] if root_matches else None,
    'jsonl_bytes': (Path(dir_path)/f'leaf_values_{cfg}.jsonl').stat().st_size,
    'pickle_bytes': (Path(dir_path)/f'merkle_tree_{cfg}.pkl').stat().st_size,
    'construction_log': str(Path(log_path)),
    'recorded_utc': datetime.now(timezone.utc).isoformat(),
}
Path(target).write_text(json.dumps(record, indent=2)+'\n', encoding='utf-8')
print(f"  construction: {status}, JSONL {record['jsonl_bytes']} bytes, pickle {record['pickle_bytes']} bytes")
PY
}

for cfg in "${CONFIGS[@]}"; do
  if [[ "$cfg" == 5_3 ]]; then dir="$ROOT"; else dir="$ROOT/$cfg"; fi
  mkdir -p "$RUN_DIR/logs/$cfg" "$RUN_DIR/raw/$cfg" "$RUN_DIR/status/$cfg" "$RUN_DIR/previous_csvs/$cfg"
  echo
  echo "================ TREE $cfg : $(date) ================"
  build_ok="$RUN_DIR/status/$cfg/build.ok"
  jsonl="$dir/leaf_values_${cfg}.jsonl"
  pickle="$dir/merkle_tree_${cfg}.pkl"
  build_log="$RUN_DIR/logs/$cfg/build.log"
  if has_stage build; then
    if [[ -f "$build_ok" && -f "$jsonl" && -f "$pickle" ]]; then
      echo "[SKIP] $cfg construction already completed in this run"
    else
      if [[ -e "$jsonl" && ! -f "$pickle" || -e "$pickle" && ! -f "$jsonl" ]]; then
        echo "ERROR: incomplete dataset for $cfg (one of JSONL/pickle missing)" >&2; exit 1
      fi
      if [[ -f "$jsonl" && -f "$pickle" ]]; then
        echo "[REUSE] existing $cfg dataset (no rebuild; existing construction time unknown)"
        printf '%s\n' 'Dataset already exists; no construction run in this suite.' > "$build_log"
        write_construction_record "$cfg" reused 0 "$build_log" "$dir"
      else
        echo "[BUILD] generating $cfg dataset (new random keys)"
        start="$($PYTHON -c 'import time; print(time.perf_counter())')"
        (cd "$dir" && "$PYTHON" "merkle_${cfg}.py") 2>&1 | tee "$build_log"
        end="$($PYTHON -c 'import time; print(time.perf_counter())')"
        elapsed="$($PYTHON - "$start" "$end" <<'PY'
import sys
print(float(sys.argv[2])-float(sys.argv[1]))
PY
)"
        [[ -s "$jsonl" && -s "$pickle" ]] || { echo "ERROR: $cfg construction missing output" >&2; exit 1; }
        write_construction_record "$cfg" created "$elapsed" "$build_log" "$dir"
      fi
      touch "$build_ok"
    fi
  fi

  for operation in read update insert; do
    has_stage "$operation" || continue
    csv="$dir/${operation}_benchmark_${cfg}.csv"
    snap="$RUN_DIR/raw/$cfg/${operation}_benchmark_${cfg}.csv"
    done_file="$RUN_DIR/status/$cfg/$operation.ok"
    log="$RUN_DIR/logs/$cfg/$operation.log"
    if [[ -f "$done_file" && -s "$snap" ]]; then
      "$PYTHON" "$ROOT/consolidate_merkle_results.py" --run-dir "$RUN_DIR" --runs "$RUNS" --check-one "$snap"
      echo "[SKIP] $cfg $operation was already validated"
      continue
    fi
    if [[ "$operation" == insert && "$dir" != "$ROOT" ]]; then
      cp "$ROOT/benchmark_insert.py" "$dir/benchmark_insert.py"
    fi
    if [[ -f "$csv" ]]; then
      cp -p "$csv" "$RUN_DIR/previous_csvs/$cfg/${operation}_benchmark_${cfg}.csv"
      rm -f "$csv"   # ensure an old CSV cannot pass if the program fails
    fi
    echo "[RUN] $cfg $operation ($RUNS trials)"
    case "$operation" in
      read)
        (cd "$dir" && "$PYTHON" "read_${cfg}.py" --per-type "$((RUNS/2))") 2>&1 | tee "$log" ;;
      update)
        # CRITICAL: sequential updates happen on a working copy only.
        (cd "$dir" && "$PYTHON" "benchmark_update_${cfg}.py" --runs "$RUNS" --no-save) 2>&1 | tee "$log" ;;
      insert)
        (cd "$dir" && "$PYTHON" benchmark_insert.py --runs "$RUNS") 2>&1 | tee "$log" ;;
    esac
    "$PYTHON" "$ROOT/consolidate_merkle_results.py" --run-dir "$RUN_DIR" --runs "$RUNS" --check-one "$csv"
    cp -p "$csv" "$snap"
    touch "$done_file"
    echo "[SAVED] $snap"
  done
done

ops=()
for op in read update insert; do has_stage "$op" && ops+=("$op"); done
if (( ${#ops[@]} )); then
  ops_csv="$(IFS=,; echo "${ops[*]}")"
  cmd=("$PYTHON" "$ROOT/consolidate_merkle_results.py" --run-dir "$RUN_DIR" --root "$ROOT" --runs "$RUNS" --operations "$ops_csv")
  for cfg in "${CONFIGS[@]}"; do cmd+=(--only "$cfg"); done
  "${cmd[@]}" | tee "$RUN_DIR/consolidation.log"
else
  echo 'Construction-only run. No trial CSVs requested for consolidation.'
fi
printf '%s\n' "finished_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$RUN_DIR/environment.txt"
echo "SUCCESS: $RUN_DIR"
