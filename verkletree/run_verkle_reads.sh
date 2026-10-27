#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIGS=(5_3 5_6 5_9 6_3 6_6 6_9 7_3 7_6 7_9 8_3 8_6)
PER_TYPE=500
ONLY=""
STAGE=both
while (($#)); do
  case "$1" in
    --per-type) PER_TYPE="$2"; shift 2;;
    --only) ONLY="$2"; shift 2;;
    --stage) STAGE="$2"; shift 2;;
    -h|--help) echo "Usage: bash run_verkle_reads.sh [--per-type 4|500] [--only 5_6] [--stage build|read|both]"; exit 0;;
    *) echo "Unknown argument: $1" >&2; exit 2;;
  esac
done
[[ "$PER_TYPE" =~ ^[0-9]+$ ]] && ((PER_TYPE>0 && PER_TYPE%4==0)) || { echo "--per-type must be multiple of 4" >&2; exit 2; }
[[ "$STAGE" == "both" || "$STAGE" == "build" || "$STAGE" == "read" ]] || { echo "Bad --stage" >&2; exit 2; }
if [[ -n "$ONLY" ]]; then
  case " ${CONFIGS[*]} " in *" $ONLY "*) CONFIGS=("$ONLY");; *) echo "Unknown --only $ONLY" >&2; exit 2;; esac
fi
RUN="$ROOT/benchmark_runs/verkle_reads_$(hostname -s)_$(date +%Y%m%d_%H%M%S)_$$"
mkdir -p "$RUN/logs" "$RUN/raw"
echo "VERKLE READ RUN: $RUN"
echo "CONFIGS: ${CONFIGS[*]}; membership trials: $PER_TYPE; non-membership trials: $PER_TYPE; stage: $STAGE"
for cfg in "${CONFIGS[@]}"; do
  dir="$ROOT/$cfg"
  echo "======== VERKLE $cfg ========"
  if [[ "$STAGE" != read ]]; then
    echo "[BUILD] $cfg (creates or validates saved snapshot)"
    ( cd "$dir" && python3 -u "verkle_${cfg}.py" ) 2>&1 | tee "$RUN/logs/${cfg}_build.log"
  fi
  if [[ "$STAGE" != build ]]; then
    echo "[READ] $cfg: $((2*PER_TYPE)) queries"
    ( cd "$dir" && python3 -u "read_${cfg}.py" --per-type "$PER_TYPE" --output "$RUN/raw/read_${cfg}.csv" ) 2>&1 | tee "$RUN/logs/${cfg}_read.log"
    python3 - "$RUN/raw/read_${cfg}.csv" "$PER_TYPE" <<'PYVALIDATE'
import csv,sys
p,per=sys.argv[1],int(sys.argv[2]); rows=list(csv.DictReader(open(p,newline='')))
assert len(rows)==2*per,(p,len(rows),2*per)
assert all(r['verified']=='True' for r in rows),f'Unverified record in {p}'
assert sum(r['type']=='membership' for r in rows)==per
for cat in ('before_first','same_leaf_group','across_leaf_groups','after_last'):
    assert sum(r['type']==cat for r in rows)==per//4
print(f'VALIDATED read {p}: {len(rows)} rows, all verified', flush=True)
PYVALIDATE
  fi
done
echo "SUCCESS: Verkle READ benchmark run $RUN"
