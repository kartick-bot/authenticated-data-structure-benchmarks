#!/usr/bin/env python3
"""Lossless consolidation of per-trial Merkle benchmark CSVs.

Inputs: immutable per-run snapshots in RUN/raw/<B_D>/<operation>_benchmark_<B_D>.csv
Outputs: all_trials.csv, read_trials.csv, update_trials.csv, insert_trials.csv,
         metric_statistics.csv, category_counts.csv, construction_summary.csv,
         files_manifest.csv, validation_report.json.

Every CSV source field is retained unchanged in the consolidated trial rows
under `data_<original_field>`. Metrics get derived summaries separately.
Python 3 standard library only. Does not build trees or run benchmarks.
"""
import argparse
import csv
import hashlib
import json
import math
import os
import platform
import re
import shutil
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

CONFIGS = ('5_3', '5_6', '5_9', '6_3', '6_6', '6_9', '7_3', '7_6', '7_9', '8_3', '8_6')
OPS = ('read', 'update', 'insert')
METRIC_SUFFIXES = ('_ms', '_bytes')
META_COLUMNS = ('suite_run_id', 'configuration', 'fanout', 'depth', 'leaf_count',
                'benchmark_type', 'trial_index', 'source_row', 'source_file', 'category')


def is_truthy(text):
    return str(text).strip().lower() in {'true', '1', 'yes'}


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def options_parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run-dir', type=Path, required=True,
                   help='Timestamped results directory created by the shell runner')
    p.add_argument('--runs', type=int, default=1000,
                   help='Expected trial rows per selected operation and tree')
    p.add_argument('--only', action='append', choices=CONFIGS, help='Selected tree (repeatable)')
    p.add_argument('--operations', default='read,update,insert',
                   help='Comma-separated benchmark operations to consolidate')
    p.add_argument('--root', type=Path, help='Project root (for construction file sizes)')
    p.add_argument('--import-existing', action='store_true',
                   help='Copy existing per-tree CSVs from --root into the run archive, without executing benchmarks')
    p.add_argument('--check-one', type=Path,
                   help='Validate just this one CSV; infer operation from name, then exit')
    p.add_argument('--configuration', choices=CONFIGS,
                   help='Configuration to use with --check-one')
    return p


def classify_file(path):
    match = re.fullmatch(r'(read|update|insert)_benchmark_(\d+_\d+)\.csv', path.name)
    if not match:
        raise ValueError(f'Unexpected benchmark filename: {path.name}')
    return match.group(1), match.group(2)


def inspect_csv(path, op, cfg, expected):
    """Strict validation; returns headers, all original rows, group counts."""
    if not path.is_file():
        raise ValueError(f'Missing expected CSV: {path}')
    b, d = map(int, cfg.split('_'))
    with path.open('r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames
        if not headers or len(headers) != len(set(headers)):
            raise ValueError(f'{path}: missing or repeated columns')
        if 'verified' not in headers:
            raise ValueError(f'{path}: missing verified column')
        rows = list(reader)
    if len(rows) != expected:
        raise ValueError(f'{path}: expected exactly {expected} rows, got {len(rows)}')
    if any(not is_truthy(row['verified']) for row in rows):
        failed = [str(i) for i, row in enumerate(rows, 1) if not is_truthy(row['verified'])]
        raise ValueError(f'{path}: verification failed in trial(s) {", ".join(failed[:8])}')
    if op == 'read':
        if 'category' not in headers:
            raise ValueError(f'{path}: missing read category')
        tally = Counter(r['category'] for r in rows)
        membership = sum(n for label, n in tally.items() if 'Membership (present)' == label)
        if membership != expected // 2:
            raise ValueError(f'{path}: expected {expected//2} membership, got {membership}')
        if len(rows) - membership != expected // 2:
            raise ValueError(f'{path}: incorrect non-membership count')
        if expected % 8:
            raise ValueError('Read workload must be divisible by eight')
        for case_num in ('1', '2', '3', '4'):
            match_count = sum(n for label, n in tally.items() if label.startswith(f'Case {case_num} '))
            if match_count != expected // 8:
                raise ValueError(f'{path}: Case {case_num} count {match_count}, expected {expected//8}')
    elif op == 'insert':
        if 'fanout' not in headers or 'old_depth' not in headers:
            raise ValueError(f'{path}: missing insertion structural fields')
        if any(int(row['fanout']) != b or int(row['old_depth']) != d for row in rows):
            raise ValueError(f'{path}: fanout or depth mismatch')
        if any(int(row['padded_slots']) != b-1 for row in rows):
            raise ValueError(f'{path}: incorrect NULL padded-slot count')
        if any(row.get('old_root') != rows[0].get('old_root') for row in rows):
            raise ValueError(f'{path}: independent trials do not share a starting root')
    elif op == 'update':
        if 'old_root' in headers and 'new_root' in headers:
            for i in range(1, len(rows)):
                if rows[i]['old_root'] != rows[i-1]['new_root']:
                    raise ValueError(f'{path}: sequential root chain broken at row {i+1}')
    # Check all numeric metrics and proof size values, without altering them.
    for h in headers:
        if h.endswith(METRIC_SUFFIXES):
            for rownum, row in enumerate(rows, 2):
                val = row.get(h, '')
                if val == '' or not math.isfinite(float(val)) or float(val) < 0:
                    raise ValueError(f'{path}:{rownum}: invalid measurement {h}={val!r}')
    trial_field = 'trial' if op == 'insert' else 'operation'
    if trial_field in headers:
        indexes = [r[trial_field] for r in rows]
        if indexes != [str(i) for i in range(1, expected+1)]:
            raise ValueError(f'{path}: trial index sequence not 1..{expected}')
    return headers, rows, Counter(row.get('category', op) for row in rows)


def summary_row(series, cfg, op, category, metric):
    vals = series
    result = {
        'configuration': cfg, 'fanout': cfg.split('_')[0], 'depth': cfg.split('_')[1],
        'leaf_count': int(cfg.split('_')[0]) ** int(cfg.split('_')[1]),
        'benchmark_type': op, 'category': category, 'metric': metric,
        'unit': 'milliseconds' if metric.endswith('_ms') else 'bytes',
        'n': len(vals), 'mean': statistics.mean(vals),
        'sample_sd': statistics.stdev(vals) if len(vals) > 1 else 0.0,
        'median': statistics.median(vals), 'minimum': min(vals),
        'p95': quantile(vals, 0.95), 'p99': quantile(vals, 0.99),
        'maximum': max(vals), 'sum': sum(vals)
    }
    return result


def quantile(seq, q):
    ordered = sorted(seq)
    p = q * (len(ordered)-1)
    lo = int(p)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] * (hi-p) + ordered[hi] * (p-lo)


def write_csv(path, headers, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8', newline='') as output:
        writer = csv.DictWriter(output, fieldnames=headers, extrasaction='raise', restval='')
        writer.writeheader()
        writer.writerows(data)


def collect_build_rows(run_dir, root, configs):
    construction = []
    for cfg in configs:
        b, d = map(int, cfg.split('_'))
        directory = root if cfg == '5_3' else root / cfg
        json_path = directory / f'leaf_values_{cfg}.jsonl'
        pickle_path = directory / f'merkle_tree_{cfg}.pkl'
        meta_path = run_dir / 'construction' / f'{cfg}.json'
        record = {}
        if meta_path.exists():
            record = json.loads(meta_path.read_text(encoding='utf-8'))
        construction.append({
            'configuration': cfg, 'fanout': b, 'depth': d, 'leaf_count': b**d,
            'status': record.get('status', 'historical/no record'),
            'constructed_this_run': record.get('constructed_this_run', False),
            'construction_wall_seconds': record.get('construction_wall_seconds', ''),
            'construction_hashing_seconds': record.get('construction_hashing_seconds', ''),
            'merkle_root_if_logged': record.get('merkle_root_if_logged', ''),
            'jsonl_bytes': json_path.stat().st_size if json_path.exists() else '',
            'pickle_bytes': pickle_path.stat().st_size if pickle_path.exists() else '',
            'construction_log': record.get('construction_log', ''),
        })
    return construction


def main():
    args = options_parser().parse_args()
    if args.runs < 8 or args.runs % 8:
        raise SystemExit('--runs must be a multiple of 8, >=8')
    if args.check_one:
        op, cfg = classify_file(args.check_one)
        if args.configuration and cfg != args.configuration:
            raise SystemExit('File configuration does not match --configuration')
        _, rows, _ = inspect_csv(args.check_one, op, cfg, args.runs)
        print(f'VALIDATED {op} {cfg}: {len(rows)} rows, all verified')
        return
    run_dir = args.run_dir.expanduser().resolve()
    root = args.root.expanduser().resolve() if args.root else run_dir.parent.parent
    configs = list(dict.fromkeys(args.only or CONFIGS))
    operations = [part.strip() for part in args.operations.split(',') if part.strip()]
    if not operations or len(operations) != len(set(operations)) or any(op not in OPS for op in operations):
        raise SystemExit('Select distinct operations from read,update,insert')
    out = run_dir / 'consolidated'
    out.mkdir(parents=True, exist_ok=True)
    if args.import_existing:
        if not args.root:
            raise ValueError('--import-existing requires --root')
        for cfg in configs:
            directory = root if cfg == '5_3' else root / cfg
            for op in operations:
                source = directory / f'{op}_benchmark_{cfg}.csv'
                destination = run_dir / 'raw' / cfg / source.name
                if not source.is_file():
                    raise ValueError(f'Missing preexisting result: {source}')
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
        env = run_dir / 'environment.txt'
        if not env.exists():
            env.write_text(f'imported_existing_results=true\nsource_root={root}\n', encoding='utf-8')
    inputs = []
    all_headers = set()
    n_all = 0
    tally_rows, metric_rows, validated = [], [], []
    per_op = {op: [] for op in operations}
    joined = []
    starting_roots = defaultdict(dict)
    for cfg in configs:
        for op in operations:
            p = run_dir / 'raw' / cfg / f'{op}_benchmark_{cfg}.csv'
            headers, rows, categories = inspect_csv(p, op, cfg, args.runs)
            all_headers.update('data_' + h for h in headers)
            inputs.append(p)
            if op in ('update', 'insert') and 'old_root' in headers:
                starting_roots[cfg][op] = rows[0]['old_root']
            validated.append({'configuration': cfg, 'benchmark_type': op,
                              'rows': len(rows), 'all_verified': True,
                              'sha256': sha256_file(p), 'source_path': str(p)})
            for cat, n in sorted(categories.items()):
                tally_rows.append({'configuration': cfg, 'benchmark_type': op, 'category': cat, 'runs': n})
            metric_names = [h for h in headers if h.endswith(METRIC_SUFFIXES)]
            for cat in ['ALL'] + (list(categories) if op == 'read' else []):
                filtered = rows if cat == 'ALL' else [r for r in rows if r['category'] == cat]
                for metric in metric_names:
                    metric_rows.append(summary_row([float(r[metric]) for r in filtered], cfg, op, cat, metric))
            b, d = map(int, cfg.split('_'))
            for i, row in enumerate(rows, 1):
                original_index = row.get('trial' if op == 'insert' else 'operation', i)
                merged = {
                    'suite_run_id': run_dir.name, 'configuration': cfg,
                    'fanout': b, 'depth': d, 'leaf_count': b**d,
                    'benchmark_type': op, 'trial_index': original_index,
                    'source_row': i + 1, 'source_file': str(p.relative_to(run_dir)),
                    'category': row.get('category', op),
                }
                merged.update({'data_' + k: v for k, v in row.items()})
                joined.append(merged)
                per_op[op].append(merged)
                n_all += 1
    for cfg, root_by_operation in starting_roots.items():
        if len(set(root_by_operation.values())) > 1:
            raise ValueError(f'{cfg}: update/insert benchmarks use different initial roots: {root_by_operation}')
    wide_headers = list(META_COLUMNS) + sorted(all_headers)
    write_csv(out / 'all_trials.csv', wide_headers, joined)
    for op, rows in per_op.items():
        write_csv(out / f'{op}_trials.csv', wide_headers, rows)
    write_csv(out / 'metric_statistics.csv', list(metric_rows[0]), metric_rows)
    write_csv(out / 'category_counts.csv', list(tally_rows[0]), tally_rows)
    build_rows = collect_build_rows(run_dir, root, configs)
    write_csv(out / 'construction_summary.csv', list(build_rows[0]), build_rows)
    # Exact source files are preserved in raw/. File hashes allow audit later.
    file_rows = []
    for p in sorted(inputs):
        file_rows.append({'path': str(p.relative_to(run_dir)), 'bytes': p.stat().st_size,
                          'sha256': sha256_file(p), 'kind': 'raw benchmark CSV'})
    for cfg in configs:
        p = run_dir / 'construction' / f'{cfg}.json'
        if p.is_file():
            file_rows.append({'path': str(p.relative_to(run_dir)), 'bytes': p.stat().st_size,
                              'sha256': sha256_file(p), 'kind': 'construction metadata'})
    write_csv(out / 'files_manifest.csv', list(file_rows[0]), file_rows)
    validation = {
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'run_id': run_dir.name, 'root': str(root),
        'expected_trials_per_config_operation': args.runs,
        'operations': operations, 'configurations': configs,
        'validated_sources': validated,
        'total_trial_rows': n_all,
        'all_trial_columns': wide_headers,
        'all_original_source_fields_preserved': True,
        'numeric_summary_fields': ['n','mean','sample_sd','median','minimum','p95','p99','maximum','sum'],
        'note': 'Construction was measured once per build; missing prior build time is not fabricated.'
    }
    (out / 'validation_report.json').write_text(json.dumps(validation, indent=2), encoding='utf-8')
    print(f'PASS: {len(validated)} CSVs, {n_all} individual trial records, '
          f'{len(metric_rows)} metric summaries')
    print(f'Complete, original-column-preserving rows: {out / "all_trials.csv"}')
    print(f'Construction metadata: {out / "construction_summary.csv"}')
    print(f'Validation: {out / "validation_report.json"}')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, csv.Error) as exc:
        print(f'CONSOLIDATION FAILED: {exc}', file=sys.stderr)
        sys.exit(1)
