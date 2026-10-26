#!/usr/bin/env python3
"""Independent one-key end-append insertion benchmark for saved, FULL b-ary Merkle trees.

Run inside the directory containing merkle_b_d.py, leaf_values_b_d.jsonl,
merkle_tree_b_d.pkl:
    python3 benchmark_insert.py --runs 1000

Each trial starts from the SAME old trusted Merkle root. Insert a new key
GREATER than the previous maximum, with b-1 domain-separated NULL leaves.
A fully occupied b^d-leaf tree needs a new root (depth d+1). Only a single
new JSONL string line is physically appended to an isolated working copy;
NULL pads are NOT JSONL records. The working file is rolled back between
independent trials (rollback excluded from timings); original input files
remain unchanged. This is an append-insertion benchmark, not arbitrary-rank
sorted insertion, B+ splitting, or 1000 cumulative inserts.

Proof includes: old maximum-key membership at position b^d-1, new key+text,
new-root, and full new-leaf path with canonical NULL hashes and old root.
Verification only trusts original root, fanout, depth, sorted-tree invariant.

Only load locally generated/trusted pickle files.
"""

import argparse
import csv
import hashlib
import importlib
import json
import os
import random
import shutil
import statistics
import tempfile
import time
from bisect import bisect_left
from pathlib import Path

KEY_BYTES = 13
MAX_KEY = 2**100
HASH_BYTES = 32
NULL_LEAF = hashlib.sha256(b'\x03').digest()

COLUMNS = [
    'trial', 'fanout', 'old_depth', 'new_depth', 'old_leaf_count',
    'new_real_leaf_count', 'padded_slots', 'new_key', 'old_max_key',
    'search_ms', 'jsonl_append_ms', 'proof_ms', 'total_insert_ms',
    'verification_ms', 'proof_bytes', 'old_root', 'new_root', 'verified',
]


def derive_value(key, text):
    msg = text.encode('utf-8')
    return hashlib.sha256(
        b'\x02' + key.to_bytes(KEY_BYTES, 'big')
        + len(msg).to_bytes(4, 'big') + msg
    ).digest()


def hash_leaf(key, value):
    return hashlib.sha256(
        b'\x00' + key.to_bytes(KEY_BYTES, 'big')
        + len(value).to_bytes(4, 'big') + value
    ).digest()


def hash_internal(children, fanout):
    if len(children) != fanout or any(len(x) != HASH_BYTES for x in children):
        raise ValueError('Incorrect internal-node children')
    return hashlib.sha256(b'\x01' + b''.join(children)).digest()


def empty_hashes(fanout, depth):
    result = [NULL_LEAF]
    for _ in range(depth):
        result.append(hash_internal([result[-1]] * fanout, fanout))
    return result


def old_path(state, index):
    fanout = state['branching_factor']
    result = []
    for level in range(state['depth']):
        start = (index // fanout) * fanout
        position = index % fanout
        nodes = state['levels'][level]
        siblings = [(p, nodes[start + p]) for p in range(fanout) if p != position]
        result.append((position, siblings))
        index //= fanout
    return result


def calculate_path_root(digest, path, fanout):
    index = 0
    scale = 1
    for position, siblings in path:
        if not (0 <= position < fanout) or len(siblings) != fanout - 1:
            raise ValueError('Invalid Merkle path')
        children = [None] * fanout
        children[position] = digest
        for p, sibling_hash in siblings:
            if not (0 <= p < fanout) or children[p] is not None:
                raise ValueError('Duplicate/invalid sibling position')
            if not isinstance(sibling_hash, bytes) or len(sibling_hash) != 32:
                raise ValueError('Bad sibling digest')
            children[p] = sibling_hash
        if any(x is None for x in children):
            raise ValueError('Incomplete path')
        digest = hash_internal(children, fanout)
        index += position * scale
        scale *= fanout
    return digest, index


def construct_insert_proof(state, new_key, new_text, maximum_path):
    fanout, depth = state['branching_factor'], state['depth']
    n = state['leaf_count']
    if n != fanout**depth or new_key <= state['keys'][-1] or new_key > MAX_KEY:
        raise ValueError('This benchmark supports sorted append to a full tree only')

    empties = empty_hashes(fanout, depth)
    node = hash_leaf(new_key, derive_value(new_key, new_text))
    new_path = []
    # A group of exactly b slots: one real new leaf plus (b-1) NULL leaves.
    # The group is extended to the old tree's height with empty subtrees.
    for height in range(depth):
        siblings = [(i, empties[height]) for i in range(1, fanout)]
        new_path.append((0, siblings))
        node = hash_internal([node] + [empties[height]] * (fanout - 1), fanout)

    # Old completely occupied tree is child 0 of the newly created root;
    # the inserted subtree is child 1; all other children are NULL subtrees.
    new_path.append((1, [(0, state['root'])] + [
        (i, empties[depth]) for i in range(2, fanout)
    ]))
    new_root = hash_internal(
        [state['root'], node] + [empties[depth]] * (fanout - 2), fanout
    )
    return {
        'new_key': new_key, 'new_text': new_text,
        'new_root': new_root, 'new_path': new_path,
        'old_max_key': state['keys'][-1],
        'old_max_value': state['key_value_db'][state['keys'][-1]],
        'old_max_path': maximum_path,
    }


def verify_insert_proof(response, old_root, fanout, old_depth):
    try:
        n = fanout**old_depth
        new_key = response['new_key']
        old_max_key = response['old_max_key']
        if not (0 < old_max_key < new_key <= MAX_KEY):
            return False
        if len(response['old_max_path']) != old_depth:
            return False
        if len(response['new_path']) != old_depth + 1:
            return False
        digest, index = calculate_path_root(
            hash_leaf(old_max_key, response['old_max_value']),
            response['old_max_path'], fanout
        )
        if digest != old_root or index != n - 1:
            return False

        empties = empty_hashes(fanout, old_depth)
        for height, (position, siblings) in enumerate(response['new_path']):
            if height < old_depth:
                expected = (0, [(p, empties[height]) for p in range(1, fanout)])
            else:
                expected = (1, [(0, old_root)] + [
                    (p, empties[old_depth]) for p in range(2, fanout)
                ])
            if (position, siblings) != expected:
                return False

        new_value = derive_value(new_key, response['new_text'])
        actual_root, new_index = calculate_path_root(
            hash_leaf(new_key, new_value), response['new_path'], fanout
        )
        return (new_index == n and actual_root == response['new_root']
                and actual_root != old_root)
    except (KeyError, ValueError, TypeError, IndexError, OverflowError):
        return False


def encode_path(path, fanout):
    data = bytearray()
    for position, siblings in path:
        if len(siblings) != fanout - 1:
            raise ValueError('Invalid path')
        data.append(position)
        for sibling_position, digest in siblings:
            data.append(sibling_position)
            data.extend(digest)
    return bytes(data)


def serialize_proof(response, fanout, old_depth):
    """Complete wire response; trusted old root/fanout/depth are out of band."""
    text = response['new_text'].encode('utf-8')
    if len(text) > 2**32 - 1:
        raise ValueError('Text too long')
    return (
        bytes((1, ord('I'), fanout, old_depth + 1))
        + response['new_key'].to_bytes(KEY_BYTES, 'big')
        + len(text).to_bytes(4, 'big') + text
        + response['old_max_key'].to_bytes(KEY_BYTES, 'big')
        + response['old_max_value']
        + response['new_root']
        + encode_path(response['old_max_path'], fanout)
        + encode_path(response['new_path'], fanout)
    )


def last_jsonl_text(path):
    """Read only the last JSONL record for integrity checking."""
    with path.open('rb') as f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        if not end:
            raise ValueError('Empty JSONL')
        start = max(0, end - 4096)
        f.seek(start)
        tail = f.read()
    lines = tail.splitlines()
    if not lines or (start > 0 and len(lines) < 2):
        raise ValueError('Unusually long JSONL record; enlarge tail reader')
    text = json.loads(lines[-1])
    if not isinstance(text, str):
        raise ValueError('Expected JSON string')
    return text


def show_stats(rows, name, unit):
    vals = [r[name] for r in rows]
    print(f'{name:20s} {statistics.mean(vals):.6f} +/- {statistics.stdev(vals):.6f} {unit}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs', type=int, default=1000)
    parser.add_argument('--seed', type=int, default=20261026)
    args = parser.parse_args()
    if args.runs < 2:
        parser.error('At least two runs are needed to compute sample SD')

    base = Path(__file__).resolve().parent
    # Derive fanout/depth from saved file names; script is reusable across folders.
    candidates = sorted(base.glob('merkle_tree_*_*.pkl'))
    if len(candidates) != 1:
        parser.error('Expected exactly one merkle_tree_b_d.pkl in this folder')
    stem = candidates[0].stem
    try:
        _, _, b_s, d_s = stem.split('_')
        fanout, depth = int(b_s), int(d_s)
    except Exception as exc:
        raise RuntimeError(f'Unexpected pickle filename: {stem}') from exc
    mod = importlib.import_module(f'merkle_{fanout}_{depth}')
    state = mod.load_tree_pickle()  # trusts locally generated pickle
    json_path = base / f'leaf_values_{fanout}_{depth}.jsonl'
    csv_path = base / f'insert_benchmark_{fanout}_{depth}.csv'
    n = fanout**depth
    if state['root'] != state['levels'][-1][0] or state['leaf_count'] != n:
        raise ValueError('Loaded pickle has unexpected root/leaf count')
    if state['keys'][-1] >= MAX_KEY:
        raise ValueError('No larger key available for append insertion')
    original_text = last_jsonl_text(json_path)
    max_key = state['keys'][-1]
    if derive_value(max_key, original_text) != state['key_value_db'][max_key]:
        raise ValueError('Last JSONL record does not match authenticated max key')
    max_path = old_path(state, n-1)
    root, idx = calculate_path_root(hash_leaf(max_key, state['key_value_db'][max_key]), max_path, fanout)
    if root != state['root'] or idx != n-1:
        raise ValueError('Old maximum membership cannot be verified')
    old_root = state['root']
    rng = random.Random(args.seed)
    rows = []
    print(f'Loaded {fanout}^{depth}: {n:,} real leaves; root={old_root.hex()}')
    print('Independent append-insertion trials, not cumulative / arbitrary-position inserts.')

    with tempfile.TemporaryDirectory(prefix='.insert_benchmark_', dir=base) as tmp:
        working = Path(tmp) / json_path.name
        shutil.copyfile(json_path, working)  # once, not timed
        original_size = working.stat().st_size
        # Keep a working file handle and explicitly sync the appended data.
        for i in range(args.runs):
            new_key = max_key + 1 + rng.randrange(MAX_KEY - max_key)
            text = f'this is inserted leaf {i+1}'
            line = (json.dumps(text, ensure_ascii=False) + '\n').encode('utf-8')

            start = time.perf_counter_ns()
            insertion_index = bisect_left(state['keys'], new_key)
            search_ms = (time.perf_counter_ns() - start) / 1_000_000
            if insertion_index != n:
                raise RuntimeError('Insertion key would violate sorted order')

            start = time.perf_counter_ns()
            with working.open('ab') as file:
                file.write(line)
                file.flush()
                os.fsync(file.fileno())
            file_ms = (time.perf_counter_ns() - start) / 1_000_000

            start = time.perf_counter_ns()
            trial_max_path = old_path(state, n - 1)
            response = construct_insert_proof(state, new_key, text, trial_max_path)
            proof_ms = (time.perf_counter_ns() - start) / 1_000_000

            start = time.perf_counter_ns()
            valid = verify_insert_proof(response, old_root, fanout, depth)
            verify_ms = (time.perf_counter_ns() - start) / 1_000_000
            if not valid:
                raise AssertionError(f'Insertion proof {i+1} failed')

            wire_size = len(serialize_proof(response, fanout, depth))
            # Untimed rollback: every trial begins with the same FULL baseline.
            with working.open('r+b') as file:
                file.truncate(original_size)
                file.flush()
                os.fsync(file.fileno())

            rows.append({
                'trial': i+1, 'fanout': fanout, 'old_depth': depth,
                'new_depth': depth+1, 'old_leaf_count': n,
                'new_real_leaf_count': n+1, 'padded_slots': fanout-1,
                'new_key': new_key, 'old_max_key': max_key,
                'search_ms': search_ms, 'jsonl_append_ms': file_ms,
                'proof_ms': proof_ms,
                'total_insert_ms': search_ms + file_ms + proof_ms,
                'verification_ms': verify_ms, 'proof_bytes': wire_size,
                'old_root': old_root.hex(), 'new_root': response['new_root'].hex(),
                'verified': valid,
            })
            if (i+1) % 100 == 0:
                print(f'Verified {i+1}/{args.runs} insertions', flush=True)
        assert working.stat().st_size == original_size

    # Simple negative proof checks, outside timings.
    bad = dict(response, new_root=b'\x00' * 32)
    assert not verify_insert_proof(bad, old_root, fanout, depth)
    bad = dict(response, new_key=max_key)
    assert not verify_insert_proof(bad, old_root, fanout, depth)

    with csv_path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    print(f'\nMERKLE TREE APPEND-INSERT BENCHMARK ({fanout}^{depth})')
    print(f'Original real leaves: {n:,}; after each insert: {n+1:,}')
    print(f'New leaf block: one real key plus {fanout-1} authenticated NULL slots')
    print(f'Root depth: {depth} -> {depth+1}')
    print(f'Runs: {len(rows)}; each trial starts from the same saved root')
    print('TIMINGS (milliseconds, mean +/- sample SD)')
    for metric in ('search_ms', 'jsonl_append_ms', 'proof_ms', 'total_insert_ms', 'verification_ms'):
        show_stats(rows, metric, 'ms')
    show_stats(rows, 'proof_bytes', 'bytes')
    print('Original JSONL/pickle were NOT modified.')
    print('Untimed: copy/reset, sampling, load, wire encoding, CSV writing.')
    print('CSV:', csv_path.name)
    print(f'All {len(rows)} independently verified append-insertion trials passed.')


if __name__ == '__main__':
    main()
