"""Benchmark 7^9 Merkle-tree membership/non-membership reads.

Run: python3 read_7_9.py                 # 500 present + 500 absent
     python3 read_7_9.py --per-type 100

Requires, in this same folder:
    merkle_7_9.py
    leaf_values_7_9.jsonl
    merkle_tree_7_9.pkl

Output:
    read_benchmark_7_9.csv : one row per query

Read time = search time + proof construction time. Verification is independent.
All file loading, initial validation, sampling, serialization and CSV writing
are outside the timed operations. Searches are IN MEMORY over the loaded tree
and memory-mapped JSONL; page faults may occur during timed reads. JSON decoding is included in the
7^9 membership search time, unlike the pre-decoded 5^3/5^6 text lists.

Wire format (big-endian integers), consistent with the 5^3 benchmark:
  header = [version:1][type:'M' or 'N':1][fanout:1][depth:1]
  membership = header + key:13 + text_length:4 + UTF8(text) + path
  nonmembership = header + flags:1 + each boundary(key:13 + value:32 + path)
  path = for each level (leaf to root): child_position:1,
         then fanout-1 (sibling_position:1 + SHA256_digest:32) entries.
The query key and trusted Merkle root are known to the verifier and not sent.
A 7^9 membership path is 9*(1+6*(1+32)) = 1791 bytes.

Nonmembership relies on a correctly sorted committed key sequence; a plain
Merkle root by itself does not certify global sorting.
Do not unpickle files from untrusted sources.
"""

import argparse
import csv
import json
from array import array
import mmap
import random
import statistics
import time
from bisect import bisect_left
from pathlib import Path

import merkle_7_9 as merkle

WIRE_VERSION = 1
CSV_FILE = Path(__file__).resolve().parent / 'read_benchmark_7_9.csv'
CSV_COLUMNS = [
    'operation', 'category', 'query_key', 'leaf_index',
    'predecessor_key', 'successor_key', 'search_ms', 'proof_ms',
    'total_read_ms', 'verification_ms', 'proof_bytes', 'verified'
]


class CompactJsonlStore:
    """Index JSONL lines using an mmap and 32-bit byte offsets.

    mmap does not copy the ~957 MB JSONL into a Python bytes object.
    The offsets require about 154 MiB (40,353,608 * 4 bytes).
    Text is decoded only when a membership record is requested.
    Index building happens before the timed operations.
    """

    def __init__(self, file_path, count):
        self.handle = file_path.open('rb')
        try:
            self.data = mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_READ)
            if len(self.data) >= 2**32:
                raise ValueError('JSONL exceeds 4 GiB, requiring 64-bit offsets')

            self.offsets = array('I', [0])
            cursor = 0
            while True:
                newline = self.data.find(b'\n', cursor)
                if newline < 0:
                    if cursor != len(self.data):
                        self.offsets.append(len(self.data))
                    break
                cursor = newline + 1
                self.offsets.append(cursor)

            if len(self.offsets) != count + 1:
                raise ValueError(
                    f'Expected {count} JSONL lines; got {len(self.offsets)-1}'
                )
        except BaseException:
            if hasattr(self, 'data'):
                self.data.close()
            self.handle.close()
            raise

    def __getitem__(self, index):
        if not 0 <= index < len(self):
            raise IndexError('JSONL line index out of range')
        start, end = self.offsets[index], self.offsets[index + 1]
        text = json.loads(self.data[start:end])
        if not isinstance(text, str):
            raise ValueError('JSONL value must be a string')
        return text

    def __len__(self):
        return len(self.offsets) - 1

    def close(self):
        self.data.close()
        self.handle.close()


# ---------------------------------------------------------------------------
# Proof construction: fetch siblings from the precomputed node levels, on demand
# ---------------------------------------------------------------------------

def generate_path_from_saved_tree_index(state, leaf_index):
    b = state['branching_factor']
    proof = []
    index = leaf_index
    for level in range(state['depth']):
        hashes = state['levels'][level]
        group_start = (index // b) * b
        child_position = index % b
        siblings = [
            (position, hashes[group_start + position])
            for position in range(b) if position != child_position
        ]
        proof.append((child_position, siblings))
        index //= b
    return proof


def generate_path_from_saved_tree(state, key):
    return generate_path_from_saved_tree_index(state, state['key_to_index'][key])


def search_present(state, texts, query_key):
    index = state['key_to_index'].get(query_key)
    if index is None:
        raise KeyError(f'Key is absent: {query_key}')
    return index, texts[index]


def prove_present(state, query_key, search_result):
    index, text = search_result
    return {
        'key': query_key,
        'text': text,
        'proof': generate_path_from_saved_tree_index(state, index)
    }


def search_absent(state, query_key):
    keys = state['keys']
    records = state['key_value_db']
    index = bisect_left(keys, query_key)
    if index < len(keys) and keys[index] == query_key:
        raise ValueError(f'Expected missing key, found stored key: {query_key}')
    predecessor = (keys[index - 1], records[keys[index - 1]], index - 1) if index else None
    successor = (keys[index], records[keys[index]], index) if index < len(keys) else None
    return predecessor, successor


def prove_absent(state, search_result):
    predecessor, successor = search_result
    return {
        'predecessor': (predecessor[0], predecessor[1]) if predecessor else None,
        'predecessor_proof': (
            generate_path_from_saved_tree_index(state, predecessor[2]) if predecessor else None
        ),
        'successor': (successor[0], successor[1]) if successor else None,
        'successor_proof': (
            generate_path_from_saved_tree_index(state, successor[2]) if successor else None
        )
    }


# ---------------------------------------------------------------------------
# Verifier: independent of the pickle, key index, sorted keys or JSONL store
# ---------------------------------------------------------------------------

def verify_membership_proof(key, derived_value, proof, trusted_root):
    b, depth = merkle.BRANCHING_FACTOR, merkle.TREE_DEPTH
    if not isinstance(key, int) or not 1 <= key <= merkle.KEY_UNIVERSE:
        return False
    if not isinstance(derived_value, bytes) or len(derived_value) != 32:
        return False
    if not isinstance(trusted_root, bytes) or len(trusted_root) != 32:
        return False
    if not isinstance(proof, list) or len(proof) != depth:
        return False

    current_hash = merkle.hash_leaf(key, derived_value)
    for level in proof:
        try:
            child_position, siblings = level
            if not isinstance(child_position, int) or not 0 <= child_position < b:
                return False
            if len(siblings) != b - 1:
                return False
            children = [None] * b
            children[child_position] = current_hash
            for position, digest in siblings:
                if not isinstance(position, int) or not 0 <= position < b:
                    return False
                if children[position] is not None:
                    return False
                if not isinstance(digest, bytes) or len(digest) != 32:
                    return False
                children[position] = digest
            if any(digest is None for digest in children):
                return False
            current_hash = merkle.hash_internal(children)
        except (TypeError, ValueError, IndexError):
            return False
    return current_hash == trusted_root


def authenticated_index(path):
    if len(path) != merkle.TREE_DEPTH:
        raise ValueError('Invalid number of authentication levels')
    index = 0
    for level, (position, _) in enumerate(path):
        if not isinstance(position, int) or not 0 <= position < merkle.BRANCHING_FACTOR:
            raise ValueError('Invalid authentication position')
        index += position * (merkle.BRANCHING_FACTOR ** level)
    return index


def verify_present(query_key, response, trusted_root):
    if response['key'] != query_key:
        return False  # Bind proof to the *requested* key
    value = merkle.derive_value(query_key, response['text'])
    return verify_membership_proof(query_key, value, response['proof'], trusted_root)


def verify_absent(query_key, response, trusted_root):
    if not 1 <= query_key <= merkle.KEY_UNIVERSE:
        return False
    predecessor, successor = response['predecessor'], response['successor']
    pred_proof, succ_proof = response['predecessor_proof'], response['successor_proof']
    if predecessor is None and successor is None:
        return False
    if (predecessor is None) != (pred_proof is None):
        return False
    if (successor is None) != (succ_proof is None):
        return False

    pred_index = succ_index = None
    if predecessor is not None:
        pred_key, pred_value = predecessor
        if pred_key >= query_key or not verify_membership_proof(
            pred_key, pred_value, pred_proof, trusted_root
        ):
            return False
        pred_index = authenticated_index(pred_proof)

    if successor is not None:
        succ_key, succ_value = successor
        if succ_key <= query_key or not verify_membership_proof(
            succ_key, succ_value, succ_proof, trusted_root
        ):
            return False
        succ_index = authenticated_index(succ_proof)

    if predecessor is None:  # Before the first committed leaf
        return succ_index == 0
    if successor is None:  # After the last committed leaf
        return pred_index == merkle.NUMBER_OF_RECORDS - 1
    return succ_index == pred_index + 1  # Authenticated adjacent keys


# ---------------------------------------------------------------------------
# Compact binary proof-response encoding; measured OUTSIDE timing windows
# ---------------------------------------------------------------------------

def encode_path(path, b, depth):
    if len(path) != depth:
        raise ValueError('Invalid path depth')
    result = bytearray()
    for position, siblings in path:
        if not 0 <= position < b or len(siblings) != b - 1:
            raise ValueError('Invalid path level')
        result.append(position)
        seen = {position}
        for sibling_position, digest in siblings:
            if sibling_position in seen or not 0 <= sibling_position < b:
                raise ValueError('Invalid sibling index')
            if not isinstance(digest, bytes) or len(digest) != 32:
                raise ValueError('Incorrect digest length')
            seen.add(sibling_position)
            result.append(sibling_position)
            result.extend(digest)
        if len(seen) != b:
            raise ValueError('Incomplete siblings')
    return bytes(result)


def encode_key(key):
    if not 1 <= key <= merkle.KEY_UNIVERSE:
        raise ValueError('Key out of range')
    return key.to_bytes(merkle.KEY_LENGTH_BYTES, 'big')


def serialize_present(response, b, depth):
    text_bytes = response['text'].encode('utf-8')
    return (
        bytes((WIRE_VERSION, ord('M'), b, depth))
        + encode_key(response['key'])
        + len(text_bytes).to_bytes(4, 'big')
        + text_bytes
        + encode_path(response['proof'], b, depth)
    )


def serialize_absent(response, b, depth):
    pred, succ = response['predecessor'], response['successor']
    if pred is None and succ is None:
        raise ValueError('Both boundaries absent')
    flags = (1 if pred else 0) | (2 if succ else 0)
    result = bytearray((WIRE_VERSION, ord('N'), b, depth, flags))
    for label in ('predecessor', 'successor'):
        record = response[label]
        if record is None:
            continue
        key, value = record
        if len(value) != 32:
            raise ValueError('Invalid value size')
        result.extend(encode_key(key))
        result.extend(value)
        result.extend(encode_path(response[label + '_proof'], b, depth))
    return bytes(result)


class WireReader:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def take(self, count):
        if count < 0 or self.offset + count > len(self.data):
            raise ValueError('Truncated serialized proof')
        result = self.data[self.offset:self.offset + count]
        self.offset += count
        return result

    def finish(self):
        if self.offset != len(self.data):
            raise ValueError('Unexpected trailing proof bytes')


def decode_path(reader, b, depth):
    proof = []
    for _ in range(depth):
        position = reader.take(1)[0]
        siblings = [
            (reader.take(1)[0], reader.take(32)) for _ in range(b - 1)
        ]
        if sorted([position] + [p for p, _ in siblings]) != list(range(b)):
            raise ValueError('Malformed serialized path')
        proof.append((position, siblings))
    return proof


def deserialize_present(data):
    reader = WireReader(data)
    if tuple(reader.take(4)) != (WIRE_VERSION, ord('M'), merkle.BRANCHING_FACTOR, merkle.TREE_DEPTH):
        raise ValueError('Bad membership wire header')
    key = int.from_bytes(reader.take(merkle.KEY_LENGTH_BYTES), 'big')
    text_bytes = reader.take(int.from_bytes(reader.take(4), 'big'))
    response = {
        'key': key,
        'text': text_bytes.decode('utf-8'),
        'proof': decode_path(reader, merkle.BRANCHING_FACTOR, merkle.TREE_DEPTH)
    }
    reader.finish()
    return response


def deserialize_absent(data):
    reader = WireReader(data)
    if tuple(reader.take(4)) != (WIRE_VERSION, ord('N'), merkle.BRANCHING_FACTOR, merkle.TREE_DEPTH):
        raise ValueError('Bad non-membership wire header')
    flags = reader.take(1)[0]
    if flags not in (1, 2, 3):
        raise ValueError('Invalid boundary flags')
    response = {}
    for label, bit in (('predecessor', 1), ('successor', 2)):
        if flags & bit:
            key = int.from_bytes(reader.take(merkle.KEY_LENGTH_BYTES), 'big')
            value = reader.take(32)
            path = decode_path(reader, merkle.BRANCHING_FACTOR, merkle.TREE_DEPTH)
            response[label] = (key, value)
            response[label + '_proof'] = path
        else:
            response[label] = None
            response[label + '_proof'] = None
    reader.finish()
    return response


# ---------------------------------------------------------------------------
# Query generation; 125 for each of the 4 nonmembership cases (default)
# ---------------------------------------------------------------------------

def sample_absent_queries(keys, count_per_case, seed):
    """Sample four non-membership categories without building huge gap lists."""
    rng = random.Random(seed)
    b = merkle.BRANCHING_FACTOR
    universe = merkle.KEY_UNIVERSE
    n = len(keys)

    if keys[0] - 1 < count_per_case or universe - keys[-1] < count_per_case:
        raise ValueError('Insufficient key space for boundary queries')

    def sample_large_interval(lo, hi, count):
        selected = set()
        while len(selected) < count:
            selected.add(rng.randrange(lo, hi))
        values = list(selected)
        rng.shuffle(values)
        return values

    def interior_indices(same_parent, count):
        indices = set()
        # Include boundaries between progressively larger subtrees as case-3 tests.
        if not same_parent:
            for height in range(2, merkle.TREE_DEPTH):
                i = b**height - 1
                if i < n - 1 and keys[i] + 1 < keys[i + 1]:
                    indices.add(i)

        while len(indices) < count:
            i = rng.randrange(n - 1)
            is_same = (i // b == (i + 1) // b)
            if is_same != same_parent:
                continue
            if keys[i] + 1 >= keys[i + 1]:
                continue
            indices.add(i)

        if len(indices) > count:
            indices = set(rng.sample(sorted(indices), count))
        return list(indices)

    same = interior_indices(True, count_per_case)
    different = interior_indices(False, count_per_case)
    results = {
        'Case 1 (before first)': sample_large_interval(1, keys[0], count_per_case),
        'Case 2 (same parent)': [
            rng.randrange(keys[i] + 1, keys[i + 1]) for i in same
        ],
        'Case 3 (different subtrees)': [
            rng.randrange(keys[i] + 1, keys[i + 1]) for i in different
        ],
        'Case 4 (after last)': sample_large_interval(keys[-1] + 1, universe + 1, count_per_case)
    }
    for values in results.values():
        rng.shuffle(values)
    return results


# ---------------------------------------------------------------------------
# Per-query timings and CSV fields
# ---------------------------------------------------------------------------

def benchmark_one_present(state, texts, key):
    t0 = time.perf_counter_ns()
    located = search_present(state, texts, key)
    t1 = time.perf_counter_ns()
    response = prove_present(state, key, located)
    t2 = time.perf_counter_ns()
    verified = verify_present(key, response, state['root'])
    t3 = time.perf_counter_ns()
    if not verified:
        raise AssertionError(f'Membership proof failed: {key}')

    proof_size = len(serialize_present(response, state['branching_factor'], state['depth']))
    search_ms = (t1 - t0) / 1_000_000
    proof_ms = (t2 - t1) / 1_000_000
    return {
        'category': 'Membership (present)',
        'query_key': key,
        'leaf_index': located[0],
        'predecessor_key': '',
        'successor_key': '',
        'search_ms': search_ms,
        'proof_ms': proof_ms,
        'total_read_ms': search_ms + proof_ms,
        'verification_ms': (t3 - t2) / 1_000_000,
        'proof_bytes': proof_size,
        'verified': verified
    }


def benchmark_one_absent(state, key, label):
    t0 = time.perf_counter_ns()
    located = search_absent(state, key)
    t1 = time.perf_counter_ns()
    response = prove_absent(state, located)
    t2 = time.perf_counter_ns()
    verified = verify_absent(key, response, state['root'])
    t3 = time.perf_counter_ns()
    if not verified:
        raise AssertionError(f'Non-membership proof failed: {key}')

    proof_size = len(serialize_absent(response, state['branching_factor'], state['depth']))
    search_ms = (t1 - t0) / 1_000_000
    proof_ms = (t2 - t1) / 1_000_000
    return {
        'category': label,
        'query_key': key,
        'leaf_index': '',
        'predecessor_key': located[0][0] if located[0] else '',
        'successor_key': located[1][0] if located[1] else '',
        'search_ms': search_ms,
        'proof_ms': proof_ms,
        'total_read_ms': search_ms + proof_ms,
        'verification_ms': (t3 - t2) / 1_000_000,
        'proof_bytes': proof_size,
        'verified': verified
    }


def stats(values):
    return statistics.mean(values), (statistics.stdev(values) if len(values) > 1 else 0.0)


def print_times(label, rows):
    def fmt(column):
        mean, sd = stats([r[column] for r in rows])
        return f'{mean:.6f} +/- {sd:.6f}'
    print(f'{label:<32} {len(rows):>5} '
          f"{fmt('search_ms'):>23} {fmt('proof_ms'):>23} "
          f"{fmt('total_read_ms'):>23} {fmt('verification_ms'):>23}")


def print_sizes(label, rows):
    sizes = [r['proof_bytes'] for r in rows]
    mean, sd = stats(sizes)
    print(f'{label:<32} {len(rows):>5} {mean:>12.3f} {sd:>12.3f} '
          f'{min(sizes):>9} {max(sizes):>9}')


def untimed_checks(state, texts, groups):
    # Membership wire roundtrip and query-binding negative test.
    first_key = state['keys'][0]
    membership = prove_present(state, first_key, search_present(state, texts, first_key))
    decoded = deserialize_present(serialize_present(membership, merkle.BRANCHING_FACTOR, merkle.TREE_DEPTH))
    assert decoded == membership and verify_present(first_key, decoded, state['root'])
    assert not verify_present(state['keys'][1], decoded, state['root'])
    tampered = dict(decoded)
    tampered['text'] = decoded['text'] + ' tampered'
    assert not verify_present(first_key, tampered, state['root'])

    # All four nonmembership case roundtrips.
    for queries in groups.values():
        query = queries[0]
        response = prove_absent(state, search_absent(state, query))
        decoded = deserialize_absent(serialize_absent(response, merkle.BRANCHING_FACTOR, merkle.TREE_DEPTH))
        assert decoded == response and verify_absent(query, decoded, state['root'])

    # Test interior adjacency crossing grandparent / higher-level boundaries.
    for height in range(2, merkle.TREE_DEPTH):
        span = merkle.BRANCHING_FACTOR ** height
        i = span - 1
        if state['keys'][i] + 1 < state['keys'][i + 1]:
            query = state['keys'][i] + 1
            response = prove_absent(state, search_absent(state, query))
            assert verify_absent(query, response, state['root'])
            assert authenticated_index(response['predecessor_proof']) == i
            assert authenticated_index(response['successor_proof']) == i + 1

    # A stored key must not be accepted as missing.
    query = groups['Case 2 (same parent)'][0]
    absent = prove_absent(state, search_absent(state, query))
    assert not verify_absent(absent['predecessor'][0], absent, state['root'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--per-type', type=int, default=500,
                        help='Membership and nonmembership queries EACH (default 500)')
    parser.add_argument('--seed', type=int, default=2026)
    parser.add_argument('--validate-all', action='store_true',
                        help='Rehash all 40,353,607 leaves and internal nodes before benchmarking')
    args = parser.parse_args()
    if args.per_type < 8 or args.per_type % 4:
        parser.error('--per-type must be a multiple of 4 (minimum 8)')
    if not merkle.TREE_PICKLE_FILE.is_file() or not merkle.LEAF_VALUES_FILE.is_file():
        parser.error('Run python3 merkle_7_9.py to generate the pickle and JSONL')

    # Full validation already occurred at construction. Loading + optional
    # full revalidation are outside all timed queries.
    print('Loading saved 7^9 tree (pickle ~4.21 GB)...', flush=True)
    state = merkle.load_tree_pickle()
    if args.validate_all:
        print('Revalidating every stored hash...', flush=True)
        merkle.validate_tree_state(state)
    else:
        if (state['branching_factor'] != merkle.BRANCHING_FACTOR
                or state['depth'] != merkle.TREE_DEPTH
                or state['leaf_count'] != merkle.NUMBER_OF_RECORDS
                or len(state['levels']) != merkle.TREE_DEPTH + 1
                or len(state['levels'][0]) != merkle.NUMBER_OF_RECORDS
                or state['levels'][-1][0] != state['root']):
            raise ValueError('Invalid saved tree metadata or root')

    print('Indexing JSONL line offsets (not timed)...', flush=True)
    texts = CompactJsonlStore(merkle.LEAF_VALUES_FILE, merkle.NUMBER_OF_RECORDS)
    if len(state['keys']) != merkle.NUMBER_OF_RECORDS:
        raise AssertionError('Wrong tree size')
    keys = state['keys']
    rng = random.Random(args.seed)
    present = (
        rng.sample(keys, args.per_type) if args.per_type <= len(keys)
        else rng.choices(keys, k=args.per_type)
    )
    missing = sample_absent_queries(keys, args.per_type // 4, args.seed + 1)

    untimed_checks(state, texts, missing)
    benchmark_one_present(state, texts, present[0])
    for label, queries in missing.items():
        benchmark_one_absent(state, queries[0], label)

    groups = {}
    groups['Membership (present)'] = [
        benchmark_one_present(state, texts, key) for key in present
    ]
    for label, queries in missing.items():
        groups[label] = [
            benchmark_one_absent(state, key, label) for key in queries
        ]
    present_rows = groups['Membership (present)']
    absent_rows = [row for label in missing for row in groups[label]]
    all_rows = present_rows + absent_rows
    if len(all_rows) != 2 * args.per_type:
        raise AssertionError('Incorrect number of timed reads')
    if not all(row['verified'] for row in all_rows):
        raise AssertionError('Invalid proof accepted')
    for row in all_rows:
        assert abs(row['total_read_ms'] - row['search_ms'] - row['proof_ms']) < 1e-9

    with CSV_FILE.open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for i, row in enumerate(all_rows, 1):
            writer.writerow({'operation': i, **row})

    print('\nMERKLE TREE 7^9 READ BENCHMARK')
    print('Branching factor:', state['branching_factor'])
    print('Tree depth:', state['depth'])
    print('Number of leaves:', len(keys))
    print('Membership queries:', len(present_rows))
    print('Non-membership queries:', len(absent_rows))
    print('Total timed queries:', len(all_rows))
    print('\nTIMINGS (milliseconds, mean +/- sample SD)')
    print('Total read = search + proof construction. Verification is separate.')
    print(f"{'Operation':<32} {'Runs':>5} {'Search':>23} {'Proof':>23} "
          f"{'Total read':>23} {'Verification':>23}")
    print('-' * 142)
    for label, rows in groups.items():
        print_times(label, rows)
    print_times('Non-membership (all cases)', absent_rows)

    print('\nCOMPLETE SERIALIZED PROOF RESPONSE SIZE (bytes)')
    print(f"{'Operation':<32} {'Runs':>5} {'Mean':>12} {'SD':>12} {'Min':>9} {'Max':>9}")
    print('-' * 88)
    for label, rows in groups.items():
        print_sizes(label, rows)
    print_sizes('Non-membership (all cases)', absent_rows)

    hash_bytes = state['depth'] * (state['branching_factor'] - 1) * 32
    position_bytes = state['depth'] * state['branching_factor']
    print(f'\nSingle authentication path: {hash_bytes + position_bytes} B '
          f'({hash_bytes} SHA-256 + {position_bytes} position bytes)')
    print('Input files were NOT changed. Loading/serialization/CSV writing excluded from timings.')
    print('Search uses in-memory key indexes and mmap-backed JSONL; JSON decode included in search.')
    print('Raw per-query CSV:', CSV_FILE.name)
    print(f'All {len(all_rows)} timed reads verified successfully.')
    texts.close()


if __name__ == '__main__':
    main()
