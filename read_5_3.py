"""Benchmark authenticated reads from the previously saved 5^3 Merkle tree.

Reads merkle_tree_5_3.pkl and leaf_values_5_3.jsonl; never modifies them.
For each query separately times (a) search/record retrieval,
(b) authentication-path proof construction, and (c) cryptographic verification.
TOTAL READ TIME = SEARCH TIME + PROOF CONSTRUCTION TIME (NOT verification).
Exports per-query raw results to read_benchmark_5_3.csv and reports the
serialized proof-response sizes using the binary wire format described below.

Wire format v1 (big-endian integers):
  Header: [version:1][kind:1 ('M' or 'N')][fanout:1][depth:1]
  Membership response: header, key:13, text_len:4, text:UTF-8, path
  Non-membership response: header, boundary_flags:1 (bit0=pred, bit1=succ),
    then for each present boundary (predecessor followed by successor):
      key:13, derived_value:32, path
  Path: at each level (leaf to root): child_position:1,
    then fanout-1 entries, each [sibling_position:1][SHA256:32].

Verifier's requested key and trusted root are known out of band, so neither
is included. A path for fanout=5, depth=3 is 3*(1 + 4*(1+32)) = 399 bytes.
Loading, initial JSONL parsing, sample preparation, serialization and CSV output
are excluded from timings. Search is performed on the in-memory sorted-key
array or key-index map, NOT on disk. Timings are not directly comparable to
prior unsplit proof-construction timings because work is now measured separately.
"""

import argparse
import csv
from pathlib import Path
import random
import statistics
import time
from bisect import bisect_left

import merkle_5_3 as merkle

WIRE_VERSION = 1
KEY_BYTES = merkle.KEY_LENGTH_BYTES           # 13
VALUE_BYTES = merkle.VALUE_LENGTH_BYTES       # 32
HASH_BYTES = 32


# ============================================================
# PROVER / VERIFIER: SAME READ OPERATIONS AS BEFORE
# ============================================================

def generate_path_from_saved_tree_index(state, leaf_index):
    """Build a fresh path by fetching sibling hashes from saved node levels."""
    index = leaf_index
    branching_factor = state["branching_factor"]
    proof = []

    for level in range(state["depth"]):
        nodes = state["levels"][level]
        child_position = index % branching_factor
        group_start = (index // branching_factor) * branching_factor
        siblings = [
            (position, nodes[group_start + position])
            for position in range(branching_factor)
            if position != child_position
        ]
        proof.append((child_position, siblings))
        index //= branching_factor
    return proof


def generate_path_from_saved_tree(state, key):
    """Public helper kept compatible with the existing update benchmark."""
    index = state["key_to_index"][key]
    return generate_path_from_saved_tree_index(state, index)


def search_present(state, texts, query_key):
    """Find an existing key and fetch its original JSONL text from memory."""
    index = state["key_to_index"].get(query_key)
    if index is None:
        raise KeyError(f"Missing membership key: {query_key}")
    return index, texts[index]


def prove_present(state, query_key, search_result):
    index, text = search_result
    return {
        "key": query_key,
        "text": text,
        "proof": generate_path_from_saved_tree_index(state, index),
    }


def read_present(state, texts, key):
    """Combined convenience function, retained for older callers."""
    return prove_present(state, key, search_present(state, texts, key))


def verify_present(query_key, response, trusted_root):
    # A valid proof for another stored key must not satisfy this query.
    if response["key"] != query_key:
        return False
    derived_value = merkle.derive_value(response["key"], response["text"])
    return merkle.verify_membership_proof(
        query_key, derived_value, response["proof"], trusted_root
    )


def search_absent(state, query_key):
    """Binary-search the sorted keys and fetch authenticated boundary records."""
    keys = state["keys"]
    records = state["key_value_db"]
    position = bisect_left(keys, query_key)
    if position < len(keys) and keys[position] == query_key:
        raise ValueError("Expected an absent key, but query exists")
    predecessor = (
        (keys[position - 1], records[keys[position - 1]], position - 1)
        if position > 0 else None
    )
    successor = (
        (keys[position], records[keys[position]], position)
        if position < len(keys) else None
    )
    return predecessor, successor


def prove_absent(state, search_result):
    predecessor, successor = search_result
    return {
        "predecessor": (
            (predecessor[0], predecessor[1]) if predecessor is not None else None
        ),
        "predecessor_proof": (
            generate_path_from_saved_tree_index(state, predecessor[2])
            if predecessor is not None else None
        ),
        "successor": (
            (successor[0], successor[1]) if successor is not None else None
        ),
        "successor_proof": (
            generate_path_from_saved_tree_index(state, successor[2])
            if successor is not None else None
        ),
    }


def read_absent(state, query_key):
    """Combined convenience function, retained for older callers."""
    return prove_absent(state, search_absent(state, query_key))


def verify_absent(query_key, response, trusted_root):
    return merkle.verify_non_membership_from_package(
        query_key, response, trusted_root
    )


# ============================================================
# COMPACT BINARY SERIALIZATION: FULL PROOF RESPONSE, NOT JUST HASHES
# ============================================================

def wire_header(kind, branching_factor, depth):
    if kind not in (b"M", b"N"):
        raise ValueError("Invalid proof type")
    if not (2 <= branching_factor <= 255 and 1 <= depth <= 255):
        raise ValueError("Branching factor / depth cannot fit in one byte")
    return bytes((WIRE_VERSION,)) + kind + bytes((branching_factor, depth))


def encode_key(key):
    if not (1 <= key <= merkle.KEY_UNIVERSE):
        raise ValueError("Invalid key")
    return key.to_bytes(KEY_BYTES, "big")


def encode_path(proof, branching_factor, depth):
    if len(proof) != depth:
        raise ValueError("Invalid path depth")

    result = bytearray()
    for child_position, siblings in proof:
        if not 0 <= child_position < branching_factor:
            raise ValueError("Invalid child position")
        if len(siblings) != branching_factor - 1:
            raise ValueError("Incorrect sibling count")
        result.append(child_position)
        seen = {child_position}
        for position, sibling_hash in siblings:
            if position in seen or not 0 <= position < branching_factor:
                raise ValueError("Invalid/duplicate sibling position")
            if not isinstance(sibling_hash, bytes) or len(sibling_hash) != HASH_BYTES:
                raise ValueError("Invalid SHA-256 digest")
            seen.add(position)
            result.append(position)
            result.extend(sibling_hash)
        if len(seen) != branching_factor:
            raise ValueError("Incomplete sibling positions")
    return bytes(result)


def serialize_present(response, branching_factor, depth):
    """Bytes a sender would transmit to enable membership verification."""
    text_bytes = response["text"].encode("utf-8")
    if len(text_bytes) > 0xFFFFFFFF:
        raise ValueError("Text too large")
    return (
        wire_header(b"M", branching_factor, depth)
        + encode_key(response["key"])
        + len(text_bytes).to_bytes(4, "big")
        + text_bytes
        + encode_path(response["proof"], branching_factor, depth)
    )


def serialize_absent(response, branching_factor, depth):
    """Bytes a sender would transmit to enable non-membership verification."""
    pred = response["predecessor"]
    succ = response["successor"]
    if pred is None and succ is None:
        raise ValueError("Both boundary records are missing")
    flags = (1 if pred is not None else 0) | (2 if succ is not None else 0)
    result = bytearray(wire_header(b"N", branching_factor, depth))
    result.append(flags)

    for side in ("predecessor", "successor"):
        record = response[side]
        proof = response[side + "_proof"]
        if record is None:
            if proof is not None:
                raise ValueError("Unexpected proof without boundary record")
            continue
        if proof is None:
            raise ValueError("Missing authentication path")
        key, value = record
        if not isinstance(value, bytes) or len(value) != VALUE_BYTES:
            raise ValueError("Invalid derived value")
        result.extend(encode_key(key))
        result.extend(value)
        result.extend(encode_path(proof, branching_factor, depth))
    return bytes(result)


# Decoder is used in untimed correctness tests to confirm sizes measure
# genuinely decodable/transmittable data, not just a formula or estimate.
class WireReader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, n):
        if n < 0 or self.offset + n > len(self.data):
            raise ValueError("Truncated wire proof")
        result = self.data[self.offset:self.offset + n]
        self.offset += n
        return result

    def byte(self):
        return self.take(1)[0]

    def finish(self):
        if self.offset != len(self.data):
            raise ValueError("Unexpected trailing proof bytes")


def decode_header(reader, expected_kind):
    version, kind, branching_factor, depth = reader.take(4)
    if version != WIRE_VERSION or kind != ord(expected_kind):
        raise ValueError("Incorrect proof format/version")
    if branching_factor != merkle.BRANCHING_FACTOR or depth != merkle.TREE_DEPTH:
        raise ValueError("Incorrect tree parameters")
    return branching_factor, depth


def decode_path(reader, branching_factor, depth):
    proof = []
    for _ in range(depth):
        child_position = reader.byte()
        siblings = [
            (reader.byte(), reader.take(HASH_BYTES))
            for _ in range(branching_factor - 1)
        ]
        # The encoder performs full position consistency checks; re-check
        # for tampered/malformed wire data as well.
        positions = [child_position] + [position for position, _ in siblings]
        if sorted(positions) != list(range(branching_factor)):
            raise ValueError("Malformed authentication path positions")
        proof.append((child_position, siblings))
    return proof


def deserialize_present(data):
    reader = WireReader(data)
    b, d = decode_header(reader, "M")
    key = int.from_bytes(reader.take(KEY_BYTES), "big")
    text_length = int.from_bytes(reader.take(4), "big")
    text = reader.take(text_length).decode("utf-8")
    proof = decode_path(reader, b, d)
    reader.finish()
    return {"key": key, "text": text, "proof": proof}


def deserialize_absent(data):
    reader = WireReader(data)
    b, d = decode_header(reader, "N")
    flags = reader.byte()
    if flags not in (1, 2, 3):
        raise ValueError("Invalid non-membership boundary flags")
    response = {}
    for side, bit in (("predecessor", 1), ("successor", 2)):
        if flags & bit:
            key = int.from_bytes(reader.take(KEY_BYTES), "big")
            value = reader.take(VALUE_BYTES)
            response[side] = (key, value)
            response[side + "_proof"] = decode_path(reader, b, d)
        else:
            response[side] = None
            response[side + "_proof"] = None
    reader.finish()
    return response


# ============================================================
# SELECT PRESENT AND ABSENT QUERIES
# ============================================================

def sample_absent_queries(keys, count_per_case, seed):
    rng = random.Random(seed)
    b = merkle.BRANCHING_FACTOR
    max_key = merkle.KEY_UNIVERSE

    case2_gaps = [
        i for i in range(len(keys) - 1)
        if i // b == (i + 1) // b and keys[i + 1] - keys[i] > 1
    ]
    case3_gaps = [
        i for i in range(len(keys) - 1)
        if i // b != (i + 1) // b
        and i // (b ** 2) == (i + 1) // (b ** 2)
        and keys[i + 1] - keys[i] > 1
    ]

    sources = {
        "Case 1 (before first)": [(-1, 1, keys[0])],
        "Case 2 (same parent)": [
            (i, keys[i] + 1, keys[i + 1]) for i in case2_gaps
        ],
        "Case 3 (two subtrees)": [
            (i, keys[i] + 1, keys[i + 1]) for i in case3_gaps
        ],
        "Case 4 (after last)": [(-1, keys[-1] + 1, max_key + 1)],
    }

    results = {}
    for label, gaps in sources.items():
        if not gaps or sum(max(0, high - low) for _, low, high in gaps) < count_per_case:
            raise ValueError(f"Not enough missing keys for {label}")

        chosen = set()
        while len(chosen) < count_per_case:
            _, low, high = rng.choice(gaps)
            if low < high:
                chosen.add(rng.randrange(low, high))

        results[label] = list(chosen)
        rng.shuffle(results[label])
    return results


# ============================================================
# BENCHMARK: SEARCH, PROOF, TOTAL READ, VERIFICATION
# ============================================================

CSV_FILE = Path(__file__).resolve().parent / "read_benchmark_5_3.csv"

CSV_COLUMNS = [
    "operation", "category", "query_key", "leaf_index",
    "predecessor_key", "successor_key", "search_ms", "proof_ms",
    "total_read_ms", "verification_ms", "proof_bytes", "verified"
]


def benchmark_one_present(state, texts, key):
    t0 = time.perf_counter_ns()
    located = search_present(state, texts, key)
    t1 = time.perf_counter_ns()
    response = prove_present(state, key, located)
    t2 = time.perf_counter_ns()
    verified = verify_present(key, response, state["root"])
    t3 = time.perf_counter_ns()
    if not verified:
        raise AssertionError(f"Membership verification failed for key {key}")

    # Serialization excluded from the three timing windows.
    proof_bytes = len(serialize_present(
        response, state["branching_factor"], state["depth"]
    ))
    search_ms = (t1 - t0) / 1_000_000
    proof_ms = (t2 - t1) / 1_000_000
    return {
        "category": "Membership (present)",
        "query_key": key,
        "leaf_index": located[0],
        "predecessor_key": "",
        "successor_key": "",
        "search_ms": search_ms,
        "proof_ms": proof_ms,
        "total_read_ms": search_ms + proof_ms,
        "verification_ms": (t3 - t2) / 1_000_000,
        "proof_bytes": proof_bytes,
        "verified": verified,
    }


def benchmark_one_absent(state, key, category="Non-membership"):
    t0 = time.perf_counter_ns()
    located = search_absent(state, key)
    t1 = time.perf_counter_ns()
    response = prove_absent(state, located)
    t2 = time.perf_counter_ns()
    verified = verify_absent(key, response, state["root"])
    t3 = time.perf_counter_ns()
    if not verified:
        raise AssertionError(f"Non-membership verification failed for key {key}")

    proof_bytes = len(serialize_absent(
        response, state["branching_factor"], state["depth"]
    ))
    search_ms = (t1 - t0) / 1_000_000
    proof_ms = (t2 - t1) / 1_000_000
    return {
        "category": category,
        "query_key": key,
        "leaf_index": "",
        "predecessor_key": located[0][0] if located[0] is not None else "",
        "successor_key": located[1][0] if located[1] is not None else "",
        "search_ms": search_ms,
        "proof_ms": proof_ms,
        "total_read_ms": search_ms + proof_ms,
        "verification_ms": (t3 - t2) / 1_000_000,
        "proof_bytes": proof_bytes,
        "verified": verified,
    }


def stats(values):
    return statistics.mean(values), (
        statistics.stdev(values) if len(values) > 1 else 0.0
    )


def show_time_stats(label, rows):
    def formatted(key):
        mean, sd = stats([r[key] for r in rows])
        return f"{mean:.6f} +/- {sd:.6f}"

    print(f"{label:<30} {len(rows):>5} "
          f"{formatted('search_ms'):>23} "
          f"{formatted('proof_ms'):>23} "
          f"{formatted('total_read_ms'):>23} "
          f"{formatted('verification_ms'):>23}")


def show_size_stats(label, rows):
    sizes = [r["proof_bytes"] for r in rows]
    mean, sd = stats(sizes)
    print(f"{label:<30} {len(sizes):>5} "
          f"{mean:>12.3f} {sd:>12.3f} "
          f"{min(sizes):>9} {max(sizes):>9}")


def assert_wire_roundtrip(state, texts, absent_groups):
    """Untimed tests: encoding, verification, and requested-key binding."""
    key = state["keys"][0]
    response = read_present(state, texts, key)
    wire = serialize_present(response, state["branching_factor"], state["depth"])
    decoded = deserialize_present(wire)
    assert decoded == response and verify_present(key, decoded, state["root"])
    assert not verify_present(state["keys"][1], decoded, state["root"])
    for queries in absent_groups.values():
        key = queries[0]
        response = read_absent(state, key)
        wire = serialize_absent(response, state["branching_factor"], state["depth"])
        decoded = deserialize_absent(wire)
        assert decoded == response and verify_absent(key, decoded, state["root"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--per-type", type=int, default=500,
        help="Number of membership AND non-membership reads each (default: 500)",
    )
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args()
    if args.per_type < 8 or args.per_type % 4 != 0:
        parser.error("--per-type must be a multiple of 4, at least 8")
    if not merkle.TREE_PICKLE_FILE.is_file() or not merkle.LEAF_VALUES_FILE.is_file():
        parser.error("Run python3 merkle_5_3.py first to generate pickle and JSONL")

    # Load + validate entirely outside benchmark timing.
    state = merkle.load_tree_pickle()
    texts = merkle.load_leaf_values_file()
    merkle.validate_tree_state(state, texts)

    rng = random.Random(args.seed)
    keys = state["keys"]
    present_keys = (
        rng.sample(keys, args.per_type)
        if args.per_type <= len(keys)
        else rng.choices(keys, k=args.per_type)
    )
    absent_groups = sample_absent_queries(keys, args.per_type // 4, args.seed + 1)

    # Warm up Python function paths and validate wire format outside timing.
    assert_wire_roundtrip(state, texts, absent_groups)
    benchmark_one_present(state, texts, present_keys[0])
    for label, queries in absent_groups.items():
        benchmark_one_absent(state, queries[0], label)

    # Benchmark every read independently. All successes are required.
    all_rows = []
    grouped = {}
    membership_rows = [benchmark_one_present(state, texts, key) for key in present_keys]
    grouped["Membership (present)"] = membership_rows
    all_rows.extend(membership_rows)
    for label, queries in absent_groups.items():
        rows = [benchmark_one_absent(state, key, label) for key in queries]
        grouped[label] = rows
        all_rows.extend(rows)
    absent_rows = all_rows[len(membership_rows):]
    assert len(membership_rows) == args.per_type
    assert len(absent_rows) == args.per_type
    assert all(r["verified"] for r in all_rows)
    assert all(abs(r["total_read_ms"] - r["search_ms"] - r["proof_ms"]) < 1e-9 for r in all_rows)

    # Write one CSV row per timed query; NOT aggregated averages only.
    with CSV_FILE.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for i, row in enumerate(all_rows, 1):
            writer.writerow({"operation": i, **row})

    print("\nMERKLE TREE READ BENCHMARK")
    print("Branching factor:", state["branching_factor"])
    print("Tree depth:", state["depth"])
    print("Number of leaves:", len(keys))
    print("Membership queries:", len(membership_rows))
    print("Non-membership queries:", len(absent_rows))
    print("Total queries:", len(all_rows))
    print("\nTimes: milliseconds; entries are mean +/- sample SD")
    print("Total read = search + proof generation; verification is separate.")
    print(f"{'Operation':<30} {'Runs':>5} "
          f"{'Search (mean +/- SD)':>23} "
          f"{'Proof (mean +/- SD)':>23} "
          f"{'Read total (mean +/- SD)':>23} "
          f"{'Verify (mean +/- SD)':>23}")
    print("-" * 132)
    for label, rows in grouped.items():
        show_time_stats(label, rows)
    show_time_stats("Non-membership (all cases)", absent_rows)

    print("\nFULL SERIALIZED PROOF RESPONSE SIZE (bytes)")
    print(f"{'Operation':<30} {'Runs':>5} "
          f"{'Mean (B)':>12} {'SD (B)':>12} "
          f"{'Min (B)':>9} {'Max (B)':>9}")
    print("-" * 76)
    for label, rows in grouped.items():
        show_size_stats(label, rows)
    show_size_stats("Non-membership (all cases)", absent_rows)
    print("\nEach 5^3 authentication path = 399 bytes (hashes + positions).")
    print("Search is an IN-MEMORY dict lookup or binary search over loaded keys.")
    print("Input loading, proof serialization and CSV writing are NOT timed.")
    print("Raw per-query CSV saved to:", CSV_FILE)
    print(f"All {len(all_rows)} timed reads verified successfully")


if __name__ == "__main__":
    main()
