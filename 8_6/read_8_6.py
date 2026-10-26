"""8^6 Merkle read benchmark: 500 membership + 500 non-membership queries.

Requires merkle_8_6.py, leaf_values_8_6.jsonl, merkle_tree_8_6.pkl.
Writes read_benchmark_8_6.csv (one row per query).
Timings exclude loading, validation, serialization and CSV writing.
A standard Merkle root does not independently certify global key sorting.
"""
import argparse
import csv
import random
import statistics
import time
from bisect import bisect_left
from pathlib import Path
import merkle_8_6 as merkle

CSV_PATH = Path(__file__).resolve().parent / "read_benchmark_8_6.csv"
COLUMNS = ("operation", "category", "query_key", "leaf_index",
           "predecessor_key", "successor_key", "search_ms", "proof_ms",
           "total_read_ms", "verification_ms", "proof_bytes", "verified")

# ---------------- Prover: retrieve existing hashes on demand ----------------
def generate_path_from_saved_tree_index(state, leaf_index):
    b = state["branching_factor"]
    path = []
    for level in range(state["depth"]):
        hashes = state["levels"][level]
        pos = leaf_index % b
        begin = (leaf_index // b) * b
        path.append((pos, [(j, hashes[begin + j]) for j in range(b) if j != pos]))
        leaf_index //= b
    return path


def generate_path_from_saved_tree(state, key):
    return generate_path_from_saved_tree_index(state, state["key_to_index"][key])


def search_present(state, texts, key):
    index = state["key_to_index"].get(key)
    if index is None:
        raise KeyError("Membership key is absent")
    return index, texts[index]


def prove_present(state, key, found):
    index, text = found
    return {"key": key, "text": text,
            "proof": generate_path_from_saved_tree_index(state, index)}


def search_absent(state, key):
    keys = state["keys"]
    i = bisect_left(keys, key)
    if i < len(keys) and keys[i] == key:
        raise ValueError("Non-membership key actually exists")
    records = state["key_value_db"]
    before = (keys[i-1], records[keys[i-1]], i-1) if i > 0 else None
    after = (keys[i], records[keys[i]], i) if i < len(keys) else None
    return before, after


def prove_absent(state, found):
    before, after = found
    return {
        "predecessor": before[:2] if before else None,
        "predecessor_proof": generate_path_from_saved_tree_index(state, before[2]) if before else None,
        "successor": after[:2] if after else None,
        "successor_proof": generate_path_from_saved_tree_index(state, after[2]) if after else None,
    }

# ---------------- Verifier: only query, proof and root ----------------
def verify_membership_proof(key, value, path, root):
    b = merkle.BRANCHING_FACTOR
    if not isinstance(key, int) or not 1 <= key <= merkle.KEY_UNIVERSE:
        return False
    if not isinstance(value, bytes) or len(value) != 32:
        return False
    if not isinstance(root, bytes) or len(root) != 32:
        return False
    if not isinstance(path, list) or len(path) != merkle.TREE_DEPTH:
        return False
    current = merkle.hash_leaf(key, value)
    try:
        for position, siblings in path:
            if not isinstance(position, int) or not 0 <= position < b or len(siblings) != b - 1:
                return False
            children = [None] * b
            children[position] = current
            for j, sibling_hash in siblings:
                if not isinstance(j, int) or not 0 <= j < b or children[j] is not None:
                    return False
                if not isinstance(sibling_hash, bytes) or len(sibling_hash) != 32:
                    return False
                children[j] = sibling_hash
            if any(child is None for child in children):
                return False
            current = merkle.hash_internal(children)
    except (TypeError, IndexError, ValueError):
        return False
    return current == root


def authenticated_index(path):
    if len(path) != merkle.TREE_DEPTH:
        raise ValueError("Incorrect proof depth")
    index = 0
    for level, (pos, _) in enumerate(path):
        if not isinstance(pos, int) or not 0 <= pos < merkle.BRANCHING_FACTOR:
            raise ValueError("Incorrect path position")
        index += pos * merkle.BRANCHING_FACTOR ** level
    return index


def verify_present(query_key, response, root):
    if response["key"] != query_key:
        return False
    value = merkle.derive_value(query_key, response["text"])
    return verify_membership_proof(query_key, value, response["proof"], root)


def verify_absent(query_key, response, root):
    if not isinstance(query_key, int) or not 1 <= query_key <= merkle.KEY_UNIVERSE:
        return False
    pred, succ = response["predecessor"], response["successor"]
    pp, sp = response["predecessor_proof"], response["successor_proof"]
    if pred is None and succ is None:
        return False
    if (pred is None) != (pp is None) or (succ is None) != (sp is None):
        return False
    pi = si = None
    if pred is not None:
        if pred[0] >= query_key or not verify_membership_proof(pred[0], pred[1], pp, root):
            return False
        pi = authenticated_index(pp)
    if succ is not None:
        if succ[0] <= query_key or not verify_membership_proof(succ[0], succ[1], sp, root):
            return False
        si = authenticated_index(sp)
    if pred is None:
        return si == 0
    if succ is None:
        return pi == merkle.NUMBER_OF_RECORDS - 1
    return si == pi + 1

# ---------------- Compact serialized response size ----------------
def encode_key(key):
    if not 1 <= key <= merkle.KEY_UNIVERSE:
        raise ValueError("Invalid key")
    return key.to_bytes(merkle.KEY_LENGTH_BYTES, "big")


def encode_path(path, b, depth):
    if len(path) != depth:
        raise ValueError("Wrong path depth")
    wire = bytearray()
    for pos, siblings in path:
        if not 0 <= pos < b or len(siblings) != b-1:
            raise ValueError("Invalid path level")
        wire.append(pos)
        seen = {pos}
        for j, digest in siblings:
            if j in seen or not 0 <= j < b or not isinstance(digest, bytes) or len(digest) != 32:
                raise ValueError("Malformed sibling")
            seen.add(j)
            wire.append(j)
            wire.extend(digest)
        if len(seen) != b:
            raise ValueError("Missing sibling")
    return bytes(wire)


def serialize_present(response, b, depth):
    text = response["text"].encode("utf-8")
    return (bytes((1, ord("M"), b, depth)) + encode_key(response["key"])
            + len(text).to_bytes(4, "big") + text
            + encode_path(response["proof"], b, depth))


def serialize_absent(response, b, depth):
    pred, succ = response["predecessor"], response["successor"]
    if pred is None and succ is None:
        raise ValueError("Missing both boundaries")
    flags = (1 if pred else 0) | (2 if succ else 0)
    wire = bytearray((1, ord("N"), b, depth, flags))
    for side in ("predecessor", "successor"):
        record = response[side]
        if record is not None:
            key, value = record
            if len(value) != 32:
                raise ValueError("Incorrect record length")
            wire.extend(encode_key(key))
            wire.extend(value)
            wire.extend(encode_path(response[side + "_proof"], b, depth))
    return bytes(wire)


class WireReader:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def take(self, count):
        if count < 0 or self.offset + count > len(self.data):
            raise ValueError("Truncated proof")
        chunk = self.data[self.offset:self.offset + count]
        self.offset += count
        return chunk

    def finish(self):
        if self.offset != len(self.data):
            raise ValueError("Unexpected trailing data")


def decode_path(reader, b, depth):
    path = []
    for _ in range(depth):
        pos = reader.take(1)[0]
        siblings = [(reader.take(1)[0], reader.take(32)) for _ in range(b-1)]
        if sorted([pos] + [i for i, _ in siblings]) != list(range(b)):
            raise ValueError("Invalid sibling positions")
        path.append((pos, siblings))
    return path


def deserialize_present(data):
    r = WireReader(data)
    if tuple(r.take(4)) != (1, ord("M"), merkle.BRANCHING_FACTOR, merkle.TREE_DEPTH):
        raise ValueError("Bad membership header")
    key = int.from_bytes(r.take(merkle.KEY_LENGTH_BYTES), "big")
    text_size = int.from_bytes(r.take(4), "big")
    text = r.take(text_size).decode("utf-8")
    path = decode_path(r, merkle.BRANCHING_FACTOR, merkle.TREE_DEPTH)
    r.finish()
    return {"key": key, "text": text, "proof": path}


def deserialize_absent(data):
    r = WireReader(data)
    if tuple(r.take(4)) != (1, ord("N"), merkle.BRANCHING_FACTOR, merkle.TREE_DEPTH):
        raise ValueError("Bad non-membership header")
    flags = r.take(1)[0]
    if flags not in (1, 2, 3):
        raise ValueError("Bad boundary flags")
    response = {}
    for side, bit in (("predecessor", 1), ("successor", 2)):
        if flags & bit:
            key = int.from_bytes(r.take(merkle.KEY_LENGTH_BYTES), "big")
            value = r.take(32)
            response[side] = (key, value)
            response[side + "_proof"] = decode_path(r, merkle.BRANCHING_FACTOR, merkle.TREE_DEPTH)
        else:
            response[side] = None
            response[side + "_proof"] = None
    r.finish()
    return response

# ---------------- 500 missing queries: 125 from each case ----------------
def sample_absent_queries(keys, per_case, seed):
    rng = random.Random(seed)
    b = merkle.BRANCHING_FACTOR
    gaps2 = [i for i in range(len(keys)-1)
             if i // b == (i+1) // b and keys[i+1]-keys[i] > 1]
    gaps3 = [i for i in range(len(keys)-1)
             if i // b != (i+1) // b and keys[i+1]-keys[i] > 1]
    if not gaps2 or not gaps3:
        raise ValueError("Missing suitable interior gaps")

    def distinct_values(low, high, count):
        if high-low < count:
            raise ValueError("Not enough boundary missing keys")
        chosen = set()
        while len(chosen) < count:
            chosen.add(rng.randrange(low, high))
        values = list(chosen)
        rng.shuffle(values)
        return values

    def gap_values(gaps, count):
        # Sampling distinct missing keys may reuse the same neighboring
        # pair, especially for small tree configurations.
        chosen = set()
        while len(chosen) < count:
            i = rng.choice(gaps)
            chosen.add(rng.randrange(keys[i]+1, keys[i+1]))
        values = list(chosen)
        rng.shuffle(values)
        return values

    return {
        "Case 1 (before first)": distinct_values(1, keys[0], per_case),
        "Case 2 (same parent)": gap_values(gaps2, per_case),
        "Case 3 (different subtrees)": gap_values(gaps3, per_case),
        "Case 4 (after last)": distinct_values(keys[-1]+1, merkle.KEY_UNIVERSE+1, per_case),
    }

# ---------------- Timed read operations ----------------
def benchmark_one_present(state, texts, key):
    t0 = time.perf_counter_ns()
    found = search_present(state, texts, key)
    t1 = time.perf_counter_ns()
    response = prove_present(state, key, found)
    t2 = time.perf_counter_ns()
    verified = verify_present(key, response, state["root"])
    t3 = time.perf_counter_ns()
    if not verified:
        raise AssertionError("Membership proof failed")
    wire = serialize_present(response, state["branching_factor"], state["depth"])
    search_ms, proof_ms = (t1-t0)/1e6, (t2-t1)/1e6
    return dict(category="Membership (present)", query_key=key,
                leaf_index=found[0], predecessor_key="", successor_key="",
                search_ms=search_ms, proof_ms=proof_ms,
                total_read_ms=search_ms+proof_ms,
                verification_ms=(t3-t2)/1e6, proof_bytes=len(wire), verified=True)


def benchmark_one_absent(state, key, label):
    t0 = time.perf_counter_ns()
    found = search_absent(state, key)
    t1 = time.perf_counter_ns()
    response = prove_absent(state, found)
    t2 = time.perf_counter_ns()
    verified = verify_absent(key, response, state["root"])
    t3 = time.perf_counter_ns()
    if not verified:
        raise AssertionError("Non-membership proof failed")
    wire = serialize_absent(response, state["branching_factor"], state["depth"])
    search_ms, proof_ms = (t1-t0)/1e6, (t2-t1)/1e6
    return dict(category=label, query_key=key, leaf_index="",
                predecessor_key=found[0][0] if found[0] else "",
                successor_key=found[1][0] if found[1] else "",
                search_ms=search_ms, proof_ms=proof_ms,
                total_read_ms=search_ms+proof_ms,
                verification_ms=(t3-t2)/1e6, proof_bytes=len(wire), verified=True)


def mean_sd(values):
    return statistics.mean(values), statistics.stdev(values) if len(values)>1 else 0.0


def print_timings(label, rows):
    def fmt(name):
        avg, sd = mean_sd([r[name] for r in rows])
        return f"{avg:.6f} +/- {sd:.6f}"
    print(f"{label:<32} {len(rows):>5} "
          f"{fmt('search_ms'):>23} {fmt('proof_ms'):>23} "
          f"{fmt('total_read_ms'):>23} {fmt('verification_ms'):>23}")


def print_sizes(label, rows):
    sizes = [r["proof_bytes"] for r in rows]
    avg, sd = mean_sd(sizes)
    print(f"{label:<32} {len(rows):>5} {avg:>12.3f} {sd:>12.3f} "
          f"{min(sizes):>9} {max(sizes):>9}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--per-type", type=int, default=500)
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args()
    if args.per_type < 8 or args.per_type % 4:
        parser.error("--per-type must be a multiple of 4 (minimum 8)")

    # Validation and input loading excluded from the benchmark timings.
    state = merkle.load_tree_pickle()
    texts = merkle.load_leaf_values_file()
    merkle.validate_tree_state(state, texts)
    keys = state["keys"]
    rng = random.Random(args.seed)
    present = (rng.sample(keys, args.per_type) if args.per_type <= len(keys)
               else rng.choices(keys, k=args.per_type))
    missing = sample_absent_queries(keys, args.per_type // 4, args.seed+1)

    # Untimed negative tests and complete packet round trips.
    first = prove_present(state, keys[0], search_present(state, texts, keys[0]))
    wire = serialize_present(first, 8, 6)
    assert deserialize_present(wire) == first
    assert verify_present(keys[0], first, state["root"])
    assert not verify_present(keys[1], first, state["root"])
    bad = dict(first)
    bad["text"] += " tampered"
    assert not verify_present(keys[0], bad, state["root"])
    for queries in missing.values():
        q = queries[0]
        response = prove_absent(state, search_absent(state, q))
        assert deserialize_absent(serialize_absent(response, 8, 6)) == response
        assert verify_absent(q, response, state["root"])
    for edge in (8-1, 8**2-1, 8**3-1, 8**4-1, 8**5-1):
        if keys[edge]+1 < keys[edge+1]:
            q = keys[edge]+1
            assert verify_absent(q, prove_absent(state, search_absent(state, q)), state["root"])

    # Untimed warmup.
    benchmark_one_present(state, texts, present[0])
    for label, queries in missing.items():
        benchmark_one_absent(state, queries[0], label)

    groups = {"Membership (present)": [benchmark_one_present(state, texts, k) for k in present]}
    for label, queries in missing.items():
        groups[label] = [benchmark_one_absent(state, k, label) for k in queries]
    absent = [row for label in missing for row in groups[label]]
    all_rows = groups["Membership (present)"] + absent
    assert len(all_rows) == 2*args.per_type and all(r["verified"] for r in all_rows)

    with CSV_PATH.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows({"operation": i, **row} for i, row in enumerate(all_rows, 1))

    print("\nMERKLE TREE 8^6 READ BENCHMARK")
    print("Branching factor:", state["branching_factor"])
    print("Tree depth:", state["depth"])
    print("Number of leaves:", len(keys))
    print("Membership queries:", len(groups["Membership (present)"]))
    print("Non-membership queries:", len(absent))
    print("Total timed queries:", len(all_rows))
    print("\nTIMINGS (milliseconds, mean +/- sample SD)")
    print("Total read = search + proof construction. Verification is separate.")
    print(f"{'Operation':<32} {'Runs':>5} {'Search':>23} {'Proof':>23} "
          f"{'Total read':>23} {'Verification':>23}")
    print("-"*142)
    for label, rows in groups.items():
        print_timings(label, rows)
    print_timings("Non-membership (all cases)", absent)
    print("\nCOMPLETE SERIALIZED PROOF RESPONSE SIZE (bytes)")
    print(f"{'Operation':<32} {'Runs':>5} {'Mean':>12} {'SD':>12} {'Min':>9} {'Max':>9}")
    print("-"*88)
    for label, rows in groups.items():
        print_sizes(label, rows)
    print_sizes("Non-membership (all cases)", absent)
    print("\nSingle authentication path: 1392 B (1344 SHA-256 + 48 position bytes)")
    print("Inputs unchanged. Loading, serialization and CSV output excluded from timings.")
    print("Search is in memory (dict lookup or binary search of sorted keys).")
    print("Raw per-query CSV:", CSV_PATH.name)
    print(f"All {len(all_rows)} timed reads verified successfully.")


if __name__ == "__main__":
    main()
