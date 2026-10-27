"""Construct, store, or validate the complete sorted 6^9 Merkle tree.

Outputs (in the same folder as this script):
    leaf_values_6_9.jsonl    10,077,696 JSON string lines
    merkle_tree_6_9.pkl      keys, records, complete hash levels, Merkle root

Leaf and internal hashing and saved state keys are compatible with the
existing 5^3 and 5^6 constructions. Construction and validation stream
through the JSONL file to avoid allocating millions of text strings.

Commands:
    python3 merkle_6_9.py                # create or verify saved tree
    python3 merkle_6_9.py --rebuild      # replace both files with fresh data

SECURITY: Only unpickle files you created or otherwise trust.
"""

import argparse
import gc
import hashlib
import json
import os
import pickle
import secrets
import time
from pathlib import Path


BRANCHING_FACTOR = 6
TREE_DEPTH = 9
NUMBER_OF_RECORDS = BRANCHING_FACTOR ** TREE_DEPTH
KEY_UNIVERSE = 2**100
KEY_LENGTH_BYTES = 13
VALUE_LENGTH_BYTES = 32
HASH_LENGTH_BYTES = 32

BASE_DIR = Path(__file__).resolve().parent
LEAF_VALUES_FILE = BASE_DIR / "leaf_values_6_9.jsonl"
TREE_PICKLE_FILE = BASE_DIR / "merkle_tree_6_9.pkl"


def generate_keys(n):
    """Generate unique random keys, sorted by their encoded 13-byte order."""
    if not 1 <= n <= KEY_UNIVERSE:
        raise ValueError("Invalid number of keys")
    unique = set()
    while len(unique) < n:
        unique.add(secrets.randbelow(KEY_UNIVERSE) + 1)
    keys = sorted(unique)
    del unique
    return keys


def create_leaf_values_file(path):
    """Create one JSON string per line; do not accumulate strings in RAM."""
    with path.open("w", encoding="utf-8", newline="\n", buffering=1024 * 1024) as f:
        for i in range(1, NUMBER_OF_RECORDS + 1):
            f.write(json.dumps(f"this is leaf {i}") + "\n")


def iter_leaf_values_file(path=LEAF_VALUES_FILE):
    with path.open("r", encoding="utf-8", buffering=1024 * 1024) as f:
        for line_no, line in enumerate(f, 1):
            try:
                text = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at line {line_no}") from exc
            if not isinstance(text, str):
                raise ValueError(f"Non-string JSON value at line {line_no}")
            yield text


def load_leaf_values_file():
    """Optional compatibility helper for later read/update code.

    Warning: returns ~10 million strings and consumes substantial RAM.
    Construction and validation use the streaming iterator instead.
    """
    texts = list(iter_leaf_values_file())
    if len(texts) != NUMBER_OF_RECORDS:
        raise ValueError(f"Expected {NUMBER_OF_RECORDS} JSONL lines, got {len(texts)}")
    return texts


def derive_value(key, text):
    text_bytes = text.encode("utf-8")
    return hashlib.sha256(
        b"\x02" + key.to_bytes(KEY_LENGTH_BYTES, "big")
        + len(text_bytes).to_bytes(4, "big") + text_bytes
    ).digest()


def hash_leaf(key, value):
    return hashlib.sha256(
        b"\x00" + key.to_bytes(KEY_LENGTH_BYTES, "big")
        + len(value).to_bytes(4, "big") + value
    ).digest()


def hash_internal(children):
    if len(children) != BRANCHING_FACTOR:
        raise ValueError("A 6-ary internal node requires exactly six children")
    return hashlib.sha256(b"\x01" + b"".join(children)).digest()


def build_records_and_leaves(keys, jsonl_path):
    """Read the JSONL just once, deriving values and leaf hashes in one pass."""
    records = {}
    leaves = []
    count = 0
    for count, text in enumerate(iter_leaf_values_file(jsonl_path), 1):
        if count > len(keys):
            raise ValueError("JSONL has more entries than leaves")
        key = keys[count - 1]
        value = derive_value(key, text)
        records[key] = value
        leaves.append(hash_leaf(key, value))
    if count != NUMBER_OF_RECORDS:
        raise ValueError(f"Expected {NUMBER_OF_RECORDS} JSONL entries; got {count}")
    return records, leaves


def build_levels(leaves):
    if len(leaves) != NUMBER_OF_RECORDS:
        raise ValueError("Incorrect leaf count")
    levels = [leaves]
    print(f"Level 0: {len(leaves)} nodes", flush=True)
    while len(levels[-1]) > 1:
        child = levels[-1]
        if len(child) % BRANCHING_FACTOR:
            raise ValueError("Incomplete internal node")
        parent = [
            hash_internal(child[i:i + BRANCHING_FACTOR])
            for i in range(0, len(child), BRANCHING_FACTOR)
        ]
        levels.append(parent)
        print(f"Level {len(levels) - 1}: {len(parent)} nodes", flush=True)
    if len(levels) != TREE_DEPTH + 1 or len(levels[-1]) != 1:
        raise ValueError("Incorrect depth or root")
    return levels


def validate_tree_state(state, jsonl_path=LEAF_VALUES_FILE):
    """Independently validate keys, JSONL, all hashes and root in O(n) time.

    Streaming validation avoids creating duplicate 10m-element arrays.
    """
    if (state["branching_factor"], state["depth"], state["leaf_count"]) != (
        BRANCHING_FACTOR, TREE_DEPTH, NUMBER_OF_RECORDS
    ):
        raise ValueError("Incorrect tree configuration in pickle")
    keys = state["keys"]
    records = state["key_value_db"]
    mapping = state["key_to_index"]
    levels = state["levels"]
    n = NUMBER_OF_RECORDS
    if (len(keys), len(records), len(mapping), len(levels)) != (n, n, n, TREE_DEPTH + 1):
        raise ValueError("Incorrect sizes in saved tree")
    if len(levels[0]) != n or len(levels[-1]) != 1:
        raise ValueError("Incorrect leaf or root count")

    # Ensure sorted keys and identical record-dictionary iteration order.
    previous = 0
    for i, (key, stored_key) in enumerate(zip(keys, records)):
        if key <= previous or key != stored_key or mapping.get(key) != i:
            raise ValueError(f"Key order/index is incorrect at leaf {i}")
        previous = key

    # Reconstruct every leaf from the saved JSONL and record database.
    count = 0
    for count, text in enumerate(iter_leaf_values_file(jsonl_path), 1):
        if count > n:
            raise ValueError("JSONL has excess entries")
        i = count - 1
        key = keys[i]
        value = derive_value(key, text)
        if records[key] != value or levels[0][i] != hash_leaf(key, value):
            raise ValueError(f"Record or leaf hash differs at index {i}")
    if count != n:
        raise ValueError(f"JSONL has {count} entries instead of {n}")

    # Reconstruct every internal parent hash without allocating a new level.
    for level in range(TREE_DEPTH):
        children = levels[level]
        parents = levels[level + 1]
        expected_size = BRANCHING_FACTOR ** (TREE_DEPTH - level)
        if len(children) != expected_size or len(parents) != expected_size // BRANCHING_FACTOR:
            raise ValueError(f"Bad node count at level {level}")
        for i, parent_hash in enumerate(parents):
            start = i * BRANCHING_FACTOR
            if parent_hash != hash_internal(children[start:start + BRANCHING_FACTOR]):
                raise ValueError(f"Bad parent hash at level {level + 1}, index {i}")

    if state["root"] != levels[-1][0]:
        raise ValueError("Stored root differs from reconstructed root")
    return True


def save_tree_pickle(state, path=TREE_PICKLE_FILE):
    temp = path.with_name(path.name + ".tmp")
    try:
        with temp.open("wb", buffering=1024 * 1024) as f:
            pickle.dump(state, f, protocol=pickle.HIGHEST_PROTOCOL)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def load_tree_pickle(path=TREE_PICKLE_FILE):
    """Never load untrusted pickle files."""
    with path.open("rb", buffering=1024 * 1024) as f:
        return pickle.load(f)


def print_summary(state, status):
    print("\nMERKLE TREE 6^9")
    print("Status:", status)
    print("Branching factor:", state["branching_factor"])
    print("Depth:", state["depth"])
    print("Number of leaves:", state["leaf_count"])
    print("Tree levels:", [len(level) for level in state["levels"]])
    print("Merkle root:", state["root"].hex())
    print("JSONL file:", LEAF_VALUES_FILE.name)
    print("Pickle file:", TREE_PICKLE_FILE.name)
    print("JSONL bytes:", LEAF_VALUES_FILE.stat().st_size)
    print("Pickle bytes:", TREE_PICKLE_FILE.stat().st_size)
    print("Validation: PASSED")


def main():
    parser = argparse.ArgumentParser(description="Construct/verify complete 6^9 Merkle tree")
    parser.add_argument("--rebuild", action="store_true", help="Replace existing data; destroys saved updates")
    args = parser.parse_args()

    if TREE_PICKLE_FILE.exists() and not args.rebuild:
        if not LEAF_VALUES_FILE.exists():
            parser.error("Pickle exists but JSONL file is missing")
        print("Loading existing pickle and verifying all 10,077,696 leaves...", flush=True)
        state = load_tree_pickle()
        validate_tree_state(state)
        print_summary(state, "loaded existing tree")
        return

    # Generate JSONL as part of THIS construction script; stage it before commit.
    staged_json = BASE_DIR / (LEAF_VALUES_FILE.name + ".new")
    staged_pickle = BASE_DIR / (TREE_PICKLE_FILE.name + ".new")
    if args.rebuild:
        print("WARNING: --rebuild replaces existing JSONL, keys and pickle.", flush=True)
    try:
        if LEAF_VALUES_FILE.exists() and not args.rebuild:
            json_path = LEAF_VALUES_FILE
            print("JSONL: reusing existing file", flush=True)
        else:
            print("Generating 10,077,696 JSONL lines...", flush=True)
            create_leaf_values_file(staged_json)
            json_path = staged_json

        print("Generating sorted keys, values and tree hashes...", flush=True)
        t0 = time.perf_counter()
        keys = generate_keys(NUMBER_OF_RECORDS)
        records, leaves = build_records_and_leaves(keys, json_path)
        levels = build_levels(leaves)
        state = {
            "format_version": 1,
            "branching_factor": BRANCHING_FACTOR,
            "depth": TREE_DEPTH,
            "leaf_count": NUMBER_OF_RECORDS,
            "key_universe": KEY_UNIVERSE,
            "leaf_text_file": LEAF_VALUES_FILE.name,
            "keys": keys,
            "key_to_index": {key: i for i, key in enumerate(keys)},
            "key_value_db": records,
            "levels": levels,
            "root": levels[-1][0],
            "value_scheme": "sha256(0x02 || fixed13_key || fixed4_len || utf8_text)",
        }
        construction_s = time.perf_counter() - t0
        print("Validating full tree before saving...", flush=True)
        validate_tree_state(state, json_path)

        print("Writing pickle...", flush=True)
        save_tree_pickle(state, staged_pickle)
        # Drop large in-memory tree before reloading it independently.
        del state, keys, records, leaves, levels
        gc.collect()

        print("Reloading pickle and independently validating all hashes...", flush=True)
        reloaded = load_tree_pickle(staged_pickle)
        validate_tree_state(reloaded, json_path)

        # Promote both validated staged files. First-time build is safe to rerun
        # after interruption; --rebuild of existing state should be backed up first.
        if json_path == staged_json:
            os.replace(staged_json, LEAF_VALUES_FILE)
        os.replace(staged_pickle, TREE_PICKLE_FILE)

        print(f"Construction (keys + leaf/internal hashing): {construction_s:.3f} s")
        print_summary(reloaded, "new tree created and reloaded")
    finally:
        staged_json.unlink(missing_ok=True)
        staged_pickle.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
