"""Build or load the 7^3 sorted, complete SHA-256 Merkle-tree baseline.

This is the CONSTRUCTION step only.  Read/update benchmarks come later.
Files, generated in this script's folder:
    leaf_values_7_3.jsonl    one JSON string per sorted leaf
    merkle_tree_7_3.pkl      all levels, records, positions, root

Hashing and pickle state format match the existing merkle_5_3.py.
Run: python3 merkle_7_3.py
Reset: python3 merkle_7_3.py --rebuild

WARNING: Only unpickle files you generated yourself or otherwise trust.
"""

import argparse
import hashlib
import json
import os
import pickle
import secrets
import time
from pathlib import Path


BRANCHING_FACTOR = 7
TREE_DEPTH = 3
NUMBER_OF_RECORDS = BRANCHING_FACTOR ** TREE_DEPTH  # 343
KEY_UNIVERSE = 2**100
KEY_LENGTH_BYTES = 13
VALUE_LENGTH_BYTES = 32
HASH_LENGTH_BYTES = 32

BASE_DIR = Path(__file__).resolve().parent
LEAF_VALUES_FILE = BASE_DIR / "leaf_values_7_3.jsonl"
TREE_PICKLE_FILE = BASE_DIR / "merkle_tree_7_3.pkl"


def generate_keys(n):
    """Generate distinct random keys in [1, 2^100], sorted by key."""
    if not 1 <= n <= KEY_UNIVERSE:
        raise ValueError("Invalid record count")
    keys = set()
    while len(keys) < n:
        keys.add(secrets.randbelow(KEY_UNIVERSE) + 1)
    return sorted(keys)


def create_leaf_values_file(overwrite=False):
    """Write 343 physical lines of individually valid JSON strings."""
    if LEAF_VALUES_FILE.exists() and not overwrite:
        return False
    temp = LEAF_VALUES_FILE.with_suffix(".jsonl.tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as f:
        for i in range(1, NUMBER_OF_RECORDS + 1):
            f.write(json.dumps(f"this is leaf {i}") + "\n")
    os.replace(temp, LEAF_VALUES_FILE)
    return True


def load_leaf_values_file():
    with LEAF_VALUES_FILE.open("r", encoding="utf-8") as f:
        texts = [json.loads(line) for line in f]
    if len(texts) != NUMBER_OF_RECORDS:
        raise ValueError(f"Expected {NUMBER_OF_RECORDS} JSONL lines, got {len(texts)}")
    if any(not isinstance(t, str) for t in texts):
        raise ValueError("Each JSONL line must be a string")
    return texts


def derive_value(key, text):
    """SHA256(0x02 || key_13 || len(text)_4 || UTF8(text))."""
    data = text.encode("utf-8")
    return hashlib.sha256(
        b"\x02" + key.to_bytes(KEY_LENGTH_BYTES, "big")
        + len(data).to_bytes(4, "big") + data
    ).digest()


def make_key_value_db(keys, texts):
    if len(keys) != NUMBER_OF_RECORDS or len(texts) != NUMBER_OF_RECORDS:
        raise ValueError("Incorrect key or text count")
    if keys != sorted(keys) or len(set(keys)) != NUMBER_OF_RECORDS:
        raise ValueError("Keys must be distinct and sorted")
    return {key: derive_value(key, texts[i]) for i, key in enumerate(keys)}


def hash_leaf(key, value):
    """SHA256(0x00 || key_13 || len(value)_4 || value)."""
    return hashlib.sha256(
        b"\x00" + key.to_bytes(KEY_LENGTH_BYTES, "big")
        + len(value).to_bytes(4, "big") + value
    ).digest()


def hash_internal(children):
    """SHA256(0x01 || seven child hashes, in order)."""
    if len(children) != BRANCHING_FACTOR:
        raise ValueError("Expected exactly seven child hashes")
    return hashlib.sha256(b"\x01" + b"".join(children)).digest()


def build_merkle_tree(key_value_db):
    """Return every level, starting with leaves and ending with [root]."""
    keys = list(key_value_db)
    if len(keys) != NUMBER_OF_RECORDS or keys != sorted(keys):
        raise ValueError("Expected sorted records of the configured size")

    levels = [[hash_leaf(k, key_value_db[k]) for k in keys]]
    print(f"Level 0: {len(levels[0])} nodes")
    while len(levels[-1]) > 1:
        child_level = levels[-1]
        if len(child_level) % BRANCHING_FACTOR:
            raise ValueError("Incomplete parent at a tree level")
        parents = [
            hash_internal(child_level[i:i + BRANCHING_FACTOR])
            for i in range(0, len(child_level), BRANCHING_FACTOR)
        ]
        levels.append(parents)
        print(f"Level {len(levels)-1}: {len(parents)} nodes")

    if len(levels) != TREE_DEPTH + 1 or len(levels[-1]) != 1:
        raise ValueError("Tree has incorrect depth or root count")
    return levels


def save_tree_pickle(state):
    tmp = TREE_PICKLE_FILE.with_suffix(".pkl.tmp")
    with tmp.open("wb") as f:
        pickle.dump(state, f, protocol=pickle.HIGHEST_PROTOCOL)
    os.replace(tmp, TREE_PICKLE_FILE)


def load_tree_pickle():
    """Only use with a trusted pickle file!"""
    with TREE_PICKLE_FILE.open("rb") as f:
        return pickle.load(f)


def validate_tree_state(state, texts):
    """Recompute values, leaves, internal levels, and root independently."""
    if (state["branching_factor"], state["depth"], state["leaf_count"]) != (
        BRANCHING_FACTOR, TREE_DEPTH, NUMBER_OF_RECORDS
    ):
        raise ValueError("Wrong configuration stored in pickle")

    keys = state["keys"]
    records = state["key_value_db"]
    levels = state["levels"]

    if len(keys) != NUMBER_OF_RECORDS or keys != sorted(keys) or len(set(keys)) != len(keys):
        raise ValueError("Persisted keys are not distinct/sorted")
    if list(records) != keys:
        raise ValueError("Record order is not the same as key order")
    if state["key_to_index"] != {k: i for i, k in enumerate(keys)}:
        raise ValueError("Key-to-index mapping is inconsistent")
    if len(levels) != TREE_DEPTH + 1:
        raise ValueError("Incorrect number of stored tree levels")
    if len(texts) != NUMBER_OF_RECORDS:
        raise ValueError("Incorrect JSONL length")

    expected_leaves = []
    for i, key in enumerate(keys):
        value = derive_value(key, texts[i])
        if records[key] != value:
            raise ValueError(f"Derived value differs at index {i}")
        expected_leaves.append(hash_leaf(key, value))

    if levels[0] != expected_leaves:
        raise ValueError("Leaf hashes do not match stored records")

    for level in range(TREE_DEPTH):
        children = levels[level]
        if len(children) != BRANCHING_FACTOR ** (TREE_DEPTH - level):
            raise ValueError(f"Unexpected number of nodes at level {level}")
        expected = [
            hash_internal(children[i:i + BRANCHING_FACTOR])
            for i in range(0, len(children), BRANCHING_FACTOR)
        ]
        if levels[level + 1] != expected:
            raise ValueError(f"Parent hashes differ at level {level + 1}")

    if len(levels[-1]) != 1 or state["root"] != levels[-1][0]:
        raise ValueError("Stored Merkle root is inconsistent")
    return True


def construct_or_load_tree(rebuild=False):
    if TREE_PICKLE_FILE.exists() and not rebuild:
        if not LEAF_VALUES_FILE.exists():
            raise FileNotFoundError("Saved pickle exists but its JSONL file is missing")
        texts = load_leaf_values_file()
        state = load_tree_pickle()
        validate_tree_state(state, texts)
        print("Loaded and verified existing tree (no rebuild).")
        return state

    # Regenerate BOTH files only on an explicit --rebuild.
    made_json = create_leaf_values_file(overwrite=rebuild)
    print("JSONL:", "generated" if made_json else "reused", LEAF_VALUES_FILE.name)
    texts = load_leaf_values_file()

    started = time.perf_counter()
    keys = generate_keys(NUMBER_OF_RECORDS)
    records = make_key_value_db(keys, texts)
    levels = build_merkle_tree(records)
    elapsed = time.perf_counter() - started

    state = {
        "format_version": 1,
        "branching_factor": BRANCHING_FACTOR,
        "depth": TREE_DEPTH,
        "leaf_count": NUMBER_OF_RECORDS,
        "key_universe": KEY_UNIVERSE,
        "leaf_text_file": LEAF_VALUES_FILE.name,
        "keys": keys,
        "key_to_index": {k: i for i, k in enumerate(keys)},
        "key_value_db": records,
        "levels": levels,
        "root": levels[-1][0],
        "value_scheme": "sha256(0x02 || fixed13_key || fixed4_len || utf8_text)",
    }
    validate_tree_state(state, texts)
    save_tree_pickle(state)
    reloaded = load_tree_pickle()
    validate_tree_state(reloaded, texts)
    print(f"Construction (random keys + hashing): {elapsed:.3f} s")
    print("Pickle written and independently reloaded/validated.")
    return reloaded


def main():
    parser = argparse.ArgumentParser(description="Construct/load complete 7^3 Merkle tree")
    parser.add_argument(
        "--rebuild", action="store_true",
        help="Replace the saved 7^3 JSONL and pickle (destroys existing updates)",
    )
    args = parser.parse_args()

    state = construct_or_load_tree(rebuild=args.rebuild)
    print("\nMERKLE TREE 7^3")
    print("Branching factor:", state["branching_factor"])
    print("Depth:", state["depth"])
    print("Number of leaves:", state["leaf_count"])
    print("Keys sorted:", state["keys"] == sorted(state["keys"]))
    print("Tree levels:", [len(level) for level in state["levels"]])
    print("Merkle root:", state["root"].hex())
    print("JSONL file:", LEAF_VALUES_FILE.name)
    print("Pickle file:", TREE_PICKLE_FILE.name)
    print("Validation: PASSED")


if __name__ == "__main__":
    main()
