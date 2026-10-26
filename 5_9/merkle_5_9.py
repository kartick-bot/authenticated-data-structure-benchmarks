
"""Construct, save, or validate a complete 5^9 Merkle tree."""

import argparse
import gc
import hashlib
import json
import os
import pickle
import secrets
import time
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

BRANCHING_FACTOR = 5
TREE_DEPTH = 9
NUMBER_OF_RECORDS = BRANCHING_FACTOR ** TREE_DEPTH

KEY_UNIVERSE = 2**100
KEY_LENGTH_BYTES = 13
VALUE_LENGTH_BYTES = 32
HASH_LENGTH_BYTES = 32

BASE_DIR = Path(__file__).resolve().parent

LEAF_VALUES_FILE = BASE_DIR / "leaf_values_5_9.jsonl"
TREE_PICKLE_FILE = BASE_DIR / "merkle_tree_5_9.pkl"


# ============================================================
# GENERATE SORTED KEYS
# ============================================================

def generate_keys(n):

    if not 1 <= n <= KEY_UNIVERSE:
        raise ValueError("Invalid number of keys")

    unique = set()

    while len(unique) < n:
        unique.add(secrets.randbelow(KEY_UNIVERSE) + 1)

    keys = sorted(unique)
    del unique

    return keys


# ============================================================
# GENERATE JSONL FILE
# ============================================================

def create_leaf_values_file(path):

    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
        buffering=1024 * 1024
    ) as f:

        for i in range(1, NUMBER_OF_RECORDS + 1):
            f.write(
                json.dumps(f"this is leaf {i}") + "\n"
            )


def iter_leaf_values_file(path=LEAF_VALUES_FILE):

    with path.open(
        "r",
        encoding="utf-8",
        buffering=1024 * 1024
    ) as f:

        for line_no, line in enumerate(f, 1):

            try:
                text = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON at line {line_no}"
                ) from exc

            if not isinstance(text, str):
                raise ValueError(
                    f"Non-string JSON at line {line_no}"
                )

            yield text


def load_leaf_values_file():

    texts = list(iter_leaf_values_file())

    if len(texts) != NUMBER_OF_RECORDS:
        raise ValueError("Incorrect JSONL line count")

    return texts


# ============================================================
# HASHING FUNCTIONS
# ============================================================

def derive_value(key, text):

    data = text.encode("utf-8")

    return hashlib.sha256(
        b"\x02"
        + key.to_bytes(KEY_LENGTH_BYTES, "big")
        + len(data).to_bytes(4, "big")
        + data
    ).digest()


def hash_leaf(key, value):

    return hashlib.sha256(
        b"\x00"
        + key.to_bytes(KEY_LENGTH_BYTES, "big")
        + len(value).to_bytes(4, "big")
        + value
    ).digest()


def hash_internal(children):

    if len(children) != BRANCHING_FACTOR:
        raise ValueError(
            "Each internal node requires five children"
        )

    return hashlib.sha256(
        b"\x01" + b"".join(children)
    ).digest()


# ============================================================
# CONSTRUCT LEAF HASHES
# ============================================================

def build_records_and_leaves(keys, jsonl_path):

    records = {}
    leaves = []

    count = 0

    for count, text in enumerate(
        iter_leaf_values_file(jsonl_path), 1
    ):

        if count > len(keys):
            raise ValueError("Too many JSONL entries")

        key = keys[count - 1]

        value = derive_value(key, text)

        records[key] = value

        leaves.append(
            hash_leaf(key, value)
        )

    if count != NUMBER_OF_RECORDS:
        raise ValueError("Incorrect number of records")

    return records, leaves


# ============================================================
# BUILD COMPLETE MERKLE TREE
# ============================================================

def build_levels(leaves):

    if len(leaves) != NUMBER_OF_RECORDS:
        raise ValueError("Incorrect leaf count")

    levels = [leaves]

    print(
        f"Level 0: {len(leaves)} nodes",
        flush=True
    )

    while len(levels[-1]) > 1:

        children = levels[-1]

        if len(children) % BRANCHING_FACTOR != 0:
            raise ValueError("Incomplete internal node")

        parents = [
            hash_internal(
                children[i:i + BRANCHING_FACTOR]
            )
            for i in range(
                0,
                len(children),
                BRANCHING_FACTOR
            )
        ]

        levels.append(parents)

        print(
            f"Level {len(levels)-1}: "
            f"{len(parents)} nodes",
            flush=True
        )

    if len(levels) != TREE_DEPTH + 1:
        raise ValueError("Incorrect tree depth")

    if len(levels[-1]) != 1:
        raise ValueError("Incorrect root count")

    return levels


# ============================================================
# VALIDATE COMPLETE TREE
# ============================================================

def validate_tree_state(
    state,
    jsonl_path=LEAF_VALUES_FILE
):

    if (
        state["branching_factor"],
        state["depth"],
        state["leaf_count"]
    ) != (
        BRANCHING_FACTOR,
        TREE_DEPTH,
        NUMBER_OF_RECORDS
    ):
        raise ValueError("Incorrect tree configuration")

    keys = state["keys"]
    records = state["key_value_db"]
    mapping = state["key_to_index"]
    levels = state["levels"]

    n = NUMBER_OF_RECORDS

    if (
        len(keys),
        len(records),
        len(mapping),
        len(levels)
    ) != (
        n, n, n, TREE_DEPTH + 1
    ):
        raise ValueError("Incorrect stored tree sizes")

    if len(levels[0]) != n:
        raise ValueError("Incorrect number of leaves")

    # Verify sorted keys and key-index mapping
    previous = 0

    for i, (key, stored_key) in enumerate(
        zip(keys, records)
    ):

        if (
            key <= previous
            or key != stored_key
            or mapping.get(key) != i
        ):
            raise ValueError(
                f"Incorrect key ordering at leaf {i}"
            )

        previous = key

    # Verify every stored value and leaf hash
    count = 0

    for count, text in enumerate(
        iter_leaf_values_file(jsonl_path), 1
    ):

        if count > n:
            raise ValueError("Excess JSONL records")

        index = count - 1
        key = keys[index]

        expected_value = derive_value(
            key, text
        )

        expected_leaf_hash = hash_leaf(
            key, expected_value
        )

        if records[key] != expected_value:
            raise ValueError(
                f"Value mismatch at leaf {index}"
            )

        if levels[0][index] != expected_leaf_hash:
            raise ValueError(
                f"Leaf hash mismatch at index {index}"
            )

    if count != n:
        raise ValueError("Incorrect JSONL length")

    # Verify all internal node hashes
    for level in range(TREE_DEPTH):

        children = levels[level]
        parents = levels[level + 1]

        expected_count = (
            BRANCHING_FACTOR
            ** (TREE_DEPTH - level)
        )

        if len(children) != expected_count:
            raise ValueError(
                f"Incorrect nodes at level {level}"
            )

        if len(parents) != (
            expected_count // BRANCHING_FACTOR
        ):
            raise ValueError(
                f"Incorrect parent count at level {level}"
            )

        for i, parent_hash in enumerate(parents):

            start = i * BRANCHING_FACTOR

            expected_parent = hash_internal(
                children[
                    start:start + BRANCHING_FACTOR
                ]
            )

            if parent_hash != expected_parent:
                raise ValueError(
                    f"Parent hash mismatch: "
                    f"level {level+1}, index {i}"
                )

    if state["root"] != levels[-1][0]:
        raise ValueError("Merkle root mismatch")

    return True


# ============================================================
# SAVE AND LOAD PICKLE
# ============================================================

def save_tree_pickle(
    state,
    path=TREE_PICKLE_FILE
):

    temp = path.with_name(
        path.name + ".tmp"
    )

    try:

        with temp.open(
            "wb",
            buffering=1024 * 1024
        ) as f:

            pickle.dump(
                state,
                f,
                protocol=pickle.HIGHEST_PROTOCOL
            )

            f.flush()
            os.fsync(f.fileno())

        os.replace(temp, path)

    finally:
        temp.unlink(missing_ok=True)


def load_tree_pickle(
    path=TREE_PICKLE_FILE
):

    with path.open(
        "rb",
        buffering=1024 * 1024
    ) as f:

        return pickle.load(f)


# ============================================================
# PRINT TREE INFORMATION
# ============================================================

def print_summary(state, status):

    print("\nMERKLE TREE 5^9")

    print("Status:", status)

    print(
        "Branching factor:",
        state["branching_factor"]
    )

    print("Depth:", state["depth"])

    print(
        "Number of leaves:",
        state["leaf_count"]
    )

    print(
        "Tree levels:",
        [len(level) for level in state["levels"]]
    )

    print(
        "Merkle root:",
        state["root"].hex()
    )

    print(
        "JSONL file:",
        LEAF_VALUES_FILE.name
    )

    print(
        "Pickle file:",
        TREE_PICKLE_FILE.name
    )

    print(
        "JSONL bytes:",
        LEAF_VALUES_FILE.stat().st_size
    )

    print(
        "Pickle bytes:",
        TREE_PICKLE_FILE.stat().st_size
    )

    print("Validation: PASSED")


# ============================================================
# CONSTRUCT OR LOAD TREE
# ============================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Regenerate the entire dataset"
    )

    args = parser.parse_args()

    # Reuse existing tree
    if TREE_PICKLE_FILE.exists() and not args.rebuild:

        if not LEAF_VALUES_FILE.exists():
            parser.error(
                "Pickle exists but JSONL is missing"
            )

        print(
            "Loading and validating existing tree...",
            flush=True
        )

        state = load_tree_pickle()

        validate_tree_state(state)

        print_summary(
            state,
            "loaded existing tree"
        )

        return

    staged_json = BASE_DIR / (
        LEAF_VALUES_FILE.name + ".new"
    )

    staged_pickle = BASE_DIR / (
        TREE_PICKLE_FILE.name + ".new"
    )

    if args.rebuild:
        print(
            "WARNING: Rebuilding replaces existing data"
        )

    try:

        # Generate JSONL if it does not exist
        if (
            LEAF_VALUES_FILE.exists()
            and not args.rebuild
        ):

            json_path = LEAF_VALUES_FILE

            print("Reusing existing JSONL file")

        else:

            print(
                "Generating 1,953,125 JSONL lines...",
                flush=True
            )

            create_leaf_values_file(
                staged_json
            )

            json_path = staged_json

        # Construct the tree
        print(
            "Generating sorted keys and Merkle hashes...",
            flush=True
        )

        start = time.perf_counter()

        keys = generate_keys(
            NUMBER_OF_RECORDS
        )

        records, leaves = (
            build_records_and_leaves(
                keys,
                json_path
            )
        )

        levels = build_levels(leaves)

        state = {
            "format_version": 1,
            "branching_factor": BRANCHING_FACTOR,
            "depth": TREE_DEPTH,
            "leaf_count": NUMBER_OF_RECORDS,
            "key_universe": KEY_UNIVERSE,
            "leaf_text_file": LEAF_VALUES_FILE.name,
            "keys": keys,
            "key_to_index": {
                key: i
                for i, key in enumerate(keys)
            },
            "key_value_db": records,
            "levels": levels,
            "root": levels[-1][0],
            "value_scheme": (
                "sha256(0x02 || fixed13_key || "
                "fixed4_len || utf8_text)"
            )
        }

        construction_time = (
            time.perf_counter() - start
        )

        # Verify every leaf and internal node
        print(
            "Validating complete tree...",
            flush=True
        )

        validate_tree_state(
            state,
            json_path
        )

        # Save pickle
        print(
            "Writing pickle...",
            flush=True
        )

        save_tree_pickle(
            state,
            staged_pickle
        )

        # Release construction memory before reload
        del state
        del keys
        del records
        del leaves
        del levels

        gc.collect()

        # Independently reload and validate
        print(
            "Reloading and validating pickle...",
            flush=True
        )

        reloaded = load_tree_pickle(
            staged_pickle
        )

        validate_tree_state(
            reloaded,
            json_path
        )

        # Commit output files
        if json_path == staged_json:
            os.replace(
                staged_json,
                LEAF_VALUES_FILE
            )

        os.replace(
            staged_pickle,
            TREE_PICKLE_FILE
        )

        print(
            "Construction time:",
            f"{construction_time:.3f} seconds"
        )

        print_summary(
            reloaded,
            "new tree created and reloaded"
        )

    finally:

        staged_json.unlink(missing_ok=True)
        staged_pickle.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
