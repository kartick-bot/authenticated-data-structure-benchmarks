"""Construct, store, or validate the complete sorted 7^9 Merkle tree.

Outputs (in the same folder as this script):
    leaf_values_7_9.jsonl    40,353,607 JSON string lines
    merkle_tree_7_9.pkl      keys, compact records, packed hash levels, Merkle root

Leaf and internal hashing and saved state keys are compatible with the
existing Merkle baselines; the 7^9 saved state uses packed hash/value arrays
for lower RAM while retaining the same index/slice/assignment APIs.
Construction and validation stream
through the JSONL file to avoid allocating millions of text strings.

Commands:
    python3 merkle_7_9.py                # create or verify saved tree
    python3 merkle_7_9.py --rebuild      # replace both files with fresh data

SECURITY: Only unpickle files you created or otherwise trust.
"""

import argparse
import gc
import heapq
import resource
import shutil
import sys
import tempfile
import hashlib
import json
import os
import pickle
import secrets
import time
from pathlib import Path


BRANCHING_FACTOR = 7
TREE_DEPTH = 9
NUMBER_OF_RECORDS = BRANCHING_FACTOR ** TREE_DEPTH
KEY_UNIVERSE = 2**100
KEY_LENGTH_BYTES = 13
VALUE_LENGTH_BYTES = 32
HASH_LENGTH_BYTES = 32

BASE_DIR = Path(__file__).resolve().parent
LEAF_VALUES_FILE = BASE_DIR / "leaf_values_7_9.jsonl"
TREE_PICKLE_FILE = BASE_DIR / "merkle_tree_7_9.pkl"


# Packed storage substantially reduces peak RAM compared with keeping tens of
# millions of individual 32-byte Python bytes objects and dictionary entries.
# Public API remains: levels[level][i], levels[level][start:end], len(level),
# and key_value_db[key] including assignment during subsequent updates.
class PackedHashes:
    __slots__ = ("data",)

    def __init__(self, count):
        self.data = bytearray(count * HASH_LENGTH_BYTES)

    def __len__(self):
        return len(self.data) // HASH_LENGTH_BYTES

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(len(self)))]
        if not isinstance(index, int):
            raise TypeError("Hash index must be an integer")
        if index < 0:
            index += len(self)
        if not 0 <= index < len(self):
            raise IndexError(index)
        offset = index * HASH_LENGTH_BYTES
        return bytes(self.data[offset:offset + HASH_LENGTH_BYTES])

    def __setitem__(self, index, value):
        if not isinstance(index, int):
            raise TypeError("Hash index must be an integer")
        if index < 0:
            index += len(self)
        if not 0 <= index < len(self):
            raise IndexError(index)
        if len(value) != HASH_LENGTH_BYTES:
            raise ValueError("Expected a 32-byte SHA-256 digest")
        offset = index * HASH_LENGTH_BYTES
        self.data[offset:offset + HASH_LENGTH_BYTES] = value


class KeyValueDB:
    """Dict-like mapping of keys to packed SHA-256 values, with O(1) access."""
    __slots__ = ("keys", "index", "data")

    def __init__(self, keys, index):
        self.keys = keys
        self.index = index
        self.data = bytearray(len(keys) * VALUE_LENGTH_BYTES)

    def __len__(self):
        return len(self.keys)

    def __iter__(self):
        return iter(self.keys)

    def __getitem__(self, key):
        pos = self.index[key] * VALUE_LENGTH_BYTES
        return bytes(self.data[pos:pos + VALUE_LENGTH_BYTES])

    def __setitem__(self, key, value):
        if len(value) != VALUE_LENGTH_BYTES:
            raise ValueError("Expected a 32-byte SHA-256 value")
        pos = self.index[key] * VALUE_LENGTH_BYTES
        self.data[pos:pos + VALUE_LENGTH_BYTES] = value


# Pickle needs a stable importable class name when executed as a script.
# When run directly, alias __main__ as merkle_7_9 for serialization.
if __name__ == "__main__":
    sys.modules.setdefault("merkle_7_9", sys.modules[__name__])
PackedHashes.__module__ = "merkle_7_9"
KeyValueDB.__module__ = "merkle_7_9"

def peak_rss_gib():
    """Peak resident RAM so far; informational only."""
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / (1024 ** 3) if sys.platform == "darwin" else peak / (1024 ** 2)


def _read_sorted_chunk(path):
    """Yield 13-byte big-endian keys from a disk-based sorted chunk."""
    with path.open("rb", buffering=1024 * 1024) as stream:
        while True:
            word = stream.read(KEY_LENGTH_BYTES)
            if not word:
                return
            if len(word) != KEY_LENGTH_BYTES:
                raise ValueError(f"Truncated key chunk: {path}")
            yield int.from_bytes(word, "big")


def generate_keys(n, chunk_size=1_000_000):
    """Generate globally sorted unique 100-bit keys with bounded sort RAM.

    Write sorted million-key chunks to temporary files, then merge them.
    This avoids the huge Python set used by the smaller tree builders.
    Uniform independent keys collide with probability less than 10^-15 for
    this dataset; nevertheless a collision is detected and never accepted.
    """
    if not 1 <= n <= KEY_UNIVERSE or chunk_size < 1:
        raise ValueError("Invalid key count or chunk size")

    with tempfile.TemporaryDirectory(prefix=".keychunks_7_9_", dir=BASE_DIR) as tmp:
        chunk_paths = []
        remaining = n
        chunk_id = 0
        while remaining:
            size = min(chunk_size, remaining)
            chunk = [secrets.randbelow(KEY_UNIVERSE) + 1 for _ in range(size)]
            chunk.sort()
            path = Path(tmp) / f"part_{chunk_id:04d}.bin"
            with path.open("wb", buffering=1024 * 1024) as stream:
                for key in chunk:
                    stream.write(key.to_bytes(KEY_LENGTH_BYTES, "big"))
            chunk_paths.append(path)
            remaining -= size
            chunk_id += 1
            del chunk
            if chunk_id % 10 == 0 or remaining == 0:
                print(f"Generated {n-remaining:,}/{n:,} sorted random keys "
                      f"(peak RAM {peak_rss_gib():.2f} GiB)", flush=True)

        keys = [0] * n
        previous = 0
        iterators = [_read_sorted_chunk(path) for path in chunk_paths]
        for i, key in enumerate(heapq.merge(*iterators)):
            if key <= previous:
                raise ValueError("Repeated random key detected; rerun construction")
            keys[i] = key
            previous = key

        if keys[0] == 0 or keys[-1] == 0:
            raise ValueError("Key merge did not generate exactly N keys")
        print(f"Key merge complete (peak RAM {peak_rss_gib():.2f} GiB)", flush=True)
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

    Warning: returns ~40 million strings and consumes substantial RAM.
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
        raise ValueError("A 7-ary internal node requires exactly seven children")
    return hashlib.sha256(b"\x01" + b"".join(children)).digest()


def build_records_and_leaves(keys, key_to_index, jsonl_path):
    """Stream records into compact 32-byte slots, avoiding a 40m-entry dict."""
    records = KeyValueDB(keys, key_to_index)
    leaves = PackedHashes(len(keys))
    count = 0
    for count, text in enumerate(iter_leaf_values_file(jsonl_path), 1):
        if count > len(keys):
            raise ValueError("JSONL has more entries than leaves")
        key = keys[count - 1]
        value = derive_value(key, text)
        records[key] = value
        leaves[count - 1] = hash_leaf(key, value)
        if count % 5_000_000 == 0:
            print(f"Hashed {count:,}/{NUMBER_OF_RECORDS:,} leaves "
                  f"(peak RAM {peak_rss_gib():.2f} GiB)", flush=True)
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
        parent = PackedHashes(len(child) // BRANCHING_FACTOR)
        stride = BRANCHING_FACTOR * HASH_LENGTH_BYTES
        for i in range(len(parent)):
            start = i * stride
            parent[i] = hashlib.sha256(
                b"\x01" + child.data[start:start + stride]
            ).digest()
        levels.append(parent)
        print(f"Level {len(levels) - 1}: {len(parent)} nodes", flush=True)
    if len(levels) != TREE_DEPTH + 1 or len(levels[-1]) != 1:
        raise ValueError("Incorrect depth or root")
    return levels

def validate_tree_state(state, jsonl_path=LEAF_VALUES_FILE):
    """Independently validate keys, JSONL, all hashes and root in O(n) time.

    Streaming validation avoids creating duplicate 40m-element arrays.
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
    if not isinstance(records, KeyValueDB) or records.keys is not keys or records.index is not mapping:
        raise ValueError("Packed key-value database has inconsistent indexes")
    if any(not isinstance(level, PackedHashes) for level in levels):
        raise ValueError("Expected packed SHA-256 levels")
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
            begin = start * HASH_LENGTH_BYTES
            end = begin + BRANCHING_FACTOR * HASH_LENGTH_BYTES
            digest = hashlib.sha256(b"\x01" + children.data[begin:end]).digest()
            if parent_hash != digest:
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
    print("\nMERKLE TREE 7^9")
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
    print("Peak resident RAM (GiB):", f"{peak_rss_gib():.2f}")
    print("Validation: PASSED")


def main():
    parser = argparse.ArgumentParser(description="Construct/verify complete 7^9 Merkle tree")
    parser.add_argument("--rebuild", action="store_true", help="Replace existing data; destroys saved updates")
    parser.add_argument("--key-chunk-size", type=int, default=1_000_000,
                        help="Number of keys per external-sort run (default: 1000000)")
    args = parser.parse_args()

    if TREE_PICKLE_FILE.exists() and not args.rebuild:
        if not LEAF_VALUES_FILE.exists():
            parser.error("Pickle exists but JSONL file is missing")
        print("Loading existing pickle and verifying all 40,353,607 leaves...", flush=True)
        state = load_tree_pickle()
        validate_tree_state(state)
        print_summary(state, "loaded existing tree")
        return

    # Generate JSONL as part of THIS construction script; stage it before commit.
    staged_json = BASE_DIR / (LEAF_VALUES_FILE.name + ".new")
    staged_pickle = BASE_DIR / (TREE_PICKLE_FILE.name + ".new")
    if args.rebuild:
        print("WARNING: --rebuild replaces existing JSONL, keys and pickle.", flush=True)

    available = shutil.disk_usage(BASE_DIR).free
    print(f"Disk available: {available / (1024 ** 3):.2f} GiB", flush=True)
    if available < 6 * 1024 ** 3:
        raise OSError("Not enough free disk space for the 7^9 staged JSONL and pickle; free at least 6 GiB")
    if available < 8 * 1024 ** 3:
        print("WARNING: Less than 8 GiB free; disk space may be tight.", flush=True)
    try:
        if LEAF_VALUES_FILE.exists() and not args.rebuild:
            json_path = LEAF_VALUES_FILE
            print("JSONL: reusing existing file", flush=True)
        else:
            print("Generating 40,353,607 JSONL lines...", flush=True)
            create_leaf_values_file(staged_json)
            json_path = staged_json

        print("Generating sorted keys, values and tree hashes...", flush=True)
        t0 = time.perf_counter()
        keys = generate_keys(NUMBER_OF_RECORDS, chunk_size=args.key_chunk_size)
        key_to_index = {key: i for i, key in enumerate(keys)}
        records, leaves = build_records_and_leaves(keys, key_to_index, json_path)
        levels = build_levels(leaves)
        state = {
            "format_version": 1,
            "branching_factor": BRANCHING_FACTOR,
            "depth": TREE_DEPTH,
            "leaf_count": NUMBER_OF_RECORDS,
            "key_universe": KEY_UNIVERSE,
            "leaf_text_file": LEAF_VALUES_FILE.name,
            "keys": keys,
            "key_to_index": key_to_index,
            "key_value_db": records,
            "levels": levels,
            "root": levels[-1][0],
            "value_scheme": "sha256(0x02 || fixed13_key || fixed4_len || utf8_text)",
        }
        construction_s = time.perf_counter() - t0
        print(f"Validating full tree before saving "
              f"(peak RAM {peak_rss_gib():.2f} GiB)...", flush=True)
        validate_tree_state(state, json_path)

        print(f"Writing pickle (peak RAM {peak_rss_gib():.2f} GiB)...", flush=True)
        save_tree_pickle(state, staged_pickle)
        # Drop large in-memory tree before reloading it independently.
        del state, keys, key_to_index, records, leaves, levels
        gc.collect()

        print(f"Reloading pickle and independently validating all hashes "
              f"(peak RAM {peak_rss_gib():.2f} GiB)...", flush=True)
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
