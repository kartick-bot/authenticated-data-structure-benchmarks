"""Benchmark existing-key updates in the saved 5^9 Merkle tree.

1,000 random existing keys (sampled with replacement). Per update:
  search_ms: in-memory key -> leaf-index lookup and retrieval of current text
  file_update_ms: open/read/rewrite/fsync/replace a WORKING 5^9 JSONL file
  proof_ms: retrieve sibling hashes; derive new value; rehash leaf and ancestors
  total_update_ms: search_ms + file_update_ms + proof_ms
  verification_ms: check the old and new root using the SAME authentication path
  proof_bytes: compact serialized update response (outside the timers)

All 1,000 updates are sequential and use the prior update's new root.
The canonical JSONL and pickle are only replaced after all updates succeed,
unless --no-save is used (in which case they are NEVER modified).

IMPORTANT: This preserves the same FULL JSONL REWRITE methodology as the 5^6
benchmark. At 5^9, every update rewrites ~44 MB; 1,000 updates therefore
write roughly 44 GB, excluding temporary copies/backups. It is not an
in-place indexed-record update, and is not a benchmark of only the changed line.
Pickle load, initial validation, initial temporary copy, final pickle commit,
serialization, and CSV writing are excluded from the timed metrics.

Needs: merkle_5_9.py, read_5_9.py, leaf_values_5_9.jsonl,
       merkle_tree_5_9.pkl in the same directory.
"""

import argparse
import csv
import json
import os
import pickle
import random
import secrets
import shutil
import statistics
import tempfile
import time
from datetime import datetime
from pathlib import Path

import merkle_5_9 as merkle
import read_5_9 as reader

BASE = Path(__file__).resolve().parent
JSON_PATH = merkle.LEAF_VALUES_FILE
PICKLE_PATH = merkle.TREE_PICKLE_FILE
CSV_PATH = BASE / "update_benchmark_5_9.csv"
PENDING = BASE / ".merkle_5_9_update.pending"
BACKUP_JSON = BASE / ".leaf_values_5_9.jsonl.update_bak"
BACKUP_PICKLE = BASE / ".merkle_tree_5_9.pkl.update_bak"
CSV_COLUMNS = [
    "operation", "key", "leaf_index", "old_text", "new_text",
    "search_ms", "file_update_ms", "proof_ms", "total_update_ms",
    "verification_ms", "proof_bytes", "old_root", "new_root", "verified"
]


def recover_if_interrupted():
    """Restore both original files if a previous two-file commit was interrupted."""
    if not PENDING.exists():
        return
    if not BACKUP_JSON.exists() or not BACKUP_PICKLE.exists():
        raise RuntimeError("Pending commit requires original recovery backups")
    os.replace(BACKUP_JSON, JSON_PATH)
    os.replace(BACKUP_PICKLE, PICKLE_PATH)
    PENDING.unlink()
    print("Recovered canonical JSONL and pickle from interrupted commit")


def load_checked_state():
    state = merkle.load_tree_pickle()
    merkle.validate_tree_state(state, JSON_PATH)  # stream JSONL; avoid list of 2M strings
    return state


def get_current_text(original_store, changed_texts, index):
    if index in changed_texts:
        return changed_texts[index]
    return original_store[index]


def search_existing_key(state, original_store, changed_texts, key):
    index = state["key_to_index"].get(key)
    if index is None:
        raise KeyError(f"Cannot update missing key: {key}")
    return index, get_current_text(original_store, changed_texts, index)


def edit_jsonl_line(path, index, old_text, new_text):
    """Full-file JSONL rewrite, matching the 5^6 benchmark's file I/O model."""
    with path.open("r", encoding="utf-8") as handle:
        lines = handle.readlines()
    if len(lines) != merkle.NUMBER_OF_RECORDS:
        raise RuntimeError("Wrong JSONL line count in working copy")
    stored_text = json.loads(lines[index])
    if stored_text != old_text:
        raise RuntimeError("Working JSONL text differs from authenticated state")
    if stored_text == new_text:
        raise ValueError("An update must change the text")
    lines[index] = json.dumps(new_text, ensure_ascii=False) + "\n"
    staged = path.with_name(path.name + ".tmp")
    try:
        with staged.open("w", encoding="utf-8", newline="\n") as handle:
            handle.writelines(lines)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staged, path)
    finally:
        staged.unlink(missing_ok=True)
    return stored_text


def compute_update_proof(state, key, index, old_text, new_text):
    old_value = state["key_value_db"][key]
    if old_value != merkle.derive_value(key, old_text):
        raise RuntimeError("Old text does not match committed value")
    # Path must be obtained from the OLD tree, before mutating any hashes.
    path = reader.generate_path_from_saved_tree_index(state, index)
    new_value = merkle.derive_value(key, new_text)
    state["key_value_db"][key] = new_value
    position = index
    state["levels"][0][position] = merkle.hash_leaf(key, new_value)
    b = state["branching_factor"]
    for level in range(state["depth"]):
        group_start = (position // b) * b
        position //= b
        state["levels"][level + 1][position] = merkle.hash_internal(
            state["levels"][level][group_start:group_start + b]
        )
    state["root"] = state["levels"][-1][0]
    return {
        "key": key, "index": index, "old_text": old_text,
        "new_text": new_text, "new_root": state["root"], "proof": path
    }


def verify_update(response, trusted_old_root):
    """Independent verifier: no access to full tree, JSONL or key-index mapping."""
    try:
        key = response["key"]
        path = response["proof"]
        new_root = response["new_root"]
        if response["old_text"] == response["new_text"]:
            return False
        if not isinstance(new_root, bytes) or len(new_root) != 32:
            return False
        if reader.authenticated_index(path) != response["index"]:
            return False
        old_value = merkle.derive_value(key, response["old_text"])
        new_value = merkle.derive_value(key, response["new_text"])
        if old_value == new_value or new_root == trusted_old_root:
            return False
        if not reader.verify_membership_proof(key, old_value, path, trusted_old_root):
            return False
        return reader.verify_membership_proof(key, new_value, path, new_root)
    except (KeyError, ValueError, IndexError, TypeError, OverflowError):
        return False


def serialize_update(response):
    old_bytes = response["old_text"].encode("utf-8")
    new_bytes = response["new_text"].encode("utf-8")
    b, d = merkle.BRANCHING_FACTOR, merkle.TREE_DEPTH
    return (
        bytes((1, ord("U"), b, d))
        + reader.encode_key(response["key"])
        + response["index"].to_bytes(4, "big")
        + response["new_root"]
        + len(old_bytes).to_bytes(4, "big") + old_bytes
        + len(new_bytes).to_bytes(4, "big") + new_bytes
        + reader.encode_path(response["proof"], b, d)
    )


def deserialize_update(blob):
    r = reader.WireReader(blob)
    if tuple(r.take(4)) != (1, ord("U"), merkle.BRANCHING_FACTOR, merkle.TREE_DEPTH):
        raise ValueError("Incorrect update proof header")
    key = int.from_bytes(r.take(merkle.KEY_LENGTH_BYTES), "big")
    index = int.from_bytes(r.take(4), "big")
    new_root = r.take(32)
    old_text = r.take(int.from_bytes(r.take(4), "big")).decode("utf-8")
    new_text = r.take(int.from_bytes(r.take(4), "big")).decode("utf-8")
    proof = reader.decode_path(r, merkle.BRANCHING_FACTOR, merkle.TREE_DEPTH)
    r.finish()
    return {
        "key": key, "index": index, "old_text": old_text,
        "new_text": new_text, "new_root": new_root, "proof": proof
    }


def commit_final_files(state, working_jsonl):
    """Commit validated final state with durable recovery backups.

    The caller already validated EVERY hash against working_jsonl. At 5^9,
    simultaneously deserializing an additional 251 MB pickle can exhaust RAM,
    so we avoid duplicating the entire tree here. Run merkle_5_9.py afterwards
    if an independent reload/rehash is desired.
    """
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup_dir = BASE / "update_benchmark_backups" / stamp
    backup_dir.mkdir(parents=True, exist_ok=False)
    original_json = backup_dir / JSON_PATH.name
    original_pickle = backup_dir / PICKLE_PATH.name
    shutil.copy2(JSON_PATH, original_json)
    shutil.copy2(PICKLE_PATH, original_pickle)
    staged_json = BASE / ".leaf_values_5_9.jsonl.new"
    staged_pickle = BASE / ".merkle_tree_5_9.pkl.new"
    try:
        shutil.copy2(working_jsonl, staged_json)
        with staged_pickle.open("wb") as handle:
            pickle.dump(state, handle, protocol=pickle.HIGHEST_PROTOCOL)
            handle.flush()
            os.fsync(handle.fileno())
        if staged_json.stat().st_size != working_jsonl.stat().st_size:
            raise RuntimeError("Staged JSONL file size mismatch")
        if staged_pickle.stat().st_size == 0:
            raise RuntimeError("Empty staged pickle")

        # Recovery paths refer to unchanged backup inodes; use hardlinks where
        # supported to avoid two extra copies of a very large pickle.
        try:
            os.link(original_json, BACKUP_JSON)
            os.link(original_pickle, BACKUP_PICKLE)
        except OSError:
            BACKUP_JSON.unlink(missing_ok=True)
            BACKUP_PICKLE.unlink(missing_ok=True)
            shutil.copy2(original_json, BACKUP_JSON)
            shutil.copy2(original_pickle, BACKUP_PICKLE)
        PENDING.write_text("Two-file update commit in progress\n")
        os.replace(staged_json, JSON_PATH)
        os.replace(staged_pickle, PICKLE_PATH)
        PENDING.unlink()
        BACKUP_JSON.unlink(missing_ok=True)
        BACKUP_PICKLE.unlink(missing_ok=True)
        return backup_dir
    except Exception:
        if PENDING.exists():
            recover_if_interrupted()
        raise
    finally:
        staged_json.unlink(missing_ok=True)
        staged_pickle.unlink(missing_ok=True)


def mean_sd(values):
    return statistics.mean(values), statistics.stdev(values) if len(values) > 1 else 0.0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--no-save", action="store_true",
                        help="Keep original JSONL and pickle unchanged")
    args = parser.parse_args()
    if args.runs < 2:
        parser.error("At least two updates are required")
    recover_if_interrupted()

    print("Loading and validating the 5^9 pickle / JSONL...", flush=True)
    state = load_checked_state()
    # Byte-buffer + line offsets; no 1.95M decoded text strings in RAM.
    original_store = reader.CompactJsonlStore(JSON_PATH, merkle.NUMBER_OF_RECORDS)
    changed_texts = {}  # only touched leaves; also handles repeated keys
    initial_root = state["root"]
    rng = random.Random(args.seed)
    sampled_keys = [rng.choice(state["keys"]) for _ in range(args.runs)]
    run_tag = secrets.token_hex(4)

    # Untimed warm-up without mutating the tree.
    warm_key = sampled_keys[0]
    warm_index = state["key_to_index"][warm_key]
    warm_text = original_store[warm_index]
    warm_path = reader.generate_path_from_saved_tree_index(state, warm_index)
    if not reader.verify_membership_proof(
        warm_key, merkle.derive_value(warm_key, warm_text), warm_path, state["root"]
    ):
        raise RuntimeError("Warm-up membership verification failed")

    results = []
    with tempfile.TemporaryDirectory(prefix=".merkle_update_5_9_", dir=BASE) as scratch:
        working_jsonl = Path(scratch) / JSON_PATH.name
        shutil.copy2(JSON_PATH, working_jsonl)  # not timed
        for operation, key in enumerate(sampled_keys, 1):
            trusted_old_root = state["root"]
            # 1. Search for existing key and current (possibly updated) value.
            t0 = time.perf_counter_ns()
            index, old_text = search_existing_key(state, original_store, changed_texts, key)
            t1 = time.perf_counter_ns()
            new_text = f"this is leaf {index + 1} | update {run_tag}-{operation:06d}"

            # 2. Real file I/O on working copy; FULL JSONL rewrite + fsync.
            t_file = time.perf_counter_ns()
            file_old_text = edit_jsonl_line(working_jsonl, index, old_text, new_text)
            t2 = time.perf_counter_ns()
            if file_old_text != old_text:
                raise AssertionError("Unexpected JSONL text before update")

            # 3. Proof construction and nine ancestor rehashes.
            response = compute_update_proof(state, key, index, old_text, new_text)
            t3 = time.perf_counter_ns()
            valid = verify_update(response, trusted_old_root)
            t4 = time.perf_counter_ns()
            if not valid:
                raise AssertionError(f"Update {operation} failed verification")

            # Untimed complete proof serialization and independent roundtrip.
            binary_proof = serialize_update(response)
            decoded_proof = deserialize_update(binary_proof)
            if decoded_proof != response or not verify_update(decoded_proof, trusted_old_root):
                raise AssertionError(f"Update {operation} failed serialization check")
            changed_texts[index] = new_text
            search_ms = (t1 - t0) / 1e6
            file_update_ms = (t2 - t_file) / 1e6
            proof_ms = (t3 - t2) / 1e6
            results.append({
                "operation": operation, "key": key, "leaf_index": index,
                "old_text": old_text, "new_text": new_text,
                "search_ms": search_ms, "file_update_ms": file_update_ms,
                "proof_ms": proof_ms,
                "total_update_ms": search_ms + file_update_ms + proof_ms,
                "verification_ms": (t4 - t3) / 1e6,
                "proof_bytes": len(binary_proof),
                "old_root": trusted_old_root.hex(),
                "new_root": state["root"].hex(), "verified": True,
            })
            if operation % 100 == 0:
                print(f"Verified {operation}/{args.runs} updates", flush=True)

        # Independently validate every leaf/hash using the final temporary file.
        print("Validating final updated Merkle tree...", flush=True)
        merkle.validate_tree_state(state, working_jsonl)
        if state["root"] == initial_root:
            raise RuntimeError("Final root unexpectedly equals the original root")
        if args.no_save:
            print("--no-save: original JSONL and pickle are unchanged")
        else:
            backup_dir = commit_final_files(state, working_jsonl)
            print("Original dataset backed up in:", backup_dir)
            print("Final JSONL and pickle saved")

    with CSV_PATH.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(results)

    print("\nMERKLE TREE UPDATE BENCHMARK (5^9)")
    print("Branching factor:", merkle.BRANCHING_FACTOR)
    print("Tree depth:", merkle.TREE_DEPTH)
    print("Number of leaves:", merkle.NUMBER_OF_RECORDS)
    print("Update operations:", len(results))
    print("Distinct keys:", len(set(sampled_keys)))
    print("\nTOTAL UPDATE = SEARCH + JSONL FILE UPDATE + PROOF")
    print("TIMINGS (milliseconds; mean +/- sample SD)")
    for description, field in [
        ("Search", "search_ms"), ("JSONL file update", "file_update_ms"),
        ("Proof computation", "proof_ms"), ("TOTAL UPDATE", "total_update_ms"),
        ("Proof verification", "verification_ms"),
    ]:
        mean, sd = mean_sd([r[field] for r in results])
        print(f"{description:<25} {mean:.6f} +/- {sd:.6f}")
    sizes = [r["proof_bytes"] for r in results]
    mean, sd = mean_sd(sizes)
    print("\nSERIALIZED UPDATE PROOF (bytes)")
    print(f"Mean +/- SD: {mean:.3f} +/- {sd:.3f}")
    print(f"Min / Max: {min(sizes)} / {max(sizes)}")
    print("Initial root:", initial_root.hex())
    print("Final root:  ", state["root"].hex())
    print("CSV:", CSV_PATH.name)
    print(f"All {len(results)} sequential update proofs verified successfully")
    print("Note: pickle save, CSV output and proof serialization excluded from timers")


if __name__ == "__main__":
    main()
