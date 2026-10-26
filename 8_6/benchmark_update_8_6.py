"""Benchmark 1,000 authenticated updates of existing keys in a saved 8^6 Merkle tree.

For EACH update measure separately:
    search_ms       = in-memory existing-key lookup
    file_update_ms  = OPEN, READ and REWRITE the working JSONL file, including fsync
    proof_ms        = construct Merkle path + update leaf and ancestors
    total_update_ms = search_ms + file_update_ms + proof_ms
    verification_ms = independently check old-root -> new-root proof (EXCLUDED from total)
    proof_bytes     = length of complete encoded update response

Each key is sampled WITH replacement. Updates are sequential and use the new
root resulting from the previous verified update. The actual 262144-line JSONL
is edited on disk per operation in an isolated working directory. This makes
--no-save exercise real file I/O while leaving original files untouched.

On successful completion (unless --no-save), the final JSONL + pickle are
committed ONCE, outside the benchmark timings, with original-file backup.
Pickle persistence, CSV output, wire encoding/decoding, and initial loading
are NOT included in total_update_ms. No concurrent readers/writers are allowed.

Usage:
    python3 benchmark_update_8_6.py --runs 1000 --no-save
    python3 benchmark_update_8_6.py --runs 1000

Requires merkle_8_6.py, read_8_6.py, leaf_values_8_6.jsonl,
and merkle_tree_8_6.pkl in the same directory.
"""

import argparse
import csv
import hashlib
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

import merkle_8_6 as merkle
import read_8_6 as reader

BASE = Path(__file__).resolve().parent
JSON_PATH = BASE / "leaf_values_8_6.jsonl"
PICKLE_PATH = BASE / "merkle_tree_8_6.pkl"
CSV_PATH = BASE / "update_benchmark_8_6.csv"
PENDING = BASE / ".merkle_8_6_update.pending"
BACKUP_JSON = BASE / ".leaf_values_8_6.jsonl.update_bak"
BACKUP_PICKLE = BASE / ".merkle_tree_8_6.pkl.update_bak"

CSV_COLUMNS = [
    "operation", "key", "leaf_index", "old_text", "new_text",
    "search_ms", "file_update_ms", "proof_ms", "total_update_ms",
    "verification_ms", "proof_bytes", "old_root", "new_root", "verified",
]


def recover_if_interrupted():
    """Roll back if an earlier two-file commit was interrupted."""
    if not PENDING.exists():
        return
    if not BACKUP_JSON.exists() or not BACKUP_PICKLE.exists():
        raise RuntimeError("Pending update missing backups: restore manually")
    os.replace(BACKUP_JSON, JSON_PATH)
    os.replace(BACKUP_PICKLE, PICKLE_PATH)
    PENDING.unlink()
    print("Recovered JSONL and pickle from interrupted commit.")


def load_checked_state():
    state = merkle.load_tree_pickle()
    texts = merkle.load_leaf_values_file()
    merkle.validate_tree_state(state, texts)
    return state, texts


def lookup_key(state, key):
    """Same key-to-index dictionary search strategy as membership reads."""
    index = state["key_to_index"].get(key)
    if index is None:
        raise KeyError(f"Cannot update absent key: {key}")
    return index


def edit_jsonl_line(path, index, expected_old_text, new_text):
    """Open JSONL on disk and replace exactly one indexed JSON-string line.

    JSONL lines can change length, so we rewrite the 262144-line file to a temp
    file in the SAME directory and atomically replace the working JSONL.
    Includes open/read/parse/write/flush/fsync/replace in file_update_ms.
    """
    with path.open("r", encoding="utf-8") as file:
        lines = file.readlines()
    if len(lines) != merkle.NUMBER_OF_RECORDS:
        raise ValueError("Unexpected number of JSONL lines")
    if not 0 <= index < len(lines):
        raise IndexError("Leaf index outside JSONL range")
    old_text = json.loads(lines[index])
    if old_text != expected_old_text:
        raise RuntimeError("JSONL text diverged from authenticated tree state")
    if old_text == new_text:
        raise ValueError("An update must change the text")
    lines[index] = json.dumps(new_text, ensure_ascii=False) + "\n"
    temp_path = path.with_name(path.name + ".tmp")
    try:
        with temp_path.open("w", encoding="utf-8", newline="\n") as file:
            file.writelines(lines)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)
    return old_text



def path_for_index(state, index):
    """Read sibling hashes from stored levels without a second key lookup."""
    proof = []
    b = state["branching_factor"]
    for level in range(state["depth"]):
        siblings_start = (index // b) * b
        child_position = index % b
        nodes = state["levels"][level]
        siblings = [
            (position, nodes[siblings_start + position])
            for position in range(b) if position != child_position
        ]
        proof.append((child_position, siblings))
        index //= b
    return proof

def compute_update_proof(state, key, index, old_text, new_text):
    """Construct path from OLD tree and update only selected leaf + ancestors."""
    old_value = state["key_value_db"][key]
    if old_value != merkle.derive_value(key, old_text):
        raise RuntimeError("Authenticated old value does not match JSONL text")
    path = path_for_index(state, index)
    new_value = merkle.derive_value(key, new_text)
    state["key_value_db"][key] = new_value
    position = index
    state["levels"][0][position] = merkle.hash_leaf(key, new_value)
    b = state["branching_factor"]
    for level in range(state["depth"]):
        child_start = (position // b) * b
        position //= b
        state["levels"][level + 1][position] = merkle.hash_internal(
            state["levels"][level][child_start:child_start + b]
        )
    state["root"] = state["levels"][-1][0]
    return {
        "key": key,
        "index": index,
        "old_text": old_text,
        "new_text": new_text,
        "new_root": state["root"],
        "proof": path,
    }


def verify_update(response, trusted_old_root):
    """Verifier needs only old root, update response, and public hash rules."""
    try:
        key = response["key"]
        old_text = response["old_text"]
        new_text = response["new_text"]
        new_root = response["new_root"]
        path = response["proof"]
        if old_text == new_text or not isinstance(new_root, bytes) or len(new_root) != 32:
            return False
        if reader.authenticated_index(path) != response["index"]:
            return False
        old_value = merkle.derive_value(key, old_text)
        new_value = merkle.derive_value(key, new_text)
        return (
            old_value != new_value
            and reader.verify_membership_proof(key, old_value, path, trusted_old_root)
            and reader.verify_membership_proof(key, new_value, path, new_root)
            and new_root != trusted_old_root
        )
    except (ValueError, TypeError, KeyError, IndexError, OverflowError):
        return False


def serialize_update(response, b, d):
    """Binary proof: header, key, index, new root, texts, authentication path."""
    old = response["old_text"].encode("utf-8")
    new = response["new_text"].encode("utf-8")
    if len(old) >= 2**32 or len(new) >= 2**32:
        raise ValueError("Text too long")
    return (
        bytes((1, ord("U"), b, d))
        + reader.encode_key(response["key"])
        + response["index"].to_bytes(4, "big")
        + response["new_root"]
        + len(old).to_bytes(4, "big") + old
        + len(new).to_bytes(4, "big") + new
        + reader.encode_path(response["proof"], b, d)
    )


def deserialize_update(data):
    wire = reader.WireReader(data)
    version, kind, b, d = wire.take(4)
    if (version, kind, b, d) != (1, ord("U"), merkle.BRANCHING_FACTOR, merkle.TREE_DEPTH):
        raise ValueError("Incorrect update proof format")
    key = int.from_bytes(wire.take(merkle.KEY_LENGTH_BYTES), "big")
    index = int.from_bytes(wire.take(4), "big")
    new_root = wire.take(32)
    old_len = int.from_bytes(wire.take(4), "big")
    old_text = wire.take(old_len).decode("utf-8")
    new_len = int.from_bytes(wire.take(4), "big")
    new_text = wire.take(new_len).decode("utf-8")
    proof = reader.decode_path(wire, b, d)
    wire.finish()
    return {"key": key, "index": index, "old_text": old_text,
            "new_text": new_text, "new_root": new_root, "proof": proof}


def commit_final_files(texts, state, working_jsonl):
    """Back up canonical pair and safely commit final JSONL and pickle once."""
    merkle.validate_tree_state(state, texts)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup_dir = BASE / "update_benchmark_backups" / stamp
    backup_dir.mkdir(parents=True, exist_ok=False)
    shutil.copy2(JSON_PATH, backup_dir / JSON_PATH.name)
    shutil.copy2(PICKLE_PATH, backup_dir / PICKLE_PATH.name)

    staged_json = BASE / ".leaf_values_8_6.jsonl.new"
    staged_pickle = BASE / ".merkle_tree_8_6.pkl.new"
    try:
        shutil.copy2(working_jsonl, staged_json)
        with staged_pickle.open("wb") as handle:
            pickle.dump(state, handle, protocol=pickle.HIGHEST_PROTOCOL)
            handle.flush()
            os.fsync(handle.fileno())
        with staged_pickle.open("rb") as handle:
            check_state = pickle.load(handle)
        with staged_json.open("r", encoding="utf-8") as handle:
            check_texts = [json.loads(line) for line in handle]
        merkle.validate_tree_state(check_state, check_texts)
        if check_texts != texts or check_state["root"] != state["root"]:
            raise RuntimeError("Staged file validation failed")

        shutil.copy2(JSON_PATH, BACKUP_JSON)
        shutil.copy2(PICKLE_PATH, BACKUP_PICKLE)
        PENDING.write_text("Restore update_bak files if commit interrupted\n")
        os.replace(staged_json, JSON_PATH)
        os.replace(staged_pickle, PICKLE_PATH)
        saved_state, saved_texts = load_checked_state()
        if saved_texts != texts or saved_state["root"] != state["root"]:
            raise RuntimeError("Persisted state mismatch")
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


def stats(values):
    return statistics.mean(values), (
        statistics.stdev(values) if len(values) > 1 else 0.0
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--no-save", action="store_true",
                        help="Run real file writes on a temporary JSONL copy; do not change originals")
    args = parser.parse_args()
    if args.runs < 2:
        parser.error("At least two runs are needed for sample SD")

    recover_if_interrupted()
    state, texts = load_checked_state()
    texts = list(texts)
    trusted_initial_root = state["root"]
    rng = random.Random(args.seed)
    keys = [rng.choice(state["keys"]) for _ in range(args.runs)]
    tag = secrets.token_hex(4)

    # Untimed warm-up on a distinct copied state, without changing the live tree.
    warm_state = dict(state)
    warm_state["key_value_db"] = dict(state["key_value_db"])
    warm_state["levels"] = [list(level) for level in state["levels"]]
    warm_key = keys[0]
    warm_index = lookup_key(warm_state, warm_key)
    warm_text = f"this is leaf {warm_index + 1} | warmup {tag}"
    warm_proof = compute_update_proof(
        warm_state, warm_key, warm_index, texts[warm_index], warm_text
    )
    if not verify_update(warm_proof, state["root"]):
        raise AssertionError("Warmup failed")

    results = []
    with tempfile.TemporaryDirectory(prefix=".merkle_update_8_6_", dir=BASE) as working_dir:
        working_jsonl = Path(working_dir) / JSON_PATH.name
        shutil.copy2(JSON_PATH, working_jsonl)

        for operation, key in enumerate(keys, 1):
            old_root = state["root"]

            # 1: SEARCH the existing key (in memory, as in our read benchmark).
            t0 = time.perf_counter_ns()
            index = lookup_key(state, key)
            old_text = texts[index]
            t1 = time.perf_counter_ns()

            # Unique text per operation, prepared OUTSIDE the disk I/O timer.
            new_text = f"this is leaf {index + 1} | update {tag}-{operation:06d}"

            # 2: OPEN JSONL, find indexed line, REWRITE file, flush, fsync.
            t_file = time.perf_counter_ns()
            old_from_file = edit_jsonl_line(working_jsonl, index, old_text, new_text)
            t2 = time.perf_counter_ns()
            if old_from_file != old_text:
                raise AssertionError("JSONL old content mismatch")

            # 3: CONSTRUCT proof and update leaf + ancestor hashes in memory.
            response = compute_update_proof(state, key, index, old_text, new_text)
            t3 = time.perf_counter_ns()

            # 4: VERIFY old-root/new-root transition independently.
            verified = verify_update(response, old_root)
            t4 = time.perf_counter_ns()
            if not verified:
                raise AssertionError(f"Update {operation} failed verification")

            # Untimed serialization + round-trip verification.
            wire = serialize_update(response, state["branching_factor"], state["depth"])
            decoded = deserialize_update(wire)
            if decoded != response or not verify_update(decoded, old_root):
                raise AssertionError(f"Update {operation}: serialized proof incorrect")

            texts[index] = new_text
            search_ms = (t1 - t0) / 1_000_000
            file_update_ms = (t2 - t_file) / 1_000_000
            proof_ms = (t3 - t2) / 1_000_000
            total_update_ms = search_ms + file_update_ms + proof_ms
            verification_ms = (t4 - t3) / 1_000_000
            results.append({
                "operation": operation,
                "key": key,
                "leaf_index": index,
                "old_text": old_text,
                "new_text": new_text,
                "search_ms": search_ms,
                "file_update_ms": file_update_ms,
                "proof_ms": proof_ms,
                "total_update_ms": total_update_ms,
                "verification_ms": verification_ms,
                "proof_bytes": len(wire),
                "old_root": old_root.hex(),
                "new_root": state["root"].hex(),
                "verified": verified,
            })

        # Outside per-operation timings, check every record/hash and actual JSONL.
        with working_jsonl.open("r", encoding="utf-8") as handle:
            final_lines = [json.loads(line) for line in handle]
        if final_lines != texts:
            raise RuntimeError("Working JSONL and in-memory text diverged")
        merkle.validate_tree_state(state, texts)
        if state["root"] == trusted_initial_root:
            raise RuntimeError("Root unexpectedly unchanged after updates")

        if not args.no_save:
            backup_dir = commit_final_files(texts, state, working_jsonl)
            print("Original dataset backed up in:", backup_dir)
            print("Final JSONL and pickle committed to original directory.")
            print("Commit occurs once at end, EXCLUDED from update timings.")
        else:
            print("--no-save: all JSONL writes used a temporary copy; original files unchanged.")

    with CSV_PATH.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(results)

    print("\nMERKLE TREE UPDATE BENCHMARK (8^6)")
    print("Leaves:", len(state["keys"]), "  Updates:", len(results),
          "  Distinct keys:", len(set(keys)))
    print("TOTAL UPDATE = SEARCH + FILE UPDATE + PROOF (verification excluded)")
    print("All times in ms; mean +/- sample standard deviation")
    for label, field in [
        ("Search", "search_ms"),
        ("JSONL file update (open/read/rewrite/fsync)", "file_update_ms"),
        ("Proof computation + hash updates", "proof_ms"),
        ("TOTAL UPDATE", "total_update_ms"),
        ("Proof verification", "verification_ms"),
    ]:
        average, deviation = stats([row[field] for row in results])
        print(f"{label:<44} {average:.6f} +/- {deviation:.6f}")
    sizes = [row["proof_bytes"] for row in results]
    average, deviation = stats(sizes)
    print(f"Serialized proof size (bytes): {average:.3f} +/- {deviation:.3f};"
          f" min={min(sizes)} max={max(sizes)}")
    print("Initial root:", trusted_initial_root.hex())
    print("Final root:  ", state["root"].hex())
    print("CSV with every update:", CSV_PATH.name)
    print(f"All {len(results)} sequential update proofs verified successfully")
    print("Note: pickle persistence and wire encoding/decoding are excluded from timings.")


if __name__ == "__main__":
    main()
