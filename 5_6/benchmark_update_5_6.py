
"""Benchmark updates of existing keys in a saved 5^6 Merkle tree.

Measures:
    search_ms
    file_update_ms
    proof_ms
    total_update_ms
    verification_ms
    proof_bytes

Each key is sampled with replacement.

Every update:
    1. Searches for an existing key.
    2. Opens and updates its JSONL line.
    3. Computes the updated Merkle leaf and ancestor hashes.
    4. Generates the update proof.
    5. Verifies the old-root to new-root transition.

The JSONL updates happen on a temporary working copy.
Unless --no-save is provided, the final JSONL and pickle are
saved after all updates have successfully verified.

Requires:
    merkle_5_6.py
    read_5_6.py
    leaf_values_5_6.jsonl
    merkle_tree_5_6.pkl
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

import merkle_5_6 as merkle
import read_5_6 as reader


# ============================================================
# CONFIGURATION
# ============================================================

BASE = Path(__file__).resolve().parent

JSON_PATH = BASE / "leaf_values_5_6.jsonl"
PICKLE_PATH = BASE / "merkle_tree_5_6.pkl"
CSV_PATH = BASE / "update_benchmark_5_6.csv"

PENDING = BASE / ".merkle_5_6_update.pending"

BACKUP_JSON = BASE / ".leaf_values_5_6.jsonl.update_bak"
BACKUP_PICKLE = BASE / ".merkle_tree_5_6.pkl.update_bak"

CSV_COLUMNS = [
    "operation",
    "key",
    "leaf_index",
    "old_text",
    "new_text",
    "search_ms",
    "file_update_ms",
    "proof_ms",
    "total_update_ms",
    "verification_ms",
    "proof_bytes",
    "old_root",
    "new_root",
    "verified",
]


# ============================================================
# RECOVER INTERRUPTED COMMIT
# ============================================================

def recover_if_interrupted():

    if not PENDING.exists():
        return

    if not BACKUP_JSON.exists() or not BACKUP_PICKLE.exists():
        raise RuntimeError(
            "Pending update is missing recovery backups"
        )

    os.replace(BACKUP_JSON, JSON_PATH)
    os.replace(BACKUP_PICKLE, PICKLE_PATH)

    PENDING.unlink()

    print("Recovered files from interrupted commit.")


# ============================================================
# LOAD EXISTING TREE
# ============================================================

def load_checked_state():

    state = merkle.load_tree_pickle()

    texts = merkle.load_leaf_values_file()

    merkle.validate_tree_state(state, texts)

    return state, texts


# ============================================================
# SEARCH FOR AN EXISTING KEY
# ============================================================

def lookup_key(state, key):

    index = state["key_to_index"].get(key)

    if index is None:
        raise KeyError(
            f"Cannot update absent key: {key}"
        )

    return index


# ============================================================
# OPEN JSONL FILE AND UPDATE CORRESPONDING LINE
# ============================================================

def edit_jsonl_line(
    path,
    index,
    expected_old_text,
    new_text
):

    # Open and read JSONL file
    with path.open("r", encoding="utf-8") as file:
        lines = file.readlines()

    if len(lines) != merkle.NUMBER_OF_RECORDS:
        raise ValueError(
            "Unexpected number of JSONL lines"
        )

    if not 0 <= index < len(lines):
        raise IndexError(
            "Leaf index outside JSONL range"
        )

    old_text = json.loads(lines[index])

    if old_text != expected_old_text:
        raise RuntimeError(
            "JSONL content does not match tree state"
        )

    if old_text == new_text:
        raise ValueError(
            "An update must change the text"
        )

    # Replace the corresponding line
    lines[index] = (
        json.dumps(new_text, ensure_ascii=False)
        + "\n"
    )

    temp_path = path.with_name(
        path.name + ".tmp"
    )

    try:

        # Rewrite updated JSONL file
        with temp_path.open(
            "w",
            encoding="utf-8",
            newline="\n"
        ) as file:

            file.writelines(lines)

            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_path, path)

    finally:
        temp_path.unlink(missing_ok=True)

    return old_text


# ============================================================
# GENERATE AUTHENTICATION PATH FROM SAVED TREE
# ============================================================

def path_for_index(state, index):

    proof = []

    b = state["branching_factor"]

    for level in range(state["depth"]):

        nodes = state["levels"][level]

        child_position = index % b

        sibling_start = (
            index // b
        ) * b

        siblings = [
            (
                position,
                nodes[sibling_start + position]
            )
            for position in range(b)
            if position != child_position
        ]

        proof.append(
            (child_position, siblings)
        )

        index //= b

    return proof


# ============================================================
# PROVER: COMPUTE UPDATE PROOF
# ============================================================

def compute_update_proof(
    state,
    key,
    index,
    old_text,
    new_text
):

    old_value = state["key_value_db"][key]

    # Validate old record
    if old_value != merkle.derive_value(
        key, old_text
    ):
        raise RuntimeError(
            "Old value does not match JSONL text"
        )

    # Membership path from the OLD tree
    path = path_for_index(
        state, index
    )

    # Derive updated value
    new_value = merkle.derive_value(
        key, new_text
    )

    # Update key-value database
    state["key_value_db"][key] = new_value

    # Update leaf hash
    position = index

    state["levels"][0][position] = (
        merkle.hash_leaf(
            key, new_value
        )
    )

    # Recompute affected ancestors
    b = state["branching_factor"]

    for level in range(state["depth"]):

        child_start = (
            position // b
        ) * b

        position //= b

        children = state["levels"][level][
            child_start:child_start + b
        ]

        state["levels"][level + 1][position] = (
            merkle.hash_internal(children)
        )

    # Updated Merkle root
    state["root"] = state["levels"][-1][0]

    return {
        "key": key,
        "index": index,
        "old_text": old_text,
        "new_text": new_text,
        "new_root": state["root"],
        "proof": path
    }


# ============================================================
# VERIFIER: VERIFY OLD-TO-NEW ROOT TRANSITION
# ============================================================

def verify_update(
    response,
    trusted_old_root
):

    try:

        key = response["key"]

        old_text = response["old_text"]
        new_text = response["new_text"]

        new_root = response["new_root"]
        path = response["proof"]

        if old_text == new_text:
            return False

        if (
            not isinstance(new_root, bytes)
            or len(new_root) != 32
        ):
            return False

        # Verify authenticated leaf index
        index = reader.authenticated_index(
            path
        )

        if index != response["index"]:
            return False

        # Derive old and new values
        old_value = merkle.derive_value(
            key, old_text
        )

        new_value = merkle.derive_value(
            key, new_text
        )

        if old_value == new_value:
            return False

        # Verify original value against trusted old root
        old_verified = (
            reader.verify_membership_proof(
                key,
                old_value,
                path,
                trusted_old_root
            )
        )

        # Verify updated value against new root
        new_verified = (
            reader.verify_membership_proof(
                key,
                new_value,
                path,
                new_root
            )
        )

        return (
            old_verified
            and new_verified
            and new_root != trusted_old_root
        )

    except (
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        OverflowError
    ):
        return False


# ============================================================
# SERIALIZE UPDATE PROOF
# ============================================================

def serialize_update(
    response,
    b,
    d
):

    old = response["old_text"].encode(
        "utf-8"
    )

    new = response["new_text"].encode(
        "utf-8"
    )

    if len(old) >= 2**32 or len(new) >= 2**32:
        raise ValueError("Text too long")

    header = bytes(
        (1, ord("U"), b, d)
    )

    return (
        header
        + reader.encode_key(response["key"])
        + response["index"].to_bytes(4, "big")
        + response["new_root"]
        + len(old).to_bytes(4, "big")
        + old
        + len(new).to_bytes(4, "big")
        + new
        + reader.encode_path(
            response["proof"],
            b,
            d
        )
    )


# ============================================================
# DESERIALIZE UPDATE PROOF
# ============================================================

def deserialize_update(data):

    wire = reader.WireReader(data)

    version, kind, b, d = wire.take(4)

    if (
        version, kind, b, d
    ) != (
        1,
        ord("U"),
        merkle.BRANCHING_FACTOR,
        merkle.TREE_DEPTH
    ):
        raise ValueError(
            "Incorrect update proof format"
        )

    key = int.from_bytes(
        wire.take(merkle.KEY_LENGTH_BYTES),
        "big"
    )

    index = int.from_bytes(
        wire.take(4),
        "big"
    )

    new_root = wire.take(32)

    old_len = int.from_bytes(
        wire.take(4),
        "big"
    )

    old_text = wire.take(
        old_len
    ).decode("utf-8")

    new_len = int.from_bytes(
        wire.take(4),
        "big"
    )

    new_text = wire.take(
        new_len
    ).decode("utf-8")

    proof = reader.decode_path(
        wire, b, d
    )

    wire.finish()

    return {
        "key": key,
        "index": index,
        "old_text": old_text,
        "new_text": new_text,
        "new_root": new_root,
        "proof": proof
    }


# ============================================================
# BACKUP AND SAVE FINAL JSONL AND PICKLE
# ============================================================

def commit_final_files(
    texts,
    state,
    working_jsonl
):

    merkle.validate_tree_state(
        state, texts
    )

    stamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    backup_dir = (
        BASE
        / "update_benchmark_backups"
        / stamp
    )

    backup_dir.mkdir(
        parents=True,
        exist_ok=False
    )

    shutil.copy2(
        JSON_PATH,
        backup_dir / JSON_PATH.name
    )

    shutil.copy2(
        PICKLE_PATH,
        backup_dir / PICKLE_PATH.name
    )

    staged_json = (
        BASE / ".leaf_values_5_6.jsonl.new"
    )

    staged_pickle = (
        BASE / ".merkle_tree_5_6.pkl.new"
    )

    try:

        shutil.copy2(
            working_jsonl,
            staged_json
        )

        with staged_pickle.open("wb") as handle:

            pickle.dump(
                state,
                handle,
                protocol=pickle.HIGHEST_PROTOCOL
            )

            handle.flush()
            os.fsync(handle.fileno())

        # Validate staged pickle
        with staged_pickle.open("rb") as handle:
            check_state = pickle.load(handle)

        # Validate staged JSONL
        with staged_json.open(
            "r",
            encoding="utf-8"
        ) as handle:

            check_texts = [
                json.loads(line)
                for line in handle
            ]

        merkle.validate_tree_state(
            check_state,
            check_texts
        )

        if (
            check_texts != texts
            or check_state["root"] != state["root"]
        ):
            raise RuntimeError(
                "Staged file validation failed"
            )

        # Create recovery backups
        shutil.copy2(
            JSON_PATH,
            BACKUP_JSON
        )

        shutil.copy2(
            PICKLE_PATH,
            BACKUP_PICKLE
        )

        PENDING.write_text(
            "Update commit in progress\n"
        )

        # Replace canonical files
        os.replace(
            staged_json,
            JSON_PATH
        )

        os.replace(
            staged_pickle,
            PICKLE_PATH
        )

        saved_state, saved_texts = (
            load_checked_state()
        )

        if (
            saved_texts != texts
            or saved_state["root"] != state["root"]
        ):
            raise RuntimeError(
                "Persisted state mismatch"
            )

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


# ============================================================
# STATISTICS
# ============================================================

def stats(values):

    mean = statistics.mean(values)

    sd = (
        statistics.stdev(values)
        if len(values) > 1
        else 0.0
    )

    return mean, sd


# ============================================================
# MAIN BENCHMARK
# ============================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--runs",
        type=int,
        default=1000
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=2026
    )

    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Do not modify original JSONL or pickle"
    )

    args = parser.parse_args()

    if args.runs < 2:
        parser.error(
            "At least two runs are required"
        )

    recover_if_interrupted()

    # ========================================================
    # LOAD EXISTING TREE
    # ========================================================

    state, texts = load_checked_state()

    texts = list(texts)

    initial_root = state["root"]

    # ========================================================
    # RANDOMLY SAMPLE EXISTING KEYS
    # ========================================================

    rng = random.Random(args.seed)

    selected_keys = [
        rng.choice(state["keys"])
        for _ in range(args.runs)
    ]

    tag = secrets.token_hex(4)

    # ========================================================
    # UNTIMED WARM-UP
    # ========================================================

    warm_state = dict(state)

    warm_state["key_value_db"] = dict(
        state["key_value_db"]
    )

    warm_state["levels"] = [
        list(level)
        for level in state["levels"]
    ]

    warm_key = selected_keys[0]

    warm_index = lookup_key(
        warm_state,
        warm_key
    )

    warm_text = (
        f"this is leaf {warm_index + 1}"
        f" | warmup {tag}"
    )

    warm_proof = compute_update_proof(
        warm_state,
        warm_key,
        warm_index,
        texts[warm_index],
        warm_text
    )

    if not verify_update(
        warm_proof,
        state["root"]
    ):
        raise AssertionError(
            "Warm-up update verification failed"
        )

    # ========================================================
    # PREPARE TEMPORARY WORKING JSONL
    # ========================================================

    results = []

    with tempfile.TemporaryDirectory(
        prefix=".merkle_update_5_6_",
        dir=BASE
    ) as working_dir:

        working_jsonl = (
            Path(working_dir) / JSON_PATH.name
        )

        shutil.copy2(
            JSON_PATH,
            working_jsonl
        )

        # ====================================================
        # PERFORM ALL UPDATE OPERATIONS
        # ====================================================

        for operation, key in enumerate(
            selected_keys, 1
        ):

            old_root = state["root"]

            # ------------------------------------------------
            # 1. TIME SEARCH
            # ------------------------------------------------

            t0 = time.perf_counter_ns()

            index = lookup_key(
                state,
                key
            )

            old_text = texts[index]

            t1 = time.perf_counter_ns()

            # Generate unique replacement text
            new_text = (
                f"this is leaf {index + 1}"
                f" | update {tag}-{operation:06d}"
            )

            # ------------------------------------------------
            # 2. TIME JSONL FILE UPDATE
            # ------------------------------------------------

            t_file = time.perf_counter_ns()

            old_from_file = edit_jsonl_line(
                working_jsonl,
                index,
                old_text,
                new_text
            )

            t2 = time.perf_counter_ns()

            if old_from_file != old_text:
                raise AssertionError(
                    "JSONL content mismatch"
                )

            # ------------------------------------------------
            # 3. TIME PROOF COMPUTATION
            # ------------------------------------------------

            response = compute_update_proof(
                state,
                key,
                index,
                old_text,
                new_text
            )

            t3 = time.perf_counter_ns()

            # ------------------------------------------------
            # 4. TIME PROOF VERIFICATION
            # ------------------------------------------------

            verified = verify_update(
                response,
                old_root
            )

            t4 = time.perf_counter_ns()

            if not verified:
                raise AssertionError(
                    f"Update {operation} failed"
                )

            # ------------------------------------------------
            # 5. SERIALIZED PROOF SIZE
            # Outside timings
            # ------------------------------------------------

            wire = serialize_update(
                response,
                state["branching_factor"],
                state["depth"]
            )

            decoded = deserialize_update(wire)

            if (
                decoded != response
                or not verify_update(decoded, old_root)
            ):
                raise AssertionError(
                    "Serialized update proof failed"
                )

            # ------------------------------------------------
            # UPDATE IN-MEMORY TEXT
            # ------------------------------------------------

            texts[index] = new_text

            # ------------------------------------------------
            # CALCULATE TIMINGS
            # ------------------------------------------------

            search_ms = (
                t1 - t0
            ) / 1_000_000

            file_update_ms = (
                t2 - t_file
            ) / 1_000_000

            proof_ms = (
                t3 - t2
            ) / 1_000_000

            total_update_ms = (
                search_ms
                + file_update_ms
                + proof_ms
            )

            verification_ms = (
                t4 - t3
            ) / 1_000_000

            # ------------------------------------------------
            # STORE EACH EXPERIMENT RESULT
            # ------------------------------------------------

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
                "verified": verified
            })

        # ====================================================
        # VALIDATE COMPLETE UPDATED TREE
        # ====================================================

        with working_jsonl.open(
            "r",
            encoding="utf-8"
        ) as handle:

            final_lines = [
                json.loads(line)
                for line in handle
            ]

        if final_lines != texts:
            raise RuntimeError(
                "Working JSONL and memory differ"
            )

        merkle.validate_tree_state(
            state,
            texts
        )

        if state["root"] == initial_root:
            raise RuntimeError(
                "Final root did not change"
            )

        # ====================================================
        # SAVE FINAL STATE IF REQUESTED
        # ====================================================

        if not args.no_save:

            backup_dir = commit_final_files(
                texts,
                state,
                working_jsonl
            )

            print(
                "Original dataset backed up in:",
                backup_dir
            )

            print(
                "Final JSONL and pickle saved"
            )

        else:

            print(
                "--no-save: original JSONL and pickle unchanged"
            )

    # ========================================================
    # WRITE ALL 1000 RESULTS TO CSV
    # ========================================================

    with CSV_PATH.open(
        "w",
        encoding="utf-8",
        newline=""
    ) as handle:

        writer = csv.DictWriter(
            handle,
            fieldnames=CSV_COLUMNS
        )

        writer.writeheader()
        writer.writerows(results)

    # ========================================================
    # PRINT BENCHMARK STATISTICS
    # ========================================================

    print("\nMERKLE TREE UPDATE BENCHMARK (5^6)")

    print("Branching factor:", merkle.BRANCHING_FACTOR)
    print("Tree depth:", merkle.TREE_DEPTH)
    print("Number of leaves:", len(state["keys"]))
    print("Update operations:", len(results))
    print("Distinct keys:", len(set(selected_keys)))

    print(
        "\nTOTAL UPDATE = "
        "SEARCH + FILE UPDATE + PROOF"
    )

    print(
        "\nTIMINGS (milliseconds, mean +/- sample SD)"
    )

    measurements = [
        ("Search", "search_ms"),
        ("JSONL file update", "file_update_ms"),
        ("Proof computation", "proof_ms"),
        ("TOTAL UPDATE", "total_update_ms"),
        ("Proof verification", "verification_ms")
    ]

    for label, field in measurements:

        values = [
            row[field]
            for row in results
        ]

        mean, sd = stats(values)

        print(
            f"{label:<25} "
            f"{mean:.6f} +/- {sd:.6f}"
        )

    sizes = [
        row["proof_bytes"]
        for row in results
    ]

    size_mean, size_sd = stats(sizes)

    print("\nSERIALIZED PROOF SIZE (bytes)")

    print(
        f"Mean +/- SD: "
        f"{size_mean:.3f} +/- {size_sd:.3f}"
    )

    print(
        f"Minimum / Maximum: "
        f"{min(sizes)} / {max(sizes)}"
    )

    print("\nInitial root:", initial_root.hex())
    print("Final root:  ", state["root"].hex())

    print(
        "\nRaw per-update CSV:",
        CSV_PATH.name
    )

    print(
        f"\nAll {len(results)} sequential "
        "update proofs verified successfully"
    )

    print(
        "Note: pickle persistence, CSV writing and "
        "proof serialization are excluded from timings."
    )


if __name__ == "__main__":
    main()
