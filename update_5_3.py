
"""
Update one randomly selected existing key in the 5^3 Merkle tree.

Inputs:
    merkle_tree_5_3.pkl
    leaf_values_5_3.jsonl

Outputs:
    Updated merkle_tree_5_3.pkl
    Updated leaf_values_5_3.jsonl
    update_proof_5_3.json

Requires:
    merkle_5_3.py
    read_5_3.py

Run:
    python3 update_5_3.py
"""

import argparse
import json
import os
import pickle
import secrets
import shutil
from pathlib import Path

import merkle_5_3 as merkle
from read_5_3 import generate_path_from_saved_tree


# ============================================================
# FILE PATHS
# ============================================================

BASE = Path(__file__).resolve().parent

JSON_PATH = BASE / "leaf_values_5_3.jsonl"
PICKLE_PATH = BASE / "merkle_tree_5_3.pkl"
PROOF_PATH = BASE / "update_proof_5_3.json"

BACKUP_JSON = BASE / ".leaf_values_5_3.jsonl.update_bak"
BACKUP_PICKLE = BASE / ".merkle_tree_5_3.pkl.update_bak"
PENDING = BASE / ".merkle_5_3_update.pending"


# ============================================================
# RECOVER INTERRUPTED UPDATE
# ============================================================

def recover_if_interrupted():

    if not PENDING.exists():
        return

    if not BACKUP_JSON.exists() or not BACKUP_PICKLE.exists():
        raise RuntimeError(
            "Incomplete update. Recovery backups are missing."
        )

    os.replace(BACKUP_JSON, JSON_PATH)
    os.replace(BACKUP_PICKLE, PICKLE_PATH)

    PENDING.unlink()

    print("Recovered from interrupted update.")


# ============================================================
# LOAD AND VALIDATE SAVED TREE
# ============================================================

def load_checked_state():

    state = merkle.load_tree_pickle()
    texts = merkle.load_leaf_values_file()

    merkle.validate_tree_state(state, texts)

    return state, texts


# ============================================================
# UPDATE ONE EXISTING KEY
# ============================================================

def change_one_leaf(state, texts, key, new_text):

    if key not in state["key_to_index"]:
        raise ValueError("Key does not exist")

    if not isinstance(new_text, str) or not new_text:
        raise ValueError("New text must be nonempty")

    if len(new_text.encode("utf-8")) >= 2**32:
        raise ValueError("Text exceeds supported length")

    index = state["key_to_index"][key]

    old_text = texts[index]

    if new_text == old_text:
        raise ValueError("Text has not changed")

    old_value = state["key_value_db"][key]
    old_root = state["root"]

    # Generate old membership proof
    old_path = generate_path_from_saved_tree(
        state, key
    )

    # Check the current record
    if old_value != merkle.derive_value(key, old_text):
        raise RuntimeError("Stored value mismatch")

    old_verified = merkle.verify_membership_proof(
        key,
        old_value,
        old_path,
        old_root
    )

    if not old_verified:
        raise RuntimeError(
            "Old membership verification failed"
        )

    # ========================================================
    # CREATE UPDATED RECORD
    # ========================================================

    updated_texts = list(texts)
    updated_texts[index] = new_text

    new_value = merkle.derive_value(
        key,
        new_text
    )

    # Copy current state
    updated = dict(state)

    updated["key_value_db"] = dict(
        state["key_value_db"]
    )

    updated["key_value_db"][key] = new_value

    updated["levels"] = [
        list(level)
        for level in state["levels"]
    ]

    # ========================================================
    # UPDATE LEAF HASH
    # ========================================================

    pos = index

    updated["levels"][0][pos] = merkle.hash_leaf(
        key,
        new_value
    )

    # ========================================================
    # RECOMPUTE ANCESTOR HASHES
    # ========================================================

    b = state["branching_factor"]

    for level in range(state["depth"]):

        parent_start = (pos // b) * b

        children = updated["levels"][level][
            parent_start:parent_start + b
        ]

        pos //= b

        updated["levels"][level + 1][pos] = (
            merkle.hash_internal(children)
        )

    updated["root"] = updated["levels"][-1][0]

    new_root = updated["root"]

    # ========================================================
    # GENERATE NEW MEMBERSHIP PROOF
    # ========================================================

    new_path = generate_path_from_saved_tree(
        updated,
        key
    )

    # Changing one leaf does not change its siblings
    if new_path != old_path:
        raise RuntimeError(
            "Unexpected change in sibling hashes"
        )

    # Verify updated record
    new_verified = merkle.verify_membership_proof(
        key,
        new_value,
        new_path,
        new_root
    )

    if not new_verified:
        raise RuntimeError(
            "Updated membership verification failed"
        )

    # Ensure old value is no longer accepted by new root
    if merkle.verify_membership_proof(
        key,
        old_value,
        old_path,
        new_root
    ):
        raise RuntimeError(
            "Old value unexpectedly verified under new root"
        )

    if new_root == old_root:
        raise RuntimeError("Merkle root did not change")

    # Validate entire tree
    merkle.validate_tree_state(
        updated,
        updated_texts
    )

    # ========================================================
    # GENERATE UPDATE PROOF BUNDLE
    # ========================================================

    bundle = {
        "version": 1,
        "branching_factor": b,
        "depth": state["depth"],
        "key": str(key),
        "leaf_index": index,
        "old_text": old_text,
        "new_text": new_text,
        "old_root": old_root.hex(),
        "new_root": new_root.hex(),
        "proof": [
            {
                "child_position": position,
                "siblings": [
                    {
                        "position": sibling_position,
                        "hash": sibling_hash.hex()
                    }
                    for sibling_position, sibling_hash
                    in siblings
                ]
            }
            for position, siblings in new_path
        ]
    }

    return updated, updated_texts, bundle


# ============================================================
# VERIFY UPDATE PROOF
# ============================================================

def verify_update_bundle(bundle, trusted_old_root):

    try:
        key = int(bundle["key"])

        old_root = bytes.fromhex(
            bundle["old_root"]
        )

        new_root = bytes.fromhex(
            bundle["new_root"]
        )

        if old_root != trusted_old_root:
            return False

        if len(new_root) != 32:
            return False

        if bundle["old_text"] == bundle["new_text"]:
            return False

        path = []

        for level in bundle["proof"]:

            child_position = level["child_position"]

            siblings = [
                (
                    item["position"],
                    bytes.fromhex(item["hash"])
                )
                for item in level["siblings"]
            ]

            path.append(
                (child_position, siblings)
            )

        if len(path) != merkle.TREE_DEPTH:
            return False

        old_value = merkle.derive_value(
            key,
            bundle["old_text"]
        )

        new_value = merkle.derive_value(
            key,
            bundle["new_text"]
        )

        # Verify old value against trusted old root
        old_verified = merkle.verify_membership_proof(
            key,
            old_value,
            path,
            trusted_old_root
        )

        # Verify new value against claimed new root
        new_verified = merkle.verify_membership_proof(
            key,
            new_value,
            path,
            new_root
        )

        # Verify authenticated leaf position
        authenticated_index = (
            merkle.get_authenticated_leaf_index(path)
        )

        return (
            old_verified
            and new_verified
            and old_root != new_root
            and authenticated_index == bundle["leaf_index"]
        )

    except (
        KeyError,
        ValueError,
        TypeError,
        IndexError,
        OverflowError
    ):
        return False


# ============================================================
# SAVE JSONL AND PICKLE
# ============================================================

def persist_files(texts, state):

    new_json = BASE / ".leaf_values_5_3.jsonl.new"
    new_pickle = BASE / ".merkle_tree_5_3.pkl.new"

    try:
        # Write new JSONL
        with new_json.open(
            "w",
            encoding="utf-8",
            newline="\n"
        ) as f:

            for text in texts:
                f.write(
                    json.dumps(
                        text,
                        ensure_ascii=False
                    ) + "\n"
                )

            f.flush()
            os.fsync(f.fileno())

        # Write new pickle
        with new_pickle.open("wb") as f:

            pickle.dump(
                state,
                f,
                protocol=pickle.HIGHEST_PROTOCOL
            )

            f.flush()
            os.fsync(f.fileno())

        # Validate staged files
        with new_pickle.open("rb") as f:
            staged_state = pickle.load(f)

        with new_json.open(
            "r",
            encoding="utf-8"
        ) as f:
            staged_texts = [
                json.loads(line)
                for line in f
            ]

        merkle.validate_tree_state(
            staged_state,
            staged_texts
        )

        # Backup current files
        shutil.copy2(JSON_PATH, BACKUP_JSON)
        shutil.copy2(PICKLE_PATH, BACKUP_PICKLE)

        PENDING.write_text(
            "Update in progress\n"
        )

        # Replace canonical files
        os.replace(new_json, JSON_PATH)
        os.replace(new_pickle, PICKLE_PATH)

        saved_state, saved_texts = (
            load_checked_state()
        )

        if (
            saved_state["root"] != state["root"]
            or saved_texts != texts
        ):
            raise RuntimeError(
                "Persisted state verification failed"
            )

        # Successful commit
        PENDING.unlink()

        BACKUP_JSON.unlink(missing_ok=True)
        BACKUP_PICKLE.unlink(missing_ok=True)

    except Exception:

        if PENDING.exists():
            recover_if_interrupted()

        raise

    finally:

        new_json.unlink(missing_ok=True)
        new_pickle.unlink(missing_ok=True)


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--list-keys",
        action="store_true"
    )

    parser.add_argument(
        "--key",
        type=int
    )

    parser.add_argument(
        "--text"
    )

    args = parser.parse_args()

    recover_if_interrupted()

    state, texts = load_checked_state()

    if args.list_keys:

        for index, key in enumerate(state["keys"]):

            print(
                f"Leaf {index} | "
                f"JSONL line {index + 1} | "
                f"Key {key}"
            )

        return

    # Randomly select EXISTING key
    key = (
        args.key
        if args.key is not None
        else secrets.choice(state["keys"])
    )

    if key not in state["key_to_index"]:
        parser.error("Key does not exist")

    index = state["key_to_index"][key]

    old_text = texts[index]

    # Generate new text
    new_text = (
        args.text
        if args.text is not None
        else (
            f"{old_text} | "
            f"updated {secrets.token_hex(8)}"
        )
    )

    print("\nRANDOM EXISTING-KEY UPDATE")

    print("Selected key:", key)
    print("Leaf index:", index)
    print("JSONL line:", index + 1)
    print("Old text:", old_text)
    print("New text:", new_text)

    old_root = state["root"]

    # Update record and tree
    updated, new_texts, bundle = (
        change_one_leaf(
            state,
            texts,
            key,
            new_text
        )
    )

    # Independently verify update
    verified = verify_update_bundle(
        bundle,
        old_root
    )

    if not verified:
        raise RuntimeError(
            "Update proof verification failed"
        )

    # Persist updated tree
    persist_files(
        new_texts,
        updated
    )

    # Save proof bundle
    temp_proof = PROOF_PATH.with_suffix(
        ".json.tmp"
    )

    with temp_proof.open(
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            bundle,
            f,
            indent=2
        )

        f.write("\n")

    os.replace(temp_proof, PROOF_PATH)

    print("\nUPDATE SUCCESSFUL")
    print("Proof verified:", verified)
    print("Old root:", bundle["old_root"])
    print("New root:", bundle["new_root"])
    print("Updated leaf index:", index)
    print("Updated JSONL line:", index + 1)

    print("Updated JSONL and pickle saved")


if __name__ == "__main__":
    main()
