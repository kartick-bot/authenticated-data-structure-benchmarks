
import argparse
import hashlib
import json
import os
import pickle
import secrets
from bisect import bisect_left
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

BRANCHING_FACTOR = 5
TREE_DEPTH = 3
NUMBER_OF_RECORDS = BRANCHING_FACTOR ** TREE_DEPTH

KEY_UNIVERSE = 2**100
VALUE_LENGTH_BYTES = 32
HASH_LENGTH_BYTES = 32
KEY_LENGTH_BYTES = 13

BASE_DIR = Path(__file__).resolve().parent

LEAF_VALUES_FILE = BASE_DIR / "leaf_values_5_3.jsonl"
TREE_PICKLE_FILE = BASE_DIR / "merkle_tree_5_3.pkl"


# ============================================================
# STEP 1: GENERATE SORTED KEYS
# ============================================================

def generate_keys(n):

    keys = set()

    while len(keys) < n:
        key = secrets.randbelow(KEY_UNIVERSE) + 1
        keys.add(key)

    return sorted(keys)


# ============================================================
# STEP 2: GENERATE JSONL FILE
# ============================================================

def create_leaf_values_file(overwrite=False):

    if LEAF_VALUES_FILE.exists() and not overwrite:
        return

    with LEAF_VALUES_FILE.open(
        "w", encoding="utf-8"
    ) as file:

        for i in range(1, NUMBER_OF_RECORDS + 1):

            text = f"this is leaf {i}"

            file.write(json.dumps(text) + "\n")

    print("Created JSONL file:", LEAF_VALUES_FILE.name)


def load_leaf_values_file():

    with LEAF_VALUES_FILE.open(
        "r", encoding="utf-8"
    ) as file:

        lines = file.readlines()

    if len(lines) != NUMBER_OF_RECORDS:
        raise ValueError("Incorrect JSONL line count")

    texts = [json.loads(line) for line in lines]

    if any(not isinstance(text, str) for text in texts):
        raise ValueError("Every line must contain a JSON string")

    return texts


# ============================================================
# STEP 3: DERIVE VALUES FROM KEYS AND TEXT
# ============================================================

def derive_value(key, text):

    key_bytes = key.to_bytes(KEY_LENGTH_BYTES, "big")
    text_bytes = text.encode("utf-8")

    data = (
        b"\x02"
        + key_bytes
        + len(text_bytes).to_bytes(4, "big")
        + text_bytes
    )

    return hashlib.sha256(data).digest()


def make_key_value_db(keys, texts):

    if len(keys) != len(texts):
        raise ValueError("Keys and text count differ")

    key_value_db = {}

    for i, key in enumerate(keys):

        key_value_db[key] = derive_value(
            key, texts[i]
        )

    return key_value_db


# ============================================================
# STEP 4: HASH FUNCTIONS
# ============================================================

def hash_leaf(key, value):

    key_bytes = key.to_bytes(KEY_LENGTH_BYTES, "big")
    value_length = len(value).to_bytes(4, "big")

    data = (
        b"\x00"
        + key_bytes
        + value_length
        + value
    )

    return hashlib.sha256(data).digest()


def hash_internal(children):

    if len(children) != BRANCHING_FACTOR:
        raise ValueError("Incorrect number of children")

    return hashlib.sha256(
        b"\x01" + b"".join(children)
    ).digest()


# ============================================================
# STEP 5: CONSTRUCT COMPLETE MERKLE TREE
# ============================================================

def build_merkle_tree(key_value_db):

    keys = list(key_value_db.keys())

    if keys != sorted(keys):
        raise ValueError("Keys must be sorted")

    if len(keys) != NUMBER_OF_RECORDS:
        raise ValueError("Incorrect number of records")

    leaf_hashes = [
        hash_leaf(key, key_value_db[key])
        for key in keys
    ]

    levels = [leaf_hashes]

    print(f"Level 0: {len(leaf_hashes)} nodes")

    while len(levels[-1]) > 1:

        current_level = levels[-1]

        if len(current_level) % BRANCHING_FACTOR != 0:
            raise ValueError("Incomplete internal node")

        next_level = []

        for i in range(
            0,
            len(current_level),
            BRANCHING_FACTOR
        ):

            children = current_level[
                i:i + BRANCHING_FACTOR
            ]

            next_level.append(
                hash_internal(children)
            )

        levels.append(next_level)

        print(
            f"Level {len(levels)-1}: "
            f"{len(next_level)} nodes"
        )

    return levels


# ============================================================
# STEP 6: SAVE AND LOAD PICKLE
# ============================================================

def save_tree_pickle(state):

    temp_path = TREE_PICKLE_FILE.with_suffix(".pkl.tmp")

    with temp_path.open("wb") as file:

        pickle.dump(
            state,
            file,
            protocol=pickle.HIGHEST_PROTOCOL
        )

    os.replace(temp_path, TREE_PICKLE_FILE)

    print("Saved tree:", TREE_PICKLE_FILE.name)


def load_tree_pickle():

    with TREE_PICKLE_FILE.open("rb") as file:
        return pickle.load(file)


# ============================================================
# STEP 7: VALIDATE PERSISTED TREE
# ============================================================

def validate_tree_state(state, texts):

    keys = state["keys"]
    records = state["key_value_db"]
    levels = state["levels"]

    assert state["branching_factor"] == BRANCHING_FACTOR
    assert state["depth"] == TREE_DEPTH
    assert state["leaf_count"] == NUMBER_OF_RECORDS

    assert len(keys) == NUMBER_OF_RECORDS
    assert keys == sorted(keys)
    assert len(set(keys)) == NUMBER_OF_RECORDS

    assert list(records.keys()) == keys

    # Validate key-index mapping
    assert state["key_to_index"] == {
        key: i for i, key in enumerate(keys)
    }

    # Validate values against JSONL
    for i, key in enumerate(keys):

        expected_value = derive_value(
            key, texts[i]
        )

        assert records[key] == expected_value

    # Validate leaf hashes
    expected_leaves = [
        hash_leaf(key, records[key])
        for key in keys
    ]

    assert levels[0] == expected_leaves

    # Validate all internal nodes
    for level in range(TREE_DEPTH):

        current = levels[level]

        expected_parents = []

        for i in range(
            0, len(current), BRANCHING_FACTOR
        ):

            children = current[
                i:i + BRANCHING_FACTOR
            ]

            expected_parents.append(
                hash_internal(children)
            )

        assert levels[level + 1] == expected_parents

    assert state["root"] == levels[-1][0]

    return True


# ============================================================
# STEP 8: INITIALIZE OR LOAD TREE
# ============================================================

def construct_or_load_tree(rebuild=False):

    if TREE_PICKLE_FILE.exists() and not rebuild:

        if not LEAF_VALUES_FILE.exists():
            raise FileNotFoundError(
                "JSONL file missing for saved tree"
            )

        state = load_tree_pickle()

        texts = load_leaf_values_file()

        validate_tree_state(state, texts)

        print("Loaded existing tree from pickle")

        for level, nodes in enumerate(state["levels"]):
            print(f"Level {level}: {len(nodes)} nodes")

        return state

    # Generate or regenerate JSONL
    create_leaf_values_file(overwrite=rebuild)

    texts = load_leaf_values_file()

    # Generate sorted keys
    keys = generate_keys(NUMBER_OF_RECORDS)

    # Create database
    key_value_db = make_key_value_db(keys, texts)

    # Construct complete Merkle tree
    levels = build_merkle_tree(key_value_db)

    root = levels[-1][0]

    # Store complete tree state
    state = {
        "format_version": 1,
        "branching_factor": BRANCHING_FACTOR,
        "depth": TREE_DEPTH,
        "leaf_count": NUMBER_OF_RECORDS,
        "key_universe": KEY_UNIVERSE,
        "leaf_text_file": LEAF_VALUES_FILE.name,
        "keys": keys,
        "key_to_index": {
            key: i for i, key in enumerate(keys)
        },
        "key_value_db": key_value_db,
        "levels": levels,
        "root": root,
        "value_scheme": "sha256_key_text"
    }

    validate_tree_state(state, texts)

    save_tree_pickle(state)

    # Test deserialization
    loaded_state = load_tree_pickle()

    validate_tree_state(loaded_state, texts)

    return loaded_state


# ============================================================
# STEP 9: COMPUTE SUBTREE HASH ON DEMAND
# ============================================================

def compute_subtree_hash(
    keys,
    key_value_db,
    start,
    size
):

    if size == 1:

        key = keys[start]

        return hash_leaf(
            key,
            key_value_db[key]
        )

    child_size = size // BRANCHING_FACTOR

    children = []

    for i in range(BRANCHING_FACTOR):

        child_start = start + i * child_size

        children.append(
            compute_subtree_hash(
                keys,
                key_value_db,
                child_start,
                child_size
            )
        )

    return hash_internal(children)


# ============================================================
# STEP 10: GENERATE MEMBERSHIP PROOF
# ============================================================

def generate_membership_proof(key, key_value_db):

    if key not in key_value_db:
        raise KeyError("Key not found")

    keys = list(key_value_db.keys())

    leaf_index = keys.index(key)

    proof = []

    for level in range(TREE_DEPTH):

        subtree_size = BRANCHING_FACTOR ** level

        parent_size = (
            BRANCHING_FACTOR * subtree_size
        )

        child_position = (
            leaf_index // subtree_size
        ) % BRANCHING_FACTOR

        parent_start = (
            leaf_index // parent_size
        ) * parent_size

        siblings = []

        for position in range(BRANCHING_FACTOR):

            if position == child_position:
                continue

            sibling_start = (
                parent_start
                + position * subtree_size
            )

            sibling_hash = compute_subtree_hash(
                keys,
                key_value_db,
                sibling_start,
                subtree_size
            )

            siblings.append(
                (position, sibling_hash)
            )

        proof.append(
            (child_position, siblings)
        )

    return proof


# ============================================================
# STEP 11: VERIFY MEMBERSHIP PROOF
# ============================================================

def verify_membership_proof(
    key,
    value,
    proof,
    merkle_root
):

    if not 1 <= key <= KEY_UNIVERSE:
        return False

    if not isinstance(value, bytes):
        return False

    if len(value) != VALUE_LENGTH_BYTES:
        return False

    if len(proof) != TREE_DEPTH:
        return False

    current_hash = hash_leaf(key, value)

    for child_position, siblings in proof:

        if not 0 <= child_position < BRANCHING_FACTOR:
            return False

        if len(siblings) != BRANCHING_FACTOR - 1:
            return False

        children = [None] * BRANCHING_FACTOR

        children[child_position] = current_hash

        for position, sibling_hash in siblings:

            if not 0 <= position < BRANCHING_FACTOR:
                return False

            if children[position] is not None:
                return False

            if not isinstance(sibling_hash, bytes):
                return False

            if len(sibling_hash) != HASH_LENGTH_BYTES:
                return False

            children[position] = sibling_hash

        if any(x is None for x in children):
            return False

        current_hash = hash_internal(children)

    return current_hash == merkle_root


# ============================================================
# STEP 12: EXTRACT AUTHENTICATED LEAF INDEX
# ============================================================

def get_authenticated_leaf_index(proof):

    if len(proof) != TREE_DEPTH:
        raise ValueError("Invalid proof depth")

    leaf_index = 0

    for level, (position, siblings) in enumerate(proof):

        if not 0 <= position < BRANCHING_FACTOR:
            raise ValueError("Invalid child position")

        leaf_index += (
            position * BRANCHING_FACTOR ** level
        )

    return leaf_index


# ============================================================
# STEP 13: LOCATE PREDECESSOR AND SUCCESSOR
# ============================================================

def find_predecessor_successor(
    query_key,
    key_value_db
):

    if not 1 <= query_key <= KEY_UNIVERSE:
        raise ValueError("Invalid query key")

    keys = list(key_value_db.keys())

    position = bisect_left(keys, query_key)

    if (
        position < len(keys)
        and keys[position] == query_key
    ):

        return {
            "status": "MEMBER",
            "predecessor": None,
            "successor": None
        }

    pred_index = (
        position - 1 if position > 0 else None
    )

    succ_index = (
        position if position < len(keys) else None
    )

    return {
        "status": "NON_MEMBER",
        "predecessor": (
            keys[pred_index]
            if pred_index is not None else None
        ),
        "successor": (
            keys[succ_index]
            if succ_index is not None else None
        )
    }


# ============================================================
# STEP 14: GENERATE NON-MEMBERSHIP PROOF
# ============================================================

def generate_non_membership_proof(
    query_key,
    key_value_db
):

    info = find_predecessor_successor(
        query_key,
        key_value_db
    )

    if info["status"] == "MEMBER":
        raise ValueError("Queried key exists")

    pred_key = info["predecessor"]
    succ_key = info["successor"]

    return {
        "predecessor": (
            (pred_key, key_value_db[pred_key])
            if pred_key is not None else None
        ),

        "predecessor_proof": (
            generate_membership_proof(
                pred_key, key_value_db
            )
            if pred_key is not None else None
        ),

        "successor": (
            (succ_key, key_value_db[succ_key])
            if succ_key is not None else None
        ),

        "successor_proof": (
            generate_membership_proof(
                succ_key, key_value_db
            )
            if succ_key is not None else None
        )
    }


# ============================================================
# STEP 15: GENERIC NON-MEMBERSHIP VERIFIER
# ============================================================

def verify_non_membership_generic(
    query_key,
    predecessor,
    predecessor_proof,
    successor,
    successor_proof,
    merkle_root
):

    if not 1 <= query_key <= KEY_UNIVERSE:
        return False

    if predecessor is None and successor is None:
        return False

    if (
        (predecessor is None)
        != (predecessor_proof is None)
    ):
        return False

    if (
        (successor is None)
        != (successor_proof is None)
    ):
        return False

    pred_index = None
    succ_index = None

    # Verify predecessor
    if predecessor is not None:

        pred_key, pred_value = predecessor

        if pred_key >= query_key:
            return False

        if not verify_membership_proof(
            pred_key,
            pred_value,
            predecessor_proof,
            merkle_root
        ):
            return False

        pred_index = get_authenticated_leaf_index(
            predecessor_proof
        )

    # Verify successor
    if successor is not None:

        succ_key, succ_value = successor

        if succ_key <= query_key:
            return False

        if not verify_membership_proof(
            succ_key,
            succ_value,
            successor_proof,
            merkle_root
        ):
            return False

        succ_index = get_authenticated_leaf_index(
            successor_proof
        )

    # Case 1: Before first leaf
    if predecessor is None:
        return succ_index == 0

    # Case 4: After last leaf
    if successor is None:
        return pred_index == NUMBER_OF_RECORDS - 1

    # Cases 2 and 3: Consecutive leaves
    return succ_index == pred_index + 1


def verify_non_membership_from_package(
    query_key,
    package,
    merkle_root
):

    return verify_non_membership_generic(
        query_key,
        package["predecessor"],
        package["predecessor_proof"],
        package["successor"],
        package["successor_proof"],
        merkle_root
    )


# ============================================================
# STEP 16: PROOF SIZE
# ============================================================

def proof_hash_payload_size(proof):

    return sum(
        len(siblings)
        for _, siblings in proof
    ) * HASH_LENGTH_BYTES


def non_membership_hash_payload_size(package):

    total = 0

    for name in (
        "predecessor_proof",
        "successor_proof"
    ):

        proof = package[name]

        if proof is not None:
            total += proof_hash_payload_size(proof)

    return total


# ============================================================
# STEP 17: SELECT NON-MEMBERSHIP TEST QUERIES
# ============================================================

def find_gap_query(keys, predicate):

    for i in range(len(keys) - 1):

        has_gap = keys[i + 1] - keys[i] > 1

        if has_gap and predicate(i):
            return keys[i] + 1, i

    raise ValueError("No suitable gap found")


# ============================================================
# MAIN FUNCTION
# ============================================================

def main(rebuild=False):

    state = construct_or_load_tree(rebuild)

    key_value_db = state["key_value_db"]
    keys = state["keys"]
    merkle_root = state["root"]

    print("\nNUMBER OF RECORDS:", len(keys))
    print("BRANCHING FACTOR:", BRANCHING_FACTOR)
    print("TREE DEPTH:", TREE_DEPTH)

    print("Keys sorted:", keys == sorted(keys))

    print("\nMERKLE ROOT:", merkle_root.hex())

    print("JSONL file:", LEAF_VALUES_FILE.name)
    print("Pickle file:", TREE_PICKLE_FILE.name)

    print(
        "Tree levels:",
        [len(level) for level in state["levels"]]
    )

    # ========================================================
    # MEMBERSHIP
    # ========================================================

    query_key = keys[2]
    query_value = key_value_db[query_key]

    proof = generate_membership_proof(
        query_key,
        key_value_db
    )

    membership_verified = verify_membership_proof(
        query_key,
        query_value,
        proof,
        merkle_root
    )

    print("\nMEMBERSHIP VERIFICATION")
    print("Queried key:", query_key)
    print("Proof verified:", membership_verified)
    print(
        "Hash payload size:",
        proof_hash_payload_size(proof),
        "bytes"
    )

    assert membership_verified is True

    # ========================================================
    # FIRST AND LAST LEAF INDICES
    # ========================================================

    first_proof = generate_membership_proof(
        keys[0], key_value_db
    )

    last_proof = generate_membership_proof(
        keys[-1], key_value_db
    )

    assert verify_membership_proof(
        keys[0],
        key_value_db[keys[0]],
        first_proof,
        merkle_root
    )

    assert verify_membership_proof(
        keys[-1],
        key_value_db[keys[-1]],
        last_proof,
        merkle_root
    )

    assert get_authenticated_leaf_index(first_proof) == 0

    assert (
        get_authenticated_leaf_index(last_proof)
        == NUMBER_OF_RECORDS - 1
    )

    # ========================================================
    # CASE 2: SAME PARENT
    # ========================================================

    case2_query, case2_index = find_gap_query(
        keys,
        lambda i: (
            i // BRANCHING_FACTOR
            == (i + 1) // BRANCHING_FACTOR
        )
    )

    # ========================================================
    # CASE 3: DIFFERENT SUBTREES
    # ========================================================

    case3_query, case3_index = find_gap_query(
        keys,
        lambda i: (
            i // BRANCHING_FACTOR
            != (i + 1) // BRANCHING_FACTOR
            and
            i // (BRANCHING_FACTOR ** 2)
            == (i + 1) // (BRANCHING_FACTOR ** 2)
        )
    )

    cases = []

    # Case 1: Before first leaf
    if keys[0] > 1:
        cases.append(
            ("CASE 1: BEFORE FIRST LEAF", keys[0] - 1)
        )

    # Case 2
    cases.append(
        ("CASE 2: SAME PARENT", case2_query)
    )

    # Case 3
    cases.append(
        ("CASE 3: DIFFERENT SUBTREES", case3_query)
    )

    # Case 4: After last leaf
    if keys[-1] < KEY_UNIVERSE:
        cases.append(
            ("CASE 4: AFTER LAST LEAF", keys[-1] + 1)
        )

    # ========================================================
    # VERIFY ALL FOUR CASES
    # ========================================================

    for label, missing_key in cases:

        package = generate_non_membership_proof(
            missing_key,
            key_value_db
        )

        verified = verify_non_membership_from_package(
            missing_key,
            package,
            merkle_root
        )

        print("\n" + label)

        print("Queried key:", missing_key)

        pred = package["predecessor"]
        succ = package["successor"]

        print(
            "Predecessor:",
            pred[0] if pred else None
        )

        print(
            "Successor:",
            succ[0] if succ else None
        )

        print("Non-membership verified:", verified)

        print(
            "Hash payload size:",
            non_membership_hash_payload_size(package),
            "bytes"
        )

        assert verified is True

        # Check structural positions for Cases 2 and 3
        if label.startswith("CASE 2") or label.startswith("CASE 3"):

            pred_i = get_authenticated_leaf_index(
                package["predecessor_proof"]
            )
            succ_i = get_authenticated_leaf_index(
                package["successor_proof"]
            )

            assert succ_i == pred_i + 1

            if label.startswith("CASE 2"):
                assert pred_i == case2_index
                assert pred_i // BRANCHING_FACTOR == (
                    succ_i // BRANCHING_FACTOR
                )
            else:
                assert pred_i == case3_index
                assert pred_i // BRANCHING_FACTOR != (
                    succ_i // BRANCHING_FACTOR
                )
                assert pred_i // (BRANCHING_FACTOR ** 2) == (
                    succ_i // (BRANCHING_FACTOR ** 2)
                )

    # ========================================================
    # NEGATIVE TESTS
    # ========================================================

    print("\nNEGATIVE TESTS")

    middle_package = generate_non_membership_proof(
        case2_query,
        key_value_db
    )

    existing_key = middle_package["predecessor"][0]

    existing_rejected = not verify_non_membership_from_package(
        existing_key,
        middle_package,
        merkle_root
    )

    tampered_value = (
        bytes([query_value[0] ^ 1])
        + query_value[1:]
    )

    tampered_rejected = not verify_membership_proof(
        query_key,
        tampered_value,
        proof,
        merkle_root
    )

    print(
        "Existing key rejected:",
        existing_rejected
    )

    print(
        "Tampered value rejected:",
        tampered_rejected
    )

    assert existing_rejected
    assert tampered_rejected

    print("\nALL TESTS PASSED")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Regenerate the dataset and tree"
    )

    args = parser.parse_args()

    main(rebuild=args.rebuild)
