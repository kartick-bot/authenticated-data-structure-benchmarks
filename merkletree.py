"""Minimal binary Merkle tree baseline, built from scratch with the Python stdlib.

Stores original (key, value) records in a dictionary and retains only the
Merkle root after construction. Leaf and internal hashes are temporary during
root construction. A queried leaf's sibling hash is recomputed on demand.

Current version requires a power-of-two number of records.
"""

import hashlib
import secrets


KEY_UNIVERSE = 2**100
VALUE_LENGTH_BYTES = 32  # 256-bit values
NUMBER_OF_RECORDS = 8


def generate_records(n):
    """Create n distinct random keys, each mapped to a 256-bit byte string."""
    if not 1 <= n <= KEY_UNIVERSE:
        raise ValueError("Record count must be between 1 and 2**100")

    records = {}
    while len(records) < n:
        key = secrets.randbelow(KEY_UNIVERSE) + 1  # [1, 2**100]
        if key not in records:
            records[key] = secrets.token_bytes(VALUE_LENGTH_BYTES)
    return records

def sort_key_value_db(key_value_db):

    sorted_records = sorted(
        key_value_db.items(),
        key=lambda item: item[0].to_bytes(13, "big")
    )

    return dict(sorted_records)



def hash_leaf(key, value):
    """Hash an unambiguously encoded (key, value) record."""
    # 2**100 needs 101 bits, which fit in 13 bytes.
    key_bytes = key.to_bytes(13, byteorder="big")
    value_length = len(value).to_bytes(4, byteorder="big")
    return hashlib.sha256(b"\x00" + key_bytes + value_length + value).digest()


def hash_internal(left_hash, right_hash):
    """Hash two ordered child hashes into one internal-node hash."""
    return hashlib.sha256(b"\x01" + left_hash + right_hash).digest()


def build_merkle_root(key_value_db, show_steps=True):
    """Compute the root; do not return or retain the intermediate nodes."""
    n = len(key_value_db)
    if n == 0 or (n & (n - 1)) != 0:
        raise ValueError("For now, the number of records must be a power of 2")

    # This local list exists only during construction and is discarded on return.
    current_level = [hash_leaf(k, v) for k, v in key_value_db.items()]

    if show_steps:
        print("\nLEAF HASHES")
        for i, digest in enumerate(current_level):
            print(f"Leaf {i}: {digest.hex()}")

    level_number = 1
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            parent = hash_internal(current_level[i], current_level[i + 1])
            next_level.append(parent)

        if show_steps and len(next_level) > 1:
            print(f"\nINTERNAL LEVEL {level_number} ({len(next_level)} nodes)")
            for i, digest in enumerate(next_level):
                print(f"Node {i}: {digest.hex()}")

        current_level = next_level
        level_number += 1

    return current_level[0]  # Only the root escapes this function.


def get_leaf_sibling(key, key_value_db):
    """Compute the queried leaf's sibling hash from the original records."""
    if key not in key_value_db:
        raise KeyError("Queried key is not in the database")

    # Insertion order is exactly the leaf order used to compute the root.
    keys = list(key_value_db.keys())
    if len(keys) < 2:
        raise ValueError("A single-leaf tree has no leaf sibling")

    leaf_index = keys.index(key)
    sibling_index = leaf_index ^ 1
    sibling_key = keys[sibling_index]
    sibling_value = key_value_db[sibling_key]

    return hash_leaf(sibling_key, sibling_value)

def get_parent_sibling(key, key_value_db):

    if key not in key_value_db:
        raise KeyError("Key not found")

    keys = list(key_value_db.keys())

    # Locate queried leaf
    leaf_index = keys.index(key)

    # Find its parent's index
    parent_index = leaf_index // 2

    # Find the sibling parent
    sibling_parent_index = parent_index ^ 1

    # Determine the two leaves under the sibling parent
    start = sibling_parent_index * 2

    left_key = keys[start]
    right_key = keys[start + 1]

    # Compute the two leaf hashes on demand
    left_hash = hash_leaf(
        left_key, key_value_db[left_key]
    )

    right_hash = hash_leaf(
        right_key, key_value_db[right_key]
    )

    # Compute the sibling parent hash
    sibling_parent_hash = hash_internal(
        left_hash, right_hash
    )

    return sibling_parent_hash

def get_root_sibling(key, key_value_db):

    keys = list(key_value_db.keys())

    if len(keys) != 8:
        raise ValueError("This step assumes exactly 8 records")

    if key not in key_value_db:
        raise KeyError("Key not found")

    leaf_index = keys.index(key)

    # Identify the sibling subtree (4 leaves)
    subtree_index = leaf_index // 4
    sibling_subtree_index = subtree_index ^ 1

    start = sibling_subtree_index * 4

    # Compute the four leaf hashes on demand
    h0 = hash_leaf(keys[start], key_value_db[keys[start]])
    h1 = hash_leaf(keys[start + 1], key_value_db[keys[start + 1]])
    h2 = hash_leaf(keys[start + 2], key_value_db[keys[start + 2]])
    h3 = hash_leaf(keys[start + 3], key_value_db[keys[start + 3]])

    # Compute the two parent hashes
    p0 = hash_internal(h0, h1)
    p1 = hash_internal(h2, h3)

    # Compute the sibling subtree root
    sibling_hash = hash_internal(p0, p1)

    return sibling_hash



def main():
    # The one dataset used by root construction and membership queries.
    # key_value_db = generate_records(NUMBER_OF_RECORDS)
    
    key_value_db = generate_records(NUMBER_OF_RECORDS)

# Sort records before building the Merkle tree
    key_value_db = sort_key_value_db(key_value_db)  

    print("KEY-VALUE DATABASE (not part of the tree)")
    for key, value in key_value_db.items():
        print(f"Key: {key}, Value: {value.hex()}")

    # Internal nodes are computed temporarily, then discarded.
    merkle_root = build_merkle_root(key_value_db)
    print("\nMERKLE ROOT:", merkle_root.hex())

    # Example: query the third record (zero-based index 2).
    query_key = list(key_value_db.keys())[2]
    sibling_hash = get_leaf_sibling(query_key, key_value_db)
    keys = list(key_value_db.keys())
    assert keys == sorted(keys)
    print("Keys are sorted lexicographically!")

    print("\nON-DEMAND LEAF SIBLING QUERY")
    print("Queried key:", query_key)
    print("Sibling hash:", sibling_hash.hex())

    parent_sibling_hash = get_parent_sibling(
        query_key,
        key_value_db
    )

    root_sibling_hash = get_root_sibling(
        query_key,
        key_value_db
    )

    print("\nON-DEMAND ROOT-LEVEL SIBLING")
    print("Sibling hash:", root_sibling_hash.hex())


    print("\nON-DEMAND PARENT SIBLING")
    print("Sibling hash:", parent_sibling_hash.hex())



    # No leaf_hashes, parent_hashes, or merkle_levels are retained.
    # Next step: compute higher-level sibling hashes for a full membership proof.


if __name__ == "__main__":
    main()
