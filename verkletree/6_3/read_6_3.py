"""READ benchmark for continuous-global-index KZG Verkle 6^3 baseline.

1000 queries by default: 500 membership and 125 each of four nonmembership
cases. Times: search, three-opening proof generation, total read, independent
three-pairing-equation verification per membership path; serialized proof size.

Nonmembership is predecessor/successor based and assumes the committed keys
are sorted. A KZG root ALONE does not cryptographically enforce sortedness;
this is the same model limitation as the Merkle sorted-key baseline.
"""

import argparse
from bisect import bisect_left
import csv
from pathlib import Path
import random
import statistics
import time

import verkle_6_3 as verkle
kzg = verkle.kzg

BASE = Path(__file__).resolve().parent
CSV_PATH = BASE / "read_benchmark_6_3.csv"
FANOUT = verkle.FANOUT
KEY_BYTES = merkle_key_bytes = 13


def create_membership_proof(state, key, index, text):
    """Produce fresh KZG witnesses, never store/precompute query proofs."""
    if state["keys"][index] != key:
        raise ValueError("Key/index mismatch")
    commitments = []
    witnesses = []
    for level in range(verkle.DEPTH):
        x = index // (FANOUT ** level)  # 0..124, 0..24, 0..4
        node = state["levels"][level][x // FANOUT]
        if x not in node["xs"]:
            raise ValueError("Invalid global evaluation position")
        actual_y, witness = kzg.open_at(node["coeffs"], x, state["srs_g1"])
        expected_y = (
            verkle.record_to_field(key, text) if level == 0
            else verkle.commitment_to_field(commitments[level - 1])
        )
        if actual_y != expected_y:
            raise ValueError("Stored evaluation does not match claimed record/child")
        if level < verkle.DEPTH - 1:
            commitments.append(node["commitment"])
        else:
            if node["commitment"] != state["root"]:
                raise ValueError("Root mismatch")
        witnesses.append(verkle.point_to_bytes(witness))
    return {
        "key": key, "index": index, "text": text,
        "commitments": commitments,  # bottom, middle; root already trusted
        "witnesses": witnesses,        # bottom, middle, root
    }


def verify_membership(query_key, response, trusted_root, srs_g2):
    """Verifier sees only request, response, trusted root and public KZG SRS."""
    try:
        if response["key"] != query_key:
            return False
        index = response["index"]
        if not isinstance(index, int) or not (0 <= index < verkle.LEAVES):
            return False
        commitments = response["commitments"]
        witnesses = response["witnesses"]
        if len(commitments) != verkle.DEPTH - 1 or len(witnesses) != verkle.DEPTH:
            return False
        if not isinstance(response["text"], str):
            return False
        prev_commitment = None
        for level in range(verkle.DEPTH):
            x = index // FANOUT ** level
            if level == 0:
                y = verkle.record_to_field(query_key, response["text"])
            else:
                y = verkle.commitment_to_field(prev_commitment)
            c_bytes = commitments[level] if level < verkle.DEPTH - 1 else trusted_root
            c_point = verkle.bytes_to_point(c_bytes)
            w_point = verkle.bytes_to_point(witnesses[level])
            if not kzg.verify(c_point, x, y, w_point, srs_g2):
                return False
            prev_commitment = c_bytes
        return True
    except (ValueError, KeyError, IndexError, TypeError, OverflowError, AttributeError):
        return False


def serialized_membership(response):
    """Compact verifiable transport: index, key, text, 2 child Cs and 3 Ws."""
    text_bytes = response["text"].encode("utf-8")
    payload = (
        response["key"].to_bytes(KEY_BYTES, "big")
        + response["index"].to_bytes(4, "big")
        + len(text_bytes).to_bytes(4, "big")
        + text_bytes
        + b"".join(response["commitments"])
        + b"".join(response["witnesses"])
    )
    assert len(response["commitments"]) == verkle.DEPTH-1 and len(response["witnesses"]) == verkle.DEPTH
    assert all(len(a) == verkle.POINT_BYTES for a in
               response["commitments"] + response["witnesses"])
    return payload


def serialize_proof(kind, response):
    if kind == "membership":
        return b"VK3M" + serialized_membership(response)
    if kind not in {"before_first", "same_leaf_group", "across_leaf_groups", "after_last"}:
        raise ValueError("Unrecognized non-membership category")
    before = response["predecessor"]
    after = response["successor"]
    cases = {"before_first": 1, "same_leaf_group": 2,
             "across_leaf_groups": 3, "after_last": 4}
    data = bytearray(b"VK3N")
    data.append(cases[kind])
    data.append((1 if before else 0) + (2 if after else 0))
    if before:
        data.extend(serialized_membership(before))
    if after:
        data.extend(serialized_membership(after))
    return bytes(data)


def get_neighbors(state, texts, query):
    keys = state["keys"]
    pos = bisect_left(keys, query)
    if pos < len(keys) and keys[pos] == query:
        raise ValueError("Expected absent query key")
    pred = (keys[pos-1], pos-1, texts[pos-1]) if pos else None
    succ = (keys[pos], pos, texts[pos]) if pos < len(keys) else None
    return pred, succ


def build_absence_proof(state, neighbors):
    pred, succ = neighbors
    def member(entry):
        if entry is None:
            return None
        key, idx, text = entry
        return create_membership_proof(state, key, idx, text)
    return {"predecessor": member(pred), "successor": member(succ)}


def verify_nonmembership(query_key, category, response, trusted_root, srs_g2):
    """Require valid KZG membership paths + sorted adjacent boundary positions."""
    try:
        pred = response["predecessor"]
        succ = response["successor"]
        if pred is None and succ is None:
            return False
        if pred is not None:
            if not (pred["key"] < query_key and
                    verify_membership(pred["key"], pred, trusted_root, srs_g2)):
                return False
        if succ is not None:
            if not (query_key < succ["key"] and
                    verify_membership(succ["key"], succ, trusted_root, srs_g2)):
                return False
        if category == "before_first":
            return pred is None and succ is not None and succ["index"] == 0
        if category == "after_last":
            return succ is None and pred is not None and pred["index"] == verkle.LEAVES-1
        if pred is None or succ is None:
            return False
        if succ["index"] != pred["index"] + 1:
            return False
        if category == "same_leaf_group":
            return pred["index"] // FANOUT == succ["index"] // FANOUT
        if category == "across_leaf_groups":
            return (pred["index"] // FANOUT != succ["index"] // FANOUT
                    and pred["index"] // (FANOUT * FANOUT)
                    == succ["index"] // (FANOUT * FANOUT))
        return False
    except (KeyError, IndexError, TypeError, ValueError):
        return False


def sample_between(a, b, rng):
    if b-a < 2:
        raise ValueError("No integer query strictly between adjacent keys")
    return rng.randint(a+1, b-1)


def generate_queries(keys, per_type, seed):
    if per_type <= 0 or per_type % 4:
        raise ValueError("--per-type must be a positive multiple of four")
    rng = random.Random(seed)
    all_queries = []
    for _ in range(per_type):
        all_queries.append(("membership", keys[rng.randrange(len(keys))]))
    n_each = per_type // 4
    before = keys[0]
    after = keys[-1]
    if before <= 1 or after >= merkle_key_max():
        raise ValueError("No valid boundary query; regenerate random dataset")
    # Uniformly sample eligible adjacent pairs by selecting a group/block directly.
    # Avoid allocating O(N) candidate lists for the 40-million-record case.
    def same_pair():
        for _ in range(1000):
            group = rng.randrange(len(keys) // FANOUT)
            pos = rng.randrange(FANOUT - 1)
            i = group * FANOUT + pos
            if keys[i+1] - keys[i] >= 2:
                return i
        raise ValueError("Could not sample adjacent same-parent keys with a gap")

    def cross_pair():
        for _ in range(1000):
            parent_group = rng.randrange(len(keys) // (FANOUT * FANOUT))
            boundary = rng.randrange(1, FANOUT)
            i = parent_group * FANOUT * FANOUT + boundary * FANOUT - 1
            if keys[i+1] - keys[i] >= 2:
                return i
        raise ValueError("Could not sample adjacent child-group boundary with a gap")

    for _ in range(n_each):
        all_queries.append(("before_first", rng.randrange(1, before)))
        i = same_pair()
        all_queries.append(("same_leaf_group", sample_between(keys[i], keys[i+1], rng)))
        i = cross_pair()
        all_queries.append(("across_leaf_groups", sample_between(keys[i], keys[i+1], rng)))
        all_queries.append(("after_last", rng.randrange(after+1, merkle_key_max()+1)))
    rng.shuffle(all_queries)
    return all_queries


def merkle_key_max():
    return 2**100


def ms_since(start):
    return (time.perf_counter()-start)*1000.0


def summarize(rows, count, output):
    print("\nVERKLE 6^3 BLS12-381 KZG READ RESULTS")
    print(f"Queries: {count} membership + {count} nonmembership; all verified")
    print("Timings: ms (mean +/- sample SD); total read excludes verification")
    print("Each membership proof checks DEPTH independent KZG openings")
    def stats(values):
        return f"{statistics.mean(values):.3f} +/- {statistics.stdev(values) if len(values)>1 else 0:.3f}"
    types = ["membership", "before_first", "same_leaf_group",
             "across_leaf_groups", "after_last", "nonmembership_all"]
    print(f"{'Type':23s} {'N':>5s} {'Search ms':>19s} {'Proof ms':>19s} "
          f"{'Total ms':>19s} {'Verify ms':>19s} {'Bytes':>19s}")
    for label in types:
        selection = [r for r in rows if (r["type"] != "membership" if label == "nonmembership_all"
                                        else r["type"] == label)]
        if not selection:
            continue
        print(f"{label:23s} {len(selection):5d} "
              f"{stats([r['search_ms'] for r in selection]):>19s} "
              f"{stats([r['proof_ms'] for r in selection]):>19s} "
              f"{stats([r['total_read_ms'] for r in selection]):>19s} "
              f"{stats([r['verification_ms'] for r in selection]):>19s} "
              f"{stats([r['proof_bytes'] for r in selection]):>19s}")
    print(f"\nRaw per-query CSV: {output}")


def run(per_type=500, seed=20261027, output=CSV_PATH):
    if per_type <= 0 or per_type % 4:
        raise ValueError("--per-type must be a positive multiple of four")
    print("Loading saved Verkle 6^3 tree and independently validating all KZG commitments...", flush=True)
    state, texts = verkle.construct_or_load(rebuild=False)
    queries = generate_queries(state["keys"], per_type, seed)
    rows = []
    # Negative tests on the first query of each type (outside benchmark timings).
    checked_tamper = False
    for sequence, (kind, query) in enumerate(queries, 1):
        t0 = time.perf_counter()
        if kind == "membership":
            idx = state["key_to_index"].get(query)
            if idx is None:
                raise AssertionError("Unexpected absent membership query")
            search_result = (query, idx, texts[idx])
        else:
            search_result = get_neighbors(state, texts, query)
        search_ms = ms_since(t0)

        t0 = time.perf_counter()
        if kind == "membership":
            response = create_membership_proof(state, *search_result)
        else:
            response = build_absence_proof(state, search_result)
        proof_ms = ms_since(t0)

        t0 = time.perf_counter()
        verified = (verify_membership(query, response, state["root"], state["srs_g2"])
                    if kind == "membership" else
                    verify_nonmembership(query, kind, response, state["root"], state["srs_g2"]))
        verification_ms = ms_since(t0)
        if not verified:
            raise AssertionError(f"Proof failed: {kind} #{sequence}")

        if kind == "membership" and not checked_tamper:
            tampered = dict(response, text=response["text"] + " [TAMPERED]")
            if verify_membership(query, tampered, state["root"], state["srs_g2"]):
                raise AssertionError("Tampered record incorrectly verified")
            if verify_membership(query+1, response, state["root"], state["srs_g2"]):
                raise AssertionError("Wrong query key incorrectly verified")
            checked_tamper = True
            print("Tampered membership response rejected: PASS", flush=True)
        bytes_count = len(serialize_proof(kind, response))
        pred = response.get("predecessor") if kind != "membership" else None
        succ = response.get("successor") if kind != "membership" else None
        rows.append({
            "seq": sequence, "type": kind, "query_key": query,
            "leaf_index": response["index"] if kind == "membership" else "",
            "predecessor_key": pred["key"] if pred else "",
            "successor_key": succ["key"] if succ else "",
            "search_ms": search_ms, "proof_ms": proof_ms,
            "total_read_ms": search_ms + proof_ms,
            "verification_ms": verification_ms, "proof_bytes": bytes_count,
            "kzg_openings": verkle.DEPTH if kind == "membership" else verkle.DEPTH*(int(pred is not None)+int(succ is not None)),
            "verified": verified,
        })
        if sequence % 50 == 0 or sequence == len(queries):
            print(f"Verified {sequence}/{len(queries)} READ proofs", flush=True)

    columns = ["seq", "type", "query_key", "leaf_index", "predecessor_key",
               "successor_key", "search_ms", "proof_ms", "total_read_ms",
               "verification_ms", "proof_bytes", "kzg_openings", "verified"]
    with Path(output).open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    summarize(rows, per_type, output)
    print("PASS: all membership and nonmembership KZG READ queries verified")
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--per-type", type=int, default=500,
                   help="membership count; same number of nonmembership, equally split four ways")
    p.add_argument("--seed", type=int, default=20261027)
    p.add_argument("--output", type=Path, default=CSV_PATH)
    args = p.parse_args()
    run(args.per_type, args.seed, args.output)


if __name__ == "__main__":
    main()
