# Verkle READ benchmark — 5^3, BLS12-381 KZG

This folder contains the **first READ experiment only**. UPDATE and INSERT will
be developed separately. It uses the user's **unchanged** `../kzg.py` API
(`setup`, `commit`, `open_at`, `verify`) and an exact copy of the original
Merkle `merkle_5_3.py` for identical random 100-bit key generation, line format,
and record hashing. Place this folder under your existing `verkletree/` folder,
so that `verkletree/kzg.py` is available.

## Tree / indexing conventions

- 5-way tree, depth 3, 125 **real** sorted `(key, JSONL string)` records.
- Scalar field: `py_ecc.optimized_bls12_381.curve_order` (`r`), NOT Fq.
- Leaf value: `int(SHA256(0x02 || key13 || len4 || UTF8(line))) mod r`.
- Leaf commitments: 25 polynomials of degree <=4, evaluated at **consecutive,
  global points** `[0..4]`, `[5..9]`, ..., `[120..124]`.
- Middle: 5 KZG polynomials for 25 child commitments, with global points
  `[0..4]`, `[5..9]`, ..., `[20..24]`.
- Root: 1 polynomial on points `[0..4]` encoding the 5 middle commitments.
- Parent's value for its child: `int(SHA256(0x04 || compress_G1(C_child))) mod r`.
- All node commitments share one degree-4 SRS; `tau` is not saved. The SRS
  is locally generated **for testing**, not a production trusted setup.
- 25+5+1 = **31 KZG commitments** are constructed from scratch.

A membership proof contains 3 KZG evaluation witnesses plus the bottom and
middle commitments (root supplied out of band). At each level the verifier
checks one opening using `kzg.verify` (pairings):

- bottom: `f_bottom(index) = H_to_field(key, text)`
- middle: `f_middle(index // 5) = H_to_field(C_bottom)`
- root: `f_root(index // 25) = H_to_field(C_middle)`

Non-membership proofs use authenticated predecessor/successor leaf positions.
Case 1: before first; case 2: adjacent in same 5-key leaf group; case 3:
adjacent at the boundary of two leaf groups with the same upper parent;
case 4: after last.

**Security model note:** KZG opening proofs alone do not cryptographically
prove that the committed keys are globally sorted. As with the reference
Merkle baseline, these non-membership arguments assume the original
constructor populated its leaf slots in sorted order. Do not claim fully
malicious-prover sound non-membership without a separate sortedness invariant.

## Requirements

Python 3.10+ and `py_ecc` (same package that makes your existing `kzg.py` work).
Install it in a user-controlled environment if needed:

```bash
python3 -m pip install --user py-ecc
```

No sudo is needed for a user installation (provided your server permits pip).

## Commands

From `verkletree/5_3`:

```bash
# First, create, save, reload, and independently validate the Verkle tree:
python3 verkle_5_3.py

# Small smoke test, 4 membership + 4 non-membership (one each case):
python3 read_5_3.py --per-type 4

# Full 1000-read benchmark: 500 membership + 125 of each absence case:
python3 read_5_3.py --per-type 500
```

The builder saves `leaf_values_5_3.jsonl` and `verkle_tree_5_3.pkl` locally,
reusing them on subsequent runs. Only use the pickle if you generated it
locally and trust its source. `--rebuild` explicitly recreates both files,
including a fresh educational KZG SRS.

The benchmark exports `read_benchmark_5_3.csv`, preserving every individual
query's category, search time, KZG proof-generation time, total read time,
actual serialized proof size, KZG verification time, and pass/fail status.
Search + proof = total read; verification is separately timed. Pickle load,
SRS setup, initial construction, query sampling, CSV writing, and serialization
are outside per-query timers. Test tampering is checked outside timed regions.

**Performance caution:** BLS12-381 pairing verification in pure Python can be
slow. Each membership query performs 3 `kzg.verify` calls (each two pairings);
interior non-membership does so twice, one per neighboring key. Start with
`--per-type 4` and run all 1000 queries only after verifying correctness.
