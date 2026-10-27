# Verkle READ benchmark suite — all 11 configurations

This package extends the user's tested `5_3` continuous-global-index BLS12-381 KZG Verkle benchmark to all 11 Merkle comparison configurations.

## Layout

`kzg.py` is the user's original unchanged implementation using `py_ecc`. Each `B_D` folder contains `merkle_B_D.py` (original baseline key generator and hashing), `verkle_B_D.py` (build / save / reload / validate), and `read_B_D.py` (1,000 read proofs and verification CSV). Only READ is implemented; UPDATE and INSERT are future steps.

## Configurations

| Config | Keys | Depth | KZG commitments |
|---|---:|---:|---:|
| `5_3` | 125 | 3 | 31 |
| `5_6` | 15,625 | 6 | 3,906 |
| `5_9` | 1,953,125 | 9 | 488,281 |
| `6_3` | 216 | 3 | 43 |
| `6_6` | 46,656 | 6 | 9,331 |
| `6_9` | 10,077,696 | 9 | 2,015,539 |
| `7_3` | 343 | 3 | 57 |
| `7_6` | 117,649 | 6 | 19,608 |
| `7_9` | 40,353,607 | 9 | 6,725,601 |
| `8_3` | 512 | 3 | 73 |
| `8_6` | 262,144 | 6 | 37,449 |

## Indexing and cryptography

- Every node has degree <= fanout-1 and evaluates at its *global* indices. At leaf record level they are `0..N-1`, then `0..N/b-1`, and so on, with nonoverlapping consecutive blocks.
- Record field element: `int(SHA256(0x02 || key_13 || length_4 || UTF8(line))) mod curve_order`.
- Parent child field element: `int(SHA256(0x04 || compressed_G1(child))) mod curve_order`.
- The root is a KZG G1 commitment; membership reveals depth-1 child commitments and depth KZG witnesses, each checked by actual BLS12-381 pairings.
- Non-membership proofs use predecessor and successor openings with authenticated adjacent positions and assume the sorted-key invariant is enforced by the original dataset constructor. The root alone does NOT enforce sorting; do not claim fully malicious-prover nonmembership soundness.
- `kzg.py` uses a locally generated experimental SRS; NEVER use for production security.

## Requirements

Python 3, `py_ecc` installed on destination machine (your existing `kzg.py` requires it). No sudo required if already installed.

## Run one tree

```bash
cd verkletree/5_6
python3 verkle_5_6.py
python3 read_5_6.py --per-type 4
python3 read_5_6.py --per-type 500
```

## Run all on a server

```bash
cd verkletree
bash run_verkle_reads.sh --only 5_6 --per-type 4
# after a successful smoke test:
nohup bash ./run_verkle_reads.sh --per-type 500 > verkle_read_full.log 2>&1 < /dev/null &
echo $! > verkle_read_full.pid
```

Runner saves per-tree CSVs and build/read logs under `benchmark_runs/verkle_reads_<host>_<timestamp>_<pid>/`. `--stage build`, `--stage read`, `--only B_D` are supported. Build runs reuse existing snapshots and revalidate them, without overwriting unless explicitly `--rebuild` is used on an individual constructor.

## Important resource caveats

The original *pure Python* `kzg.commit` performs one BLS12-381 scalar multiplication per polynomial coefficient, and *every internal node* is committed. For `7_9` this means **6,725,601 separate node commitments** and ~47 million G1 scalar multiplications in construction alone, plus expensive full-node validation, save/reload, and per-query pairing checks. This is vastly more expensive than Merkle hashing; completing the largest cases can require extremely substantial compute time and storage, even on a high-memory server. It has NOT been end-to-end tested in this environment (py_ecc unavailable here). Monitor a `5_6` full run first, then choose resources/scheduling appropriate for larger configurations.

Do not compare raw total end-to-end runtime to SHA-256 Merkle READ before specifying which stages (construction, prevalidation, pickle serialization, revalidation, search, proof, verification) are included.
