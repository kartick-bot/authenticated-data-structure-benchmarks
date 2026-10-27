# Verkle READ baseline 7^9 (40,353,607 records)

BLS12-381 KZG, branching factor **7**, depth **9**, 6,725,601 KZG commitments.

The evaluation points at each level are **global contiguous indices** from 0 onward, never reset to 0 per node. First layer: `0..40353606`; next layer: `0..5764800`; root child evaluations `0..6`.

One educational SRS of maximum degree 6. Original random sorted 100-bit key generator and original SHA256 H(key,line) encoding. Child commitments mapped to the scalar field by SHA256(0x04||compressed_G1(C)) mod r.

Commands, from this folder:

```sh
python3 verkle_7_9.py
python3 read_7_9.py --per-type 4
python3 read_7_9.py --per-type 500
```

The read benchmark has 9 KZG openings per membership. Interior non-membership contains TWO neighboring membership paths. All KZG pairing verifications are timed separately.

**Security qualification:** predecessor/successor non-membership needs an externally enforced sortedness invariant; a commitment to an arbitrary vector alone does not establish sortedness.
