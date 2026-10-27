# Verkle READ baseline 6^6 (46,656 records)

BLS12-381 KZG, branching factor **6**, depth **6**, 9,331 KZG commitments.

The evaluation points at each level are **global contiguous indices** from 0 onward, never reset to 0 per node. First layer: `0..46655`; next layer: `0..7775`; root child evaluations `0..5`.

One educational SRS of maximum degree 5. Original random sorted 100-bit key generator and original SHA256 H(key,line) encoding. Child commitments mapped to the scalar field by SHA256(0x04||compressed_G1(C)) mod r.

Commands, from this folder:

```sh
python3 verkle_6_6.py
python3 read_6_6.py --per-type 4
python3 read_6_6.py --per-type 500
```

The read benchmark has 6 KZG openings per membership. Interior non-membership contains TWO neighboring membership paths. All KZG pairing verifications are timed separately.

**Security qualification:** predecessor/successor non-membership needs an externally enforced sortedness invariant; a commitment to an arbitrary vector alone does not establish sortedness.
