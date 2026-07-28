# Delta Fingerprint

The 16-bit code SABLE uses to summarise a flash response for in-circuit
comparison. Defined by `quantize_delta_fingerprint` in
`demo/server/src/flash_challenge.rs`.

## Layout

```
bit  15 14 13 | 12 11 10 9 | 8 7 6 5 | 4 3 2 1 0
     order    | mid_ratio  | min_ratio | magnitude
     (3 bits) | (4 bits)   | (4 bits)  | (5 bits)
```

| Field | Width | Meaning |
|-------|-------|---------|
| `order` | 3 | Which of the 6 orderings of R/G/B by absolute value holds |
| `mid_ratio` | 4 | `\|mid\| / \|max\|` scaled to [0,15] |
| `min_ratio` | 4 | `\|min\| / \|max\|` scaled to [0,15] |
| `magnitude` | 5 | `min(31, \|max\| × 31 / 128)` |

A zero delta encodes as `0x0000`.

## Properties

- **Chromatic, not geometric.** The code captures the *colour direction* and
  strength of a delta. It carries no information about surface shape. This is the
  gap [[SPEC-006-geometric-liveness]] exists to close.
- **Sign-invariant.** Channels are taken in absolute value, so a delta and its
  negation encode identically.
- **Comparison is Hamming distance**, which is why the field widths are small and
  the layout is fixed — the in-circuit check is a lookup-backed popcount.

## Known defect

The encoding is implemented twice — once in Rust, once in TypeScript — with a
source comment requiring the two to stay identical. Two independent
implementations of one wire format is the shotgun-parser pattern; a divergence
between them is a soundness bug rather than a display bug. See
[[SPEC-006-geometric-liveness]] "Known Defects in the Surrounding Design".

The encoder also lives in `demo/server` despite being a contract shared by the
circuit, the server, and the client.
