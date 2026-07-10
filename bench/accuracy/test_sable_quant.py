"""Cross-check the Python port against the exact values asserted in
core/src/zk/halo2/quantizer.rs. Run: python -m pytest test_sable_quant.py
(or just `python test_sable_quant.py`).
"""

import numpy as np

import sable_quant as sq


def test_quantize_matches_rust_docvector():
    # From quantizer.rs doc comment: [0.5,-0.3,0.8,-1.0,1.0] -> [191,89,229,0,255]
    emb = np.array([0.5, -0.3, 0.8, -1.0, 1.0])
    q = sq.quantize(emb)
    assert q.tolist() == [191, 89, 229, 0, 255]


def test_quantize_boundaries():
    # test_quantize_boundary_values: -1->0, 1->255, 0->127 (truncation)
    q = sq.quantize(np.array([-1.0, 1.0, 0.0]))
    assert q.tolist() == [0, 255, 127]


def test_quantize_clamping():
    q = sq.quantize(np.array([-2.0, 2.0, -100.0, 100.0]))
    assert q.tolist() == [0, 255, 0, 255]


def test_quantize_midpoints():
    q = sq.quantize(np.array([-0.5, 0.5]))
    assert q.tolist() == [63, 191]


def test_hamming_identical_is_zero():
    a = np.array([[0.1, -0.2, 0.3, 0.4]])
    assert sq.score_hamming_binary(a, a)[0] == 0.0


def test_hamming_binary_boundary_penalty():
    # 127 (0b0111_1111) vs 128 (0b1000_0000) differ in 8 bits despite being
    # adjacent -- the core risk this whole spike exists to measure.
    a = sq.dequantize(np.array([[127]], dtype=np.uint8))
    b = sq.dequantize(np.array([[128]], dtype=np.uint8))
    assert sq.score_hamming_binary(a, b)[0] == -8.0
    # Gray code makes the same adjacency cost exactly 1 bit.
    assert sq.score_hamming_gray(a, b)[0] == -1.0


def test_gray_is_single_bit_per_level():
    # consecutive levels always 1 Gray bit apart
    vals = np.arange(256, dtype=np.uint8)
    g = vals ^ (vals >> 1)
    pop = np.array([bin(int(x)).count("1") for x in (g[:-1] ^ g[1:])])
    assert (pop == 1).all()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
