#!/usr/bin/env python3
"""Optional: extract face embeddings for a dataset into an npz the benchmark
can consume. This is a *convenience* path for a fast first look with a Python
backbone -- for numbers that reflect the deployed system, export embeddings
from the actual Human library (TF.js, 1024-d) instead and feed those in.

Layout expected (ImageFolder-style):
    root/<identity>/<image>.jpg

Output npz keys: embeddings (N,D) float32, labels (N,) <identity strings>.
Feed straight into:  python benchmark.py --embeddings out.npz

Backends:
    facenet  -- facenet-pytorch (InceptionResnetV1, 512-d, VGGFace2)
    insight  -- insightface buffalo_l (ArcFace, 512-d)

Both are 512-d, NOT the 1024-d Human library SABLE deploys. Use them to learn
the *shape* of the quantization/Hamming degradation quickly; reproduce the
final number on real 1024-d Human embeddings before drawing conclusions.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import numpy as np

IMG_EXT = {".jpg", ".jpeg", ".png", ".bmp"}


def iter_images(root: Path):
    for ident_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        for img in sorted(ident_dir.iterdir()):
            if img.suffix.lower() in IMG_EXT:
                yield ident_dir.name, img


def extract_facenet(root: Path):
    import torch
    from facenet_pytorch import InceptionResnetV1, MTCNN
    from PIL import Image

    device = "cuda" if torch.cuda.is_available() else "cpu"
    mtcnn = MTCNN(image_size=160, device=device)
    model = InceptionResnetV1(pretrained="vggface2").eval().to(device)

    embs, labels = [], []
    for ident, img_path in iter_images(root):
        img = Image.open(img_path).convert("RGB")
        face = mtcnn(img)
        if face is None:
            continue
        with torch.no_grad():
            e = model(face.unsqueeze(0).to(device)).cpu().numpy()[0]
        embs.append(e); labels.append(ident)
    return np.asarray(embs, np.float32), np.asarray(labels)


def extract_insight(root: Path):
    import cv2
    from insightface.app import FaceAnalysis

    app = FaceAnalysis(name="buffalo_l")
    app.prepare(ctx_id=0, det_size=(640, 640))

    embs, labels = [], []
    for ident, img_path in iter_images(root):
        img = cv2.imread(str(img_path))
        if img is None:
            continue
        faces = app.get(img)
        if not faces:
            continue
        faces.sort(key=lambda f: (f.bbox[2] - f.bbox[0]) * (f.bbox[3] - f.bbox[1]))
        embs.append(faces[-1].embedding); labels.append(ident)
    return np.asarray(embs, np.float32), np.asarray(labels)


def _insight_app():
    from insightface.app import FaceAnalysis
    a = FaceAnalysis(name="buffalo_l", providers=["CPUExecutionProvider"],
                     allowed_modules=["detection", "recognition"])
    a.prepare(ctx_id=-1, det_size=(320, 320))
    return a


def _list_images(root: Path):
    return sorted(p for p in root.iterdir() if p.suffix.lower() in IMG_EXT)


def insight_worker(root: str, out_chunk: str, start: int, count: int):
    """Process images[start:start+count] in a FRESH process and exit.

    Running each chunk as its own process is the only reliable way to release
    onnxruntime's *native* memory between chunks (del+gc does not), which is
    what kept SIGKILLing the long-lived extractor around ~6k images.
    """
    import cv2
    imgs = _list_images(Path(root))[start:start + count]
    app = _insight_app()
    out, dropped = {}, 0
    for i, p in enumerate(imgs):
        img = cv2.imread(str(p))
        if img is None:
            dropped += 1; continue
        faces = app.get(img)
        if not faces:
            dropped += 1; continue
        faces.sort(key=lambda f: (f.bbox[2] - f.bbox[0]) * (f.bbox[3] - f.bbox[1]))
        out[p.stem] = faces[-1].embedding.astype(np.float32)
        if (i + 1) % 500 == 0:
            print(f"    worker[{start}]: {i+1}/{len(imgs)}", flush=True)
    np.savez(out_chunk, **out)
    print(f"  worker[{start}] wrote {len(out)} ({dropped} dropped)", flush=True)


def extract_insight_flat(root: Path, out_path: str, chunk: int = 2500):
    """Flat dir -> name-keyed embeddings via one subprocess per chunk.

    Completed chunks persist as chunk_*.npz (immutable), so a kill resumes from
    the last completed chunk. Final step merges them into out_path.
    """
    import subprocess
    imgs = _list_images(root)
    n = len(imgs)
    chunkdir = Path(out_path + ".chunks")
    chunkdir.mkdir(parents=True, exist_ok=True)

    for start in range(0, n, chunk):
        cf = chunkdir / f"chunk_{start:07d}.npz"
        if cf.exists():
            print(f"  [skip chunk {start}]", flush=True)
            continue
        print(f"  >> chunk {start}..{min(start+chunk, n)} / {n}", flush=True)
        r = subprocess.run([sys.executable, os.path.abspath(__file__),
                            "__insight_worker__", str(root), str(cf),
                            str(start), str(chunk)])
        if r.returncode != 0:
            raise SystemExit(f"insight worker chunk {start} failed rc={r.returncode}")

    out: dict[str, np.ndarray] = {}
    chunks = sorted(chunkdir.glob("chunk_*.npz"))
    for cf in chunks:
        d = np.load(cf, allow_pickle=True)
        for k in d.files:
            out[k] = d[k]
    dropped = n - len(out)
    np.savez(out_path, **out)
    print(f"  merged {len(chunks)} chunks -> {len(out)} embeddings", flush=True)
    for cf in chunks:
        cf.unlink()
    chunkdir.rmdir()
    return out, dropped


def main():
    # Internal per-chunk worker entrypoint (see extract_insight_flat):
    #   <script> __insight_worker__ <root> <out_chunk> <start> <count>
    import sys as _sys
    if len(_sys.argv) >= 6 and _sys.argv[1] == "__insight_worker__":
        _, _, root, out_chunk, start, count = _sys.argv[:6]
        insight_worker(root, out_chunk, int(start), int(count))
        return

    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("root", help="dataset root (ImageFolder, or flat dir with --flat)")
    p.add_argument("out", help="output .npz")
    p.add_argument("--backend", choices=["facenet", "insight"], default="facenet")
    p.add_argument("--flat", action="store_true",
                   help="root is a flat dir of images; emit name-keyed npz (key=stem)")
    args = p.parse_args()

    root = Path(args.root)

    if args.flat:
        if args.backend != "insight":
            raise SystemExit("--flat currently supports --backend insight only")
        out, dropped = extract_insight_flat(root, args.out)
        if not out:
            raise SystemExit("no faces detected -- check dir / deps")
        np.savez(args.out, **out)
        dim = next(iter(out.values())).shape[0]
        print(f"wrote {args.out}: {len(out)} keyed embeddings, dim={dim}, "
              f"{dropped} dropped (insight/flat)")
        return

    extract = extract_facenet if args.backend == "facenet" else extract_insight
    embs, labels = extract(root)
    if len(embs) == 0:
        raise SystemExit("no faces detected -- check dataset layout / backend deps")

    np.savez(args.out, embeddings=embs, labels=labels)
    n_ids = len(set(labels.tolist()))
    print(f"wrote {args.out}: {len(embs)} embeddings, {n_ids} identities, "
          f"dim={embs.shape[1]} ({args.backend})")


if __name__ == "__main__":
    main()
