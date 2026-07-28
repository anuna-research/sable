# Photometric Stereo

Recovering surface orientation from how a fixed viewpoint responds to *known,
varying illumination*. Where stereo vision moves the camera, photometric stereo
moves the light.

## The Lambertian model

For a diffuse surface patch with albedo ρ and unit normal **n**, lit by a light of
unit direction **l** and intensity L, the observed intensity is

```
I = ρ · L · max(0, n · l)
```

Three or more lights from non-coplanar directions give three or more equations per
patch, enough to solve for **n** (two degrees of freedom) and ρ.

## Colour multiplexing

When several lights of *different colours* fire simultaneously, one RGB frame
carries several measurements at once: each colour channel is dominated by the
lamp whose emission is strongest in that channel. The observation becomes

```
I(p) = Σ_k (ρ(p) ⊙ c_k) · max(0, n(p) · l_k) · v_k(p)
```

for lamps k with colours c_k and visibility v_k. This is what lets a single
captured frame stand in for several sequential exposures.

## Relevance to SABLE

Each SABLE flash round displays four quadrants **simultaneously** in four
HKDF-derived colours and captures one frame, three rounds in total. That is a
colour-multiplexed photometric stereo rig — four known light directions,
demultiplexed by colour, sampled three times. The rig already exists; only the
extraction was missing.

[[SPEC-006-geometric-liveness]] deliberately stops short of solving for **n**.
Absolute light directions depend on unknown face-to-screen distance and pose, so
an absolute solve would need a calibrated [[Device Profile]]. Instead it uses the
*ordinal* structure — which lamp dominates each patch — which is invariant to that
unknown geometry. See `ADR-007` in that spec.

## Limits

- Assumes Lambertian reflectance; specular highlights violate it and need
  rejection or robust fitting.
- Separates **3D from flat**, not **skin from silicone**. A well-formed 3D mask
  presents a real face's normals. Material discrimination needs a reflectance
  cue such as subsurface-scattering highlight softness.
- Ambient illumination reduces the delta signal-to-noise ratio; baseline
  subtraction mitigates but does not eliminate it.

## Reference

Woodham, R. J. *Photometric method for determining surface orientation from
multiple images.* Optical Engineering 19(1), 1980.
