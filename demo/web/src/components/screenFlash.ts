// Screen flash liveness capture component
// Captures baseline and flash frames from webcam for server-side liveness verification
// Based on Tang et al. "Face Flashing" (NDSS 2018)

import type { FlashRound } from '../crypto/flashChallenge';

export interface ScreenFlashCapture {
  baselineDataUrl: string;  // JPEG data URL of frame before flash
  flashDataUrl: string;     // JPEG data URL of frame during flash
}

export interface SpatialFlashCapture {
  baselineDataUrl: string;    // JPEG data URL of frame before any flash (ambient)
  roundFrames: string[];      // 3 JPEG data URLs, one per round
}

/** Duration of the screen flash in milliseconds */
const FLASH_DURATION_MS = 500;

/** Delay before capturing flash frame (let camera auto-exposure settle) */
const FLASH_SETTLE_MS = 350;

/**
 * Perform screen flash liveness capture using a running video stream.
 *
 * Flow:
 * 1. Capture baseline frame from video (current ambient lighting)
 * 2. Flash screen white (full-screen overlay)
 * 3. Wait for camera to register the flash
 * 4. Capture flash frame
 * 5. Remove overlay
 *
 * @param video - Active HTMLVideoElement with webcam stream
 * @returns Baseline and flash frame data URLs
 */
export async function performScreenFlash(
  video: HTMLVideoElement
): Promise<ScreenFlashCapture> {
  // 1. Capture baseline frame
  const baselineDataUrl = captureVideoFrame(video);

  // 2. Create full-screen white flash overlay
  const overlay = createFlashOverlay();
  document.body.appendChild(overlay);

  // Force a reflow so the overlay is rendered before we capture
  overlay.offsetHeight;

  // 3. Wait for camera to register the reflected flash
  await sleep(FLASH_SETTLE_MS);

  // 4. Capture flash frame
  const flashDataUrl = captureVideoFrame(video);

  // 5. Keep flash visible briefly, then fade and remove
  await sleep(FLASH_DURATION_MS - FLASH_SETTLE_MS);
  overlay.style.opacity = '0';
  await sleep(200);
  overlay.remove();

  return { baselineDataUrl, flashDataUrl };
}

/**
 * Capture a single frame from a video element as JPEG data URL.
 */
function captureVideoFrame(video: HTMLVideoElement): string {
  const canvas = document.createElement('canvas');
  canvas.width = video.videoWidth || 640;
  canvas.height = video.videoHeight || 480;

  const ctx = canvas.getContext('2d');
  if (!ctx) {
    throw new Error('Failed to get canvas context');
  }

  ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
  return canvas.toDataURL('image/jpeg', 0.85);
}

/**
 * Create a full-screen white flash overlay element.
 */
function createFlashOverlay(): HTMLDivElement {
  const overlay = document.createElement('div');
  overlay.id = 'screen-flash-overlay';
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    background: white;
    z-index: 10000;
    opacity: 1;
    transition: opacity 0.2s ease-out;
    pointer-events: none;
  `;
  return overlay;
}

// ---------------------------------------------------------------------------
// Spatial (split-screen) flash capture
// ---------------------------------------------------------------------------

/** Settle time for camera auto-exposure per round */
const SPATIAL_SETTLE_MS = 350;

/** Minimum time between transitions for WCAG 2.3.1 photosensitive safety */
const MIN_TRANSITION_GAP_MS = 300;

/** Crossfade duration (CSS transition) */
const CROSSFADE_MS = 100;

/** Longer transition for users who prefer reduced motion */
const REDUCED_MOTION_CROSSFADE_MS = 500;

/**
 * Check if the user prefers reduced motion.
 */
function prefersReducedMotion(): boolean {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/**
 * Perform spatial (split-screen top/bottom) multi-color flash capture.
 *
 * Flow:
 * 1. Capture baseline frame (ambient lighting)
 * 2. For each of 3 rounds:
 *    a. Create split-screen overlay (top half = topColor, bottom half = bottomColor)
 *    b. Wait for camera to settle
 *    c. Capture frame
 *    d. Crossfade to next round (overlap overlays briefly)
 * 3. Remove overlay after last capture
 *
 * Total sequence: ~1.3s
 *
 * @param rounds - 3 FlashRound objects with top/bottom RGB colors
 * @param video - Active HTMLVideoElement with webcam stream
 * @returns Baseline and per-round frame data URLs
 */
export async function performSpatialFlash(
  rounds: FlashRound[],
  video: HTMLVideoElement
): Promise<SpatialFlashCapture> {
  const useReducedMotion = prefersReducedMotion();
  const crossfadeDuration = useReducedMotion ? REDUCED_MOTION_CROSSFADE_MS : CROSSFADE_MS;

  // 1. Capture baseline frame (ambient lighting, no overlay)
  const baselineDataUrl = captureVideoFrame(video);

  const roundFrames: string[] = [];
  let previousOverlay: HTMLDivElement | null = null;

  for (let i = 0; i < rounds.length; i++) {
    const round = rounds[i];

    // Create split-screen overlay for this round
    const overlay = createSpatialOverlay(round.topColor, round.bottomColor, crossfadeDuration);
    document.body.appendChild(overlay);

    // Force reflow so the overlay is rendered
    overlay.offsetHeight;

    // If there was a previous overlay, fade it out (crossfade)
    if (previousOverlay) {
      previousOverlay.style.opacity = '0';
      // Remove previous overlay after crossfade completes
      const prev = previousOverlay;
      setTimeout(() => prev.remove(), crossfadeDuration + 50);
    }

    // Wait for camera to settle with the new colors
    // Ensure minimum gap between transitions for WCAG 2.3.1
    const settleTime = Math.max(SPATIAL_SETTLE_MS, MIN_TRANSITION_GAP_MS);
    await sleep(settleTime);

    // Capture frame for this round
    roundFrames.push(captureVideoFrame(video));

    previousOverlay = overlay;
  }

  // Remove the last overlay with a fade
  if (previousOverlay) {
    previousOverlay.style.opacity = '0';
    const last = previousOverlay;
    setTimeout(() => last.remove(), crossfadeDuration + 50);
  }

  return { baselineDataUrl, roundFrames };
}

/**
 * Create a full-screen split overlay with top half and bottom half colors.
 * Uses CSS grid with 2 rows (each 50vh).
 */
function createSpatialOverlay(
  topColor: [number, number, number],
  bottomColor: [number, number, number],
  crossfadeDuration: number
): HTMLDivElement {
  const overlay = document.createElement('div');
  overlay.className = 'spatial-flash-overlay';
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    z-index: 10000;
    opacity: 1;
    transition: opacity ${crossfadeDuration}ms ease-out;
    pointer-events: none;
    display: grid;
    grid-template-rows: 1fr 1fr;
  `;

  const topHalf = document.createElement('div');
  topHalf.style.cssText = `
    background: rgb(${topColor[0]}, ${topColor[1]}, ${topColor[2]});
  `;

  const bottomHalf = document.createElement('div');
  bottomHalf.style.cssText = `
    background: rgb(${bottomColor[0]}, ${bottomColor[1]}, ${bottomColor[2]});
  `;

  overlay.appendChild(topHalf);
  overlay.appendChild(bottomHalf);

  return overlay;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
