// Screen flash liveness capture component
// Captures baseline and flash frames from webcam for server-side liveness verification
// Based on Tang et al. "Face Flashing" (NDSS 2018)

export interface ScreenFlashCapture {
  baselineDataUrl: string;  // JPEG data URL of frame before flash
  flashDataUrl: string;     // JPEG data URL of frame during flash
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

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
