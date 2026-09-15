const API_BASE = import.meta.env.VITE_API_URL || '/api';
let credential: string | null = null;

/** Keep the operator-issued credential only in this page's memory. */
export function setCredential(value: string): void {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error('Enter the 64-character credential issued by the demo operator.');
  const url = new URL(API_BASE, window.location.href);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) {
    throw new Error('Credentials require HTTPS or a loopback development server.');
  }
  credential = value;
}

export function clearCredential(): void { credential = null; }

export interface EnrollRequest {
  user_id: string;
  face_embedding?: number[];  // 1024-dim face embedding from Human library
}

export interface EnrollTimings {
  feature_generation_ms: number;
  poseidon_hash_ms: number;
  pedersen_commit_ms: number;
  total_ms: number;
}

export interface EnrollResponse {
  session_id: string;
  commitment_hex: string;
  quality_score: number;
  timings: EnrollTimings;
}

export interface ChallengeRequest {
  session_id: string;
  client_commitment?: string;  // hex-encoded SHA-256 of client nonce
}

export interface ChallengeResponse {
  challenge_id: string;
  nonce_hex: string;
  commitment_hex: string;
}

export interface ProveRequest {
  challenge_id: string;
  noise_level?: number;
  face_embedding?: number[];  // 1024-dim face embedding from live scan
  c_nonce?: string;           // hex-encoded client nonce for spatial flash verification
  flash_frames?: string[];    // baseline + 3 round JPEG data URLs
  eye_crops?: string[][];     // [baseline, r0, r1, r2] × [left, right] PNG data URLs
  rolling_shutter?: RollingShutterObservation;
}

export interface RollingShutterObservation {
  observed_symbols: number[]; // exactly 12 values in 0..=3
  initial_phase: number;      // 0..=11
  frame_tick_deltas: [number, number];
}

export interface RollingShutterObservationReport {
  mode: 'observe-only';
  enabled_in_circuit: false;
  capture_validated: false;
  relation_matched: boolean;
  phase_matched: boolean;
  timing_matched: boolean;
  symbol_mismatches: number;
  maximum_symbol_errors: number;
}

export interface PhotometricRound {
  round: number;
  responding_patches: number;   // of a 4×4 grid
  convexity_score: number;      // Q15 over [0, 2]
}

export interface FingerprintFields {
  hex: string;
  order: number;
  mid_ratio: number;
  min_ratio: number;
  magnitude: number;
}

export interface LivenessParameters {
  color_threshold: number;
  spatial_threshold: number;
  min_magnitude: number;
  magnitude_scale: number;
  min_coverage: number;
  min_convexity: number;
  corneal_enabled: boolean;
  glint_ratio_tolerance: number;
  glint_magnitude_floor: number;
}

export interface LivenessFailingCheck {
  check: string;
  round: number;
}

export interface CornealRound {
  round: number;
  left_glint: FingerprintFields;
  right_glint: FingerprintFields;
  expected_glint: FingerprintFields;
  enabled: boolean;
  agrees?: [boolean, boolean];
}

export interface ProveTimings {
  feature_scan_ms: number;
  distance_calc_ms: number;
  proof_generation_ms: number;
  total_ms: number;
}

export interface RegionMatchScore {
  round: number;
  tl_score: number;
  tr_score: number;
  bl_score: number;
  br_score: number;
  spatial_diff_score: number;
}

export interface ProveResponse {
  proof_hex: string;
  public_inputs_hex: string[];
  distance: number;
  quality_score: number;
  liveness_passed: boolean | null;
  color_challenge_passed?: boolean;
  /** Whether liveness was proven inside the ZK proof (not just plaintext). */
  liveness_proved_in_zk?: boolean;
  region_match_scores?: RegionMatchScore[];
  spatial_differentiation_score?: number;
  photometric_rounds?: PhotometricRound[];
  corneal_rounds?: CornealRound[];
  liveness_parameters?: LivenessParameters;
  liveness_failing_check?: LivenessFailingCheck;
  rolling_shutter_observation?: RollingShutterObservationReport;
  timings: ProveTimings;
  what_was_proven: string[];
  what_stayed_private: string[];
}

export interface VerifyRequest {
  proof_hex: string;
  public_inputs_hex: string[];
  challenge_id?: string;
  session_id?: string;
}

export interface VerificationDetails {
  commitment_valid: boolean;
  distance_check_passed: boolean;
  temporal_check_passed?: boolean | null;
  quality_check_passed: boolean;
  liveness_check_passed: boolean | null;
  /** Whether liveness was verified inside the ZK proof (from public inputs). */
  liveness_proved_in_zk?: boolean;
  color_challenge_passed?: boolean;
  region_match_scores?: RegionMatchScore[];
  spatial_differentiation_score?: number;
}

export interface LivenessRequest {
  challenge_id: string;
  session_id?: string;
  baseline_image: string;
  flash_image: string;
}

export interface LivenessSignals {
  reflectance_variance: number;
  reflectance_gradient: number;
  highlight_softness: number;
  channel_consistency: number;
}

export interface LivenessResponse {
  passed: boolean;
  signals: LivenessSignals;
  timing_ms: number;
}

export interface VerifyResponse {
  valid: boolean;
  verification_time_ms: number;
  details: VerificationDetails;
}

export interface HealthResponse {
  status: string;
  version: string;
}

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

async function request<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  if (endpoint !== '/health' && !credential) throw new Error('A demo operator credential is required.');
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    redirect: 'error',
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
      ...(endpoint !== '/health' ? { Authorization: `Bearer ${credential}` } : {}),
    },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new ApiError(response.status, error.error || 'Request failed');
  }

  return response.json();
}

export const api = {
  health(): Promise<HealthResponse> {
    return request('/health');
  },

  enroll(data: EnrollRequest): Promise<EnrollResponse> {
    return request('/enroll', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  getChallenge(data: ChallengeRequest): Promise<ChallengeResponse> {
    return request('/auth/challenge', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  prove(data: ProveRequest): Promise<ProveResponse> {
    return request('/auth/prove', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  checkLiveness(data: LivenessRequest): Promise<LivenessResponse> {
    return request('/liveness/screen-flash', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  verify(data: VerifyRequest): Promise<VerifyResponse> {
    return request('/verify', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },


};
