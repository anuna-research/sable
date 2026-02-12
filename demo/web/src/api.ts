const API_BASE = '/api';

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
  feature_preview: number[];
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
}

export interface ProveTimings {
  feature_scan_ms: number;
  distance_calc_ms: number;
  proof_generation_ms: number;
  total_ms: number;
}

export interface RegionMatchScore {
  round: number;
  upper_score: number;
  lower_score: number;
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
  timings: ProveTimings;
  what_was_proven: string[];
  what_stayed_private: string[];
}

export interface VerifyRequest {
  proof_hex: string;
  public_inputs_hex: string[];
  session_id?: string;
}

export interface VerificationDetails {
  commitment_valid: boolean;
  distance_check_passed: boolean;
  temporal_check_passed: boolean;
  quality_check_passed: boolean;
  liveness_check_passed: boolean | null;
  /** Whether liveness was verified inside the ZK proof (from public inputs). */
  liveness_proved_in_zk?: boolean;
  color_challenge_passed?: boolean;
  region_match_scores?: RegionMatchScore[];
  spatial_differentiation_score?: number;
}

export interface LivenessRequest {
  session_id: string;
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
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
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
