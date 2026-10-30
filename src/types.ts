import type { HarnessConfig } from "./config";

/** Subset of the Workers Rate Limiting binding we rely on. */
export interface RateLimiterBinding {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

/** Subset of the Analytics Engine binding we rely on. */
export interface AnalyticsEngineBinding {
  writeDataPoint(event: {
    indexes?: string[];
    blobs?: string[];
    doubles?: number[];
  }): void;
}

export interface Env {
  ORIGIN_URL?: string;
  HARNESS_CONFIG?: string;
  API_TOKEN?: string;
  RATE_LIMITER?: RateLimiterBinding;
  AUDIT?: AnalyticsEngineBinding;
  /** Optional service binding to the origin Worker. Takes precedence over ORIGIN_URL. */
  ORIGIN?: Fetcher;
}

/** The parts of `request.cf` the harness reads. Injected so tests can fake them. */
export interface CfInfo {
  country?: string;
  asn?: number;
  colo?: string;
  botManagement?: {
    score?: number;
    verifiedBot?: boolean;
    staticResource?: boolean;
  };
}

export type Decision = "allow" | "block" | "challenge";

export interface AuditEvent {
  ts: string;
  rayId: string;
  ip: string;
  country?: string;
  method: string;
  path: string;
  control: string;
  decision: Decision;
  reason?: string;
  status?: number;
  durationMs?: number;
}

export interface HarnessContext {
  request: Request;
  url: URL;
  env: Env;
  config: HarnessConfig;
  cf: CfInfo;
  clientIp: string;
  rayId: string;
  startedAt: number;
  /** Controls record what they decided here; the logger emits them once. */
  trail: Array<{ control: string; decision: Decision; reason?: string }>;
  /** Response mutators applied after the origin responds (headers, CORS). */
  responseHooks: Array<(res: Response) => Response>;
  /** Override for outbound fetches (JWKS, origin) so tests can stub them. */
  fetcher: typeof fetch;
  /** Scheduler for background work (ctx.waitUntil in production). */
  waitUntil: (p: Promise<unknown>) => void;
}

export type Next = () => Promise<Response>;
export type Middleware = (ctx: HarnessContext, next: Next) => Promise<Response>;
