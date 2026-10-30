export interface HarnessConfig {
  allowedMethods: string[];
  maxBodyBytes: number;
  ipDeny: string[];
  ipAllow: string[];
  blockedCountries: string[];
  allowedCountries: string[];
  bot: {
    /** Block when Bot Management score is below this. 0 disables the check. */
    scoreThreshold: number;
    allowVerifiedBots: boolean;
  };
  rateLimit: {
    enabled: boolean;
    requests: number;
    windowSeconds: number;
    keyBy: "ip" | "ip+path";
    /** Paths exempt from rate limiting (prefix match). */
    exemptPaths: string[];
  };
  waf: {
    enabled: boolean;
    blockSqli: boolean;
    blockXss: boolean;
    blockTraversal: boolean;
    /** Path prefixes that are always blocked (probes for admin panels, dotfiles, etc). */
    blockedPaths: string[];
    /** Inspect request bodies up to this size for text content types. */
    inspectBodyBytes: number;
  };
  access: {
    enabled: boolean;
    /** e.g. "myteam.cloudflareaccess.com" */
    teamDomain: string;
    /** Application Audience (AUD) tag from the Access application. */
    aud: string;
    /** Path prefixes that require a valid Access JWT. */
    paths: string[];
  };
  bearer: {
    enabled: boolean;
    /** Path prefixes that require `Authorization: Bearer <API_TOKEN>`. */
    paths: string[];
  };
  cors: {
    enabled: boolean;
    origins: string[];
    methods: string[];
    headers: string[];
    maxAge: number;
    credentials: boolean;
  };
  headers: {
    hsts: string;
    csp: string;
    frameOptions: string;
    referrerPolicy: string;
    permissionsPolicy: string;
    /** Response headers to strip before returning to the client. */
    strip: string[];
  };
  /** Response body format for blocks. */
  blockFormat: "json" | "text";
}

export const DEFAULT_CONFIG: HarnessConfig = {
  allowedMethods: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  maxBodyBytes: 1024 * 1024,
  ipDeny: [],
  ipAllow: [],
  blockedCountries: [],
  allowedCountries: [],
  bot: { scoreThreshold: 0, allowVerifiedBots: true },
  rateLimit: {
    enabled: true,
    requests: 100,
    windowSeconds: 60,
    keyBy: "ip",
    exemptPaths: [],
  },
  waf: {
    enabled: true,
    blockSqli: true,
    blockXss: true,
    blockTraversal: true,
    blockedPaths: ["/.env", "/.git", "/wp-admin", "/wp-login.php", "/phpmyadmin"],
    inspectBodyBytes: 64 * 1024,
  },
  access: { enabled: false, teamDomain: "", aud: "", paths: ["/admin"] },
  bearer: { enabled: false, paths: ["/api"] },
  cors: {
    enabled: false,
    origins: [],
    methods: ["GET", "POST", "OPTIONS"],
    headers: ["Content-Type", "Authorization"],
    maxAge: 600,
    credentials: false,
  },
  headers: {
    hsts: "max-age=31536000; includeSubDomains; preload",
    csp: "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    frameOptions: "DENY",
    referrerPolicy: "strict-origin-when-cross-origin",
    permissionsPolicy: "camera=(), microphone=(), geolocation=()",
    strip: ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"],
  },
  blockFormat: "json",
};

export type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends unknown[] ? T[K] : T[K] extends object ? DeepPartial<T[K]> : T[K];
};

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function merge<T extends object>(base: T, override: DeepPartial<T> | undefined): T {
  if (!override) return base;
  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  for (const [key, value] of Object.entries(override)) {
    if (value === undefined) continue;
    const current = (base as Record<string, unknown>)[key];
    if (isPlainObject(current) && isPlainObject(value)) {
      out[key] = merge(current, value);
    } else {
      out[key] = value;
    }
  }
  return out as T;
}

/**
 * Build the effective config from a JSON string (the HARNESS_CONFIG var) or a
 * partial object. Invalid JSON falls back to defaults rather than failing open
 * with no policy at all.
 */
export function loadConfig(raw: string | DeepPartial<HarnessConfig> | undefined): HarnessConfig {
  let parsed: DeepPartial<HarnessConfig> | undefined;
  if (typeof raw === "string") {
    if (!raw.trim()) return DEFAULT_CONFIG;
    try {
      parsed = JSON.parse(raw) as DeepPartial<HarnessConfig>;
    } catch (err) {
      console.error("HARNESS_CONFIG is not valid JSON; using defaults", String(err));
      return DEFAULT_CONFIG;
    }
  } else {
    parsed = raw;
  }
  const cfg = merge(DEFAULT_CONFIG, parsed);
  cfg.allowedMethods = cfg.allowedMethods.map((m) => m.toUpperCase());
  cfg.blockedCountries = cfg.blockedCountries.map((c) => c.toUpperCase());
  cfg.allowedCountries = cfg.allowedCountries.map((c) => c.toUpperCase());
  return cfg;
}
