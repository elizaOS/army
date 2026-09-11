import {
  CloudflareTracePersistence,
  type D1Database,
  type R2Bucket,
} from "../../../backend/trace/cloudflare-persistence";
import { handleTraceApi } from "../../../backend/trace/handler";
import {
  PRIVATE_INTAKE_ATTESTATION_PATH,
  parsePrivateIntakeAttestation,
} from "../../../src/lib/private-intake-attestation";

type Env = {
  SLOP_DB: D1Database;
  PRIVATE_TRACES: R2Bucket;
  TRACE_AUTH_SECRET: string;
  OPERATOR_GITHUB_IDS?: string;
  SLOP_IDENTITY: { fetch(request: Request): Promise<Response> };
  ASSETS?: { fetch(request: Request): Promise<Response> };
};

type PagesContext = {
  request: Request;
  env: Env;
};

export const MAX_IDENTITY_RESPONSE_BYTES = 16 * 1024;
export const MAX_PRIVATE_INTAKE_RESPONSE_BYTES = 16 * 1024;
const PRIVATE_INTAKE_CACHE_KEY = new Request(
  "https://private-intake-cache.invalid/status-v1",
);
const PRIVATE_INTAKE_STATUS_URL =
  "https://api.github.com/repos/SlopDotCash/slopdotcash/private-vulnerability-reporting";

type EdgeCache = {
  match(request: Request): Promise<Response | undefined>;
  put(request: Request, response: Response): Promise<void>;
};

type PrivateIntakeStatus =
  | { status: "verified"; enabled: boolean; verifiedAt: string }
  | { status: "rate_limited"; resetAt: string }
  | { status: "unavailable" };

async function readBoundedJson(
  response: Response,
  maximumBytes: number,
): Promise<unknown> {
  const declared = response.headers.get("content-length");
  if (
    declared !== null &&
    (!/^\d+$/u.test(declared) || Number(declared) > maximumBytes)
  ) {
    throw new Error("Response exceeds the allowed size");
  }
  if (response.body === null) throw new Error("Response is empty");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel("response too large");
        throw new Error("Response exceeds the allowed size");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

function parsedPrivateIntakeStatus(value: unknown): PrivateIntakeStatus | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const record = value as Record<string, unknown>;
  if (
    record.status === "verified" &&
    typeof record.enabled === "boolean" &&
    typeof record.verifiedAt === "string" &&
    !Number.isNaN(Date.parse(record.verifiedAt)) &&
    Object.keys(record).length === 3
  ) {
    return {
      status: "verified",
      enabled: record.enabled,
      verifiedAt: record.verifiedAt,
    };
  }
  if (
    record.status === "rate_limited" &&
    typeof record.resetAt === "string" &&
    !Number.isNaN(Date.parse(record.resetAt)) &&
    Object.keys(record).length === 2
  ) {
    return { status: "rate_limited", resetAt: record.resetAt };
  }
  return null;
}

async function privateIntakeStatus(
  assets: Env["ASSETS"],
  requestUrl: string,
  cache: EdgeCache | undefined,
  fetchImpl: typeof fetch,
  now: () => Date,
): Promise<PrivateIntakeStatus> {
  // The reviewed Pages bundle carries a build-time attestation that GitHub
  // private vulnerability reporting was enabled for the released revision. A
  // fresh attestation answers without any external request. A missing,
  // malformed or expired attestation is not itself evidence that intake is
  // disabled, so it falls through to the bounded live GitHub check below
  // instead of failing closed on the age of a deploy. Only GitHub's own
  // answer, or the inability to obtain one, decides availability.
  if (assets !== undefined) {
    try {
      const url = new URL(PRIVATE_INTAKE_ATTESTATION_PATH, requestUrl);
      const response = await assets.fetch(
        new Request(url, {
          method: "GET",
          headers: { accept: "application/json" },
        }),
      );
      if (response.ok) {
        const value = await readBoundedJson(
          response,
          MAX_PRIVATE_INTAKE_RESPONSE_BYTES,
        );
        const attestation = parsePrivateIntakeAttestation(value, now());
        if (attestation !== null) {
          return {
            status: "verified",
            enabled: true,
            verifiedAt: attestation.verifiedAt,
          };
        }
      }
    } catch {
      // The bundle attestation is an optimization, not the authority.
      // Continue to the bounded live GitHub check.
    }
  }
  if (cache !== undefined) {
    try {
      const cached = await cache.match(PRIVATE_INTAKE_CACHE_KEY);
      if (cached !== undefined) {
        const status = parsedPrivateIntakeStatus(
          await readBoundedJson(cached, MAX_PRIVATE_INTAKE_RESPONSE_BYTES),
        );
        if (status !== null) return status;
      }
    } catch {
      // The cache is an availability optimization, not the authority. Continue
      // to the bounded GitHub check when the runtime cache is unavailable.
    }
  }
  let response: Response;
  try {
    response = await fetchImpl(PRIVATE_INTAKE_STATUS_URL, {
      method: "GET",
      // Cloudflare Workers supports manual redirect handling, not the browser
      // `error` mode. Every redirect is still rejected below because a 3xx
      // response is not successful and its body is never followed or parsed.
      redirect: "manual",
      headers: {
        Accept: "application/vnd.github+json",
        "User-Agent": "slop-private-intake-verifier",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      signal: AbortSignal.timeout(30_000),
    });
  } catch {
    return { status: "unavailable" };
  }
  let status: PrivateIntakeStatus;
  if (
    (response.status === 403 || response.status === 429) &&
    response.headers.get("x-ratelimit-remaining") === "0"
  ) {
    const reset = response.headers.get("x-ratelimit-reset");
    if (reset === null || !/^\d{9,12}$/u.test(reset)) {
      return { status: "unavailable" };
    }
    status = {
      status: "rate_limited",
      resetAt: new Date(Number(reset) * 1000).toISOString(),
    };
  } else if (response.ok) {
    let value: unknown;
    try {
      value = await readBoundedJson(
        response,
        MAX_PRIVATE_INTAKE_RESPONSE_BYTES,
      );
    } catch {
      return { status: "unavailable" };
    }
    if (
      typeof value !== "object" ||
      value === null ||
      Array.isArray(value) ||
      Object.keys(value).length !== 1 ||
      typeof (value as { enabled?: unknown }).enabled !== "boolean"
    ) {
      return { status: "unavailable" };
    }
    status = {
      status: "verified",
      enabled: (value as { enabled: boolean }).enabled,
      verifiedAt: now().toISOString(),
    };
  } else {
    return { status: "unavailable" };
  }
  if (cache !== undefined) {
    try {
      await cache.put(
        PRIVATE_INTAKE_CACHE_KEY,
        new Response(JSON.stringify(status), {
          headers: {
            "cache-control": "public, max-age=300",
            "content-type": "application/json; charset=utf-8",
          },
        }),
      );
    } catch {
      // A verified GitHub response remains authoritative even when the edge
      // runtime cannot persist the optional cache entry.
    }
  }
  return status;
}

async function readIdentityResponse(response: Response): Promise<unknown> {
  return readBoundedJson(response, MAX_IDENTITY_RESPONSE_BYTES);
}

async function verifyIdentityAssertion(
  identityService: Env["SLOP_IDENTITY"],
  assertion: string,
): Promise<{ githubId: string; githubLogin: string } | null> {
  const response = await identityService.fetch(
    new Request("https://identity.internal/v1/assertions/consume", {
      method: "POST",
      headers: {
        authorization: `Bearer ${assertion}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ audience: "private-trace-api" }),
    }),
  );
  if (!response.ok) return null;
  const body = await readIdentityResponse(response);
  if (typeof body !== "object" || body === null) return null;
  const id = (body as { githubActorId?: unknown }).githubActorId;
  const login = (body as { githubLogin?: unknown }).githubLogin;
  if (
    typeof id !== "string" ||
    !/^\d+$/u.test(id) ||
    typeof login !== "string" ||
    !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/u.test(login)
  ) {
    return null;
  }
  return { githubId: id, githubLogin: login };
}

export async function onRequest(context: PagesContext): Promise<Response> {
  const cache = (
    globalThis as typeof globalThis & { caches?: { default?: EdgeCache } }
  ).caches?.default;
  return handleTraceApi(context.request, {
    persistence: new CloudflareTracePersistence(
      context.env.SLOP_DB,
      context.env.PRIVATE_TRACES,
    ),
    authSecret: context.env.TRACE_AUTH_SECRET,
    operatorGithubIds: new Set(
      (context.env.OPERATOR_GITHUB_IDS ?? "")
        .split(",")
        .map((value) => value.trim())
        .filter((value) => /^\d+$/u.test(value)),
    ),
    now: () => new Date(),
    randomId: () => crypto.randomUUID(),
    verifyIdentityAssertion: (assertion) =>
      verifyIdentityAssertion(context.env.SLOP_IDENTITY, assertion),
    privateIntakeStatus: () =>
      privateIntakeStatus(
        context.env.ASSETS,
        context.request.url,
        cache,
        globalThis.fetch,
        () => new Date(),
      ),
  });
}
