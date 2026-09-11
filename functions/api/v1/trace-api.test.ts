import { describe, expect, it, vi } from "vitest";
import { signApiToken, verifyApiToken } from "../../../backend/trace/auth";
import type {
  AttachTraceInput,
  AuditInput,
  CreateGrantInput,
  CreateRunInput,
  PersistenceResult,
  RunProgressEvent,
  TraceObject,
  TracePersistence,
  TraceRun,
  TraceUploadIntent,
  WalletClaim,
} from "../../../backend/trace/contracts";
import {
  handleTraceApi,
  TRACE_API_CONTRACT_VERSION,
  type TraceApiDependencies,
} from "../../../backend/trace/handler";
import { readJsonObject, sha256Hex } from "../../../backend/trace/validation";
import {
  MAX_IDENTITY_RESPONSE_BYTES,
  onRequest as onPagesRequest,
} from "./[[path]]";

const SECRET = "A".repeat(43);
const NOW = new Date("2026-08-15T12:00:00.000Z");

class MemoryPersistence implements TracePersistence {
  readonly runs = new Map<string, TraceRun>();
  readonly createKeys = new Map<
    string,
    { fingerprint: string; runId: string }
  >();
  readonly objects = new Map<string, TraceObject>();
  readonly bytes = new Map<string, Uint8Array>();
  readonly uploads = new Map<string, { runId: string; sha256: string }>();
  readonly intents = new Map<string, TraceUploadIntent>();
  readonly intentKeys = new Map<string, string>();
  readonly events = new Map<string, RunProgressEvent>();
  readonly eventKeys = new Map<string, string>();
  readonly grants = new Map<string, CreateGrantInput & { consumed: boolean }>();
  readonly audits: AuditInput[] = [];
  readonly claims = new Map<string, WalletClaim>();
  failNextPut = false;
  failNextAudit = false;

  async createRun(input: CreateRunInput): Promise<PersistenceResult<TraceRun>> {
    const key = `${input.githubId}:${input.idempotencyKey}`;
    const fingerprint = JSON.stringify({
      ...input,
      id: undefined,
      createdAt: undefined,
    });
    const prior = this.createKeys.get(key);
    if (prior !== undefined) {
      const run = this.runs.get(prior.runId);
      if (run === undefined || prior.fingerprint !== fingerprint)
        return { status: "conflict" };
      return { status: "existing", value: run };
    }
    const run: TraceRun = {
      id: input.id,
      clientRunId: input.clientRunId,
      githubId: input.githubId,
      githubLogin: input.githubLogin,
      projectId: input.projectId,
      repository: input.repository,
      projectPolicyRevision: input.projectPolicyRevision,
      provider: input.provider,
      model: input.model,
      client: input.client,
      clientVersion: input.clientVersion,
      state: "awaiting_trace",
      traceSha256: null,
      createdAt: input.createdAt,
      finalizedAt: null,
    };
    this.runs.set(run.id, run);
    this.createKeys.set(key, { fingerprint, runId: run.id });
    return { status: "created", value: run };
  }

  async getRun(runId: string): Promise<TraceRun | null> {
    return this.runs.get(runId) ?? null;
  }

  async attachTrace(
    input: AttachTraceInput,
  ): Promise<PersistenceResult<TraceRun>> {
    const key = `${input.githubId}:${input.idempotencyKey}`;
    const prior = this.uploads.get(key);
    if (prior !== undefined) {
      const run = this.runs.get(prior.runId);
      if (
        run === undefined ||
        prior.runId !== input.runId ||
        prior.sha256 !== input.object.sha256 ||
        run.traceSha256 !== input.object.sha256
      ) {
        return { status: "conflict" };
      }
      return { status: "conflict" };
    }
    const run = this.runs.get(input.runId);
    const intent = this.intents.get(input.idempotencyKey);
    if (
      run === undefined ||
      run.githubId !== input.githubId ||
      run.state === "finalized" ||
      (run.traceSha256 !== null && run.traceSha256 !== input.object.sha256) ||
      intent === undefined ||
      intent.consumedAt !== null ||
      intent.expiresAt <= input.intentConsumedAt ||
      intent.runId !== input.runId ||
      intent.githubId !== input.githubId ||
      intent.sha256 !== input.object.sha256 ||
      intent.sizeBytes !== input.object.sizeBytes ||
      intent.contentType !== input.object.contentType
    ) {
      return { status: "conflict" };
    }
    const updated = {
      ...run,
      state: "trace_uploaded",
      traceSha256: input.object.sha256,
    } as const;
    this.runs.set(run.id, updated);
    this.intents.set(input.idempotencyKey, {
      ...intent,
      consumedAt: input.intentConsumedAt,
    });
    this.objects.set(input.object.sha256, input.object);
    this.uploads.set(key, { runId: run.id, sha256: input.object.sha256 });
    return { status: "created", value: updated };
  }

  async finalizeRun(
    runId: string,
    githubId: string,
    finalizedAt: string,
  ): Promise<TraceRun | null> {
    const run = this.runs.get(runId);
    if (
      run === undefined ||
      run.githubId !== githubId ||
      run.traceSha256 === null
    )
      return null;
    const updated: TraceRun = {
      ...run,
      state: "finalized",
      finalizedAt: run.finalizedAt ?? finalizedAt,
    };
    this.runs.set(runId, updated);
    return updated;
  }

  async appendEvent(
    event: RunProgressEvent & { idempotencyKey: string },
  ): Promise<PersistenceResult<RunProgressEvent>> {
    const key = `${event.githubId}:${event.idempotencyKey}`;
    const priorId = this.eventKeys.get(key);
    if (priorId !== undefined) {
      const prior = this.events.get(priorId);
      if (
        prior === undefined ||
        prior.runId !== event.runId ||
        prior.kind !== event.kind ||
        prior.occurredAt !== event.occurredAt ||
        prior.source !== event.source ||
        prior.githubObjectId !== event.githubObjectId ||
        prior.githubUrl !== event.githubUrl ||
        prior.headSha !== event.headSha
      ) {
        return { status: "conflict" };
      }
      return { status: "existing", value: prior };
    }
    this.events.set(event.id, event);
    this.eventKeys.set(key, event.id);
    return { status: "created", value: event };
  }

  async getTraceObject(sha256: string): Promise<TraceObject | null> {
    return this.objects.get(sha256) ?? null;
  }

  async createUploadIntent(
    intent: TraceUploadIntent,
  ): Promise<PersistenceResult<TraceUploadIntent>> {
    const key = `${intent.githubId}:${intent.idempotencyKey}`;
    const priorHash = this.intentKeys.get(key);
    if (priorHash !== undefined) {
      const prior = this.intents.get(priorHash);
      if (
        prior === undefined ||
        prior.runId !== intent.runId ||
        prior.sha256 !== intent.sha256 ||
        prior.sizeBytes !== intent.sizeBytes ||
        prior.contentType !== intent.contentType
      ) {
        return { status: "conflict" };
      }
      if (prior.consumedAt === null && prior.expiresAt <= intent.createdAt) {
        const renewed = {
          ...prior,
          expiresAt: intent.expiresAt,
        };
        this.intents.set(priorHash, renewed);
        return { status: "existing", value: renewed };
      }
      return { status: "existing", value: prior };
    }
    this.intents.set(intent.tokenHash, { ...intent });
    this.intentKeys.set(key, intent.tokenHash);
    return { status: "created", value: intent };
  }

  async getUploadIntent(
    tokenHash: string,
    now: string,
  ): Promise<TraceUploadIntent | null> {
    const intent = this.intents.get(tokenHash);
    if (
      intent === undefined ||
      intent.consumedAt !== null ||
      intent.expiresAt <= now
    )
      return null;
    return { ...intent };
  }

  async putTraceBytes(object: TraceObject, bytes: Uint8Array): Promise<void> {
    if (this.failNextPut) {
      this.failNextPut = false;
      throw new Error("transient R2 failure");
    }
    const existing = this.bytes.get(object.sha256);
    if (existing !== undefined) {
      expect(existing).toEqual(bytes);
      return;
    }
    this.bytes.set(object.sha256, bytes.slice());
  }

  async createReadGrant(
    input: CreateGrantInput,
    audit: AuditInput,
  ): Promise<void> {
    if (this.failNextAudit) {
      this.failNextAudit = false;
      throw new Error("injected audit failure");
    }
    this.grants.set(input.tokenHash, { ...input, consumed: false });
    this.audits.push(audit);
  }

  async consumeReadGrant(
    tokenHash: string,
    traceSha256: string,
    operatorGithubId: string,
    now: string,
    audit: AuditInput,
  ): Promise<boolean> {
    const grant = this.grants.get(tokenHash);
    if (
      grant === undefined ||
      grant.consumed ||
      grant.traceSha256 !== traceSha256 ||
      grant.operatorGithubId !== operatorGithubId ||
      grant.expiresAt <= now
    ) {
      return false;
    }
    if (this.failNextAudit) {
      this.failNextAudit = false;
      throw new Error("injected audit failure");
    }
    grant.consumed = true;
    this.audits.push(audit);
    return true;
  }

  async readTraceBytes(object: TraceObject): Promise<Uint8Array | null> {
    return this.bytes.get(object.sha256) ?? null;
  }

  async writeAudit(input: AuditInput): Promise<void> {
    if (this.failNextAudit) {
      this.failNextAudit = false;
      throw new Error("injected audit failure");
    }
    this.audits.push(input);
  }

  async createWalletClaim(
    claim: WalletClaim,
    audit: AuditInput,
  ): Promise<PersistenceResult<WalletClaim>> {
    const existing = [...this.claims.values()].find(
      (item) => item.recordSha256 === claim.recordSha256,
    );
    if (existing !== undefined) return { status: "existing", value: existing };
    const actorClaims = [...this.claims.values()].filter(
      (item) => item.githubId === claim.githubId,
    );
    if (
      (claim.supersedesClaimId === null &&
        actorClaims.some((item) => item.supersedesClaimId === null)) ||
      (claim.supersedesClaimId !== null &&
        actorClaims.some(
          (item) => item.supersedesClaimId === claim.supersedesClaimId,
        ))
    ) {
      return { status: "conflict" };
    }
    if (this.failNextAudit) {
      this.failNextAudit = false;
      throw new Error("injected audit failure");
    }
    this.claims.set(claim.id, claim);
    this.audits.push(audit);
    return { status: "created", value: claim };
  }

  async getWalletClaim(claimId: string): Promise<WalletClaim | null> {
    return this.claims.get(claimId) ?? null;
  }

  async getCurrentWalletClaim(githubId: string): Promise<WalletClaim | null> {
    const claims = [...this.claims.values()].filter(
      (claim) => claim.githubId === githubId,
    );
    return (
      claims.find(
        (claim) =>
          !claims.some((candidate) => candidate.supersedesClaimId === claim.id),
      ) ?? null
    );
  }
}

let idCounter = 0;
function dependencies(
  persistence = new MemoryPersistence(),
): TraceApiDependencies {
  return {
    persistence,
    authSecret: SECRET,
    operatorGithubIds: new Set(["99"]),
    now: () => new Date(NOW),
    randomId: () => `identifier_${String(++idCounter).padStart(8, "0")}`,
    verifyIdentityAssertion: async (assertion) =>
      assertion === "valid_slop_identity_assertion_value"
        ? { githubId: "42", githubLogin: "octocat" }
        : null,
    privateIntakeStatus: async () => ({
      status: "verified",
      enabled: true,
      verifiedAt: NOW.toISOString(),
    }),
  };
}

async function token(
  githubId: string,
  githubLogin: string,
  roles: Array<"contributor" | "project_owner" | "operator">,
): Promise<string> {
  const now = Math.floor(NOW.getTime() / 1000);
  return signApiToken(
    {
      iss: "slop.cash",
      aud: "private-trace-api",
      sub: `github:${githubId}`,
      githubId,
      githubLogin,
      roles,
      iat: now,
      exp: now + (roles.includes("operator") ? 240 : 600),
      jti: `token_identifier_${githubId}`,
    },
    SECRET,
  );
}

function request(
  path: string,
  method: string,
  bearer: string,
  body?: BodyInit,
  headers: Record<string, string> = {},
): Request {
  return new Request(`https://api.slop.cash/api/v1/${path}`, {
    method,
    body,
    headers: { authorization: `Bearer ${bearer}`, ...headers },
  });
}

async function createRun(
  deps: TraceApiDependencies,
  bearer: string,
  key = "create_run_key_0001",
  identity = {
    provider: "openai",
    model: "gpt-5",
    client: "codex",
    clientVersion: "1.0.0",
  },
) {
  return handleTraceApi(
    request(
      "runs",
      "POST",
      bearer,
      JSON.stringify({
        clientRunId: "run_01HZXTESTCLIENTRUN",
        projectId: "eliza",
        repository: "elizaOS/eliza",
        projectPolicyRevision: "a".repeat(40),
        ...identity,
      }),
      { "content-type": "application/json", "idempotency-key": key },
    ),
    deps,
  );
}

async function uploadTrace(
  deps: TraceApiDependencies,
  bearer: string,
  serverRunId: string,
  bytes: Uint8Array,
  key: string,
  contentType = "text/plain",
) {
  const digest = await sha256Hex(bytes);
  const intentResponse = await handleTraceApi(
    request(
      `runs/${serverRunId}/trace-intents`,
      "POST",
      bearer,
      JSON.stringify({
        sha256: digest,
        sizeBytes: bytes.byteLength,
        contentType,
      }),
      { "content-type": "application/json", "idempotency-key": key },
    ),
    deps,
  );
  const intent = (await intentResponse.json()) as { uploadUrl: string };
  const uploaded = await handleTraceApi(
    new Request(intent.uploadUrl, {
      method: "PUT",
      body: bytes.slice().buffer,
      headers: { "content-type": contentType, digest: `sha-256=${digest}` },
    }),
    deps,
  );
  return { digest, intentResponse, uploaded };
}

describe("private trace API", () => {
  it("renews an expired unconsumed upload intent on an idempotent retry", async () => {
    const store = new MemoryPersistence();
    let current = new Date(NOW);
    const deps = { ...dependencies(store), now: () => new Date(current) };
    const bearer = await token("42", "octocat", ["contributor"]);
    const runResponse = await createRun(deps, bearer);
    const { serverRunId } = (await runResponse.json()) as {
      serverRunId: string;
    };
    const bytes = new TextEncoder().encode("recoverable trace");
    const digest = await sha256Hex(bytes);
    const intentRequest = () =>
      request(
        `runs/${serverRunId}/trace-intents`,
        "POST",
        bearer,
        JSON.stringify({
          sha256: digest,
          sizeBytes: bytes.byteLength,
          contentType: "text/plain",
        }),
        {
          "content-type": "application/json",
          "idempotency-key": "expired_intent_retry_key_0001",
        },
      );
    const first = await handleTraceApi(intentRequest(), deps);
    const firstIntent = (await first.json()) as {
      expiresAt: string;
      uploadUrl: string;
    };

    current = new Date(NOW.getTime() + 6 * 60 * 1000);
    const retried = await handleTraceApi(intentRequest(), deps);
    const renewedIntent = (await retried.json()) as {
      expiresAt: string;
      uploadUrl: string;
    };

    expect(retried.status).toBe(200);
    expect(renewedIntent.uploadUrl).toBe(firstIntent.uploadUrl);
    expect(renewedIntent.expiresAt).toBe(
      new Date(current.getTime() + 5 * 60 * 1000).toISOString(),
    );
    const uploaded = await handleTraceApi(
      new Request(renewedIntent.uploadUrl, {
        method: "PUT",
        body: bytes,
        headers: {
          "content-type": "text/plain",
          digest: `sha-256=${digest}`,
        },
      }),
      deps,
    );
    expect(uploaded.status).toBe(201);
  });

  it("serves the fresh private intake attestation from the exact Pages bundle", async () => {
    let requestedUrl = "";
    const verifiedAt = new Date().toISOString();
    const response = await onPagesRequest({
      request: new Request(
        "https://api.slop.cash/api/v1/private-request-intake",
      ),
      env: {
        SLOP_DB: {} as never,
        PRIVATE_TRACES: {} as never,
        TRACE_AUTH_SECRET: SECRET,
        SLOP_IDENTITY: {
          fetch: async () => new Response(null, { status: 401 }),
        },
        ASSETS: {
          fetch: async (request) => {
            requestedUrl = request.url;
            return new Response(
              JSON.stringify({
                enabled: true,
                source: "github-public-status",
                verifiedAt,
                revision: "a".repeat(40),
              }),
              { status: 200 },
            );
          },
        },
      },
    });

    expect(requestedUrl).toBe(
      "https://api.slop.cash/data/private-intake-attestation.json",
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      enabled: true,
      source: "github-public-status",
      verifiedAt,
    });
  });

  it("falls through to the live GitHub check when the bundle attestation has expired", async () => {
    const originalFetch = globalThis.fetch;
    const githubRequests: string[] = [];
    try {
      globalThis.fetch = (async (input: RequestInfo | URL) => {
        githubRequests.push(String(input));
        return new Response(JSON.stringify({ enabled: true }), {
          status: 200,
        });
      }) as unknown as typeof fetch;
      const expiredAt = new Date(
        Date.now() - 50 * 60 * 60 * 1000,
      ).toISOString();
      const response = await onPagesRequest({
        request: new Request(
          "https://api.slop.cash/api/v1/private-request-intake",
        ),
        env: {
          SLOP_DB: {} as never,
          PRIVATE_TRACES: {} as never,
          TRACE_AUTH_SECRET: SECRET,
          SLOP_IDENTITY: {
            fetch: async () => new Response(null, { status: 401 }),
          },
          ASSETS: {
            fetch: async () =>
              new Response(
                JSON.stringify({
                  enabled: true,
                  source: "github-public-status",
                  verifiedAt: expiredAt,
                  revision: "a".repeat(40),
                }),
                { status: 200 },
              ),
          },
        },
      });

      expect(githubRequests).toEqual([
        "https://api.github.com/repos/SlopDotCash/slopdotcash/private-vulnerability-reporting",
      ]);
      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toMatchObject({
        enabled: true,
        source: "github-public-status",
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("falls through to the live GitHub check when the bundle attestation is missing", async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async () =>
        new Response(JSON.stringify({ enabled: true }), {
          status: 200,
        })) as unknown as typeof fetch;
      const response = await onPagesRequest({
        request: new Request(
          "https://api.slop.cash/api/v1/private-request-intake",
        ),
        env: {
          SLOP_DB: {} as never,
          PRIVATE_TRACES: {} as never,
          TRACE_AUTH_SECRET: SECRET,
          SLOP_IDENTITY: {
            fetch: async () => new Response(null, { status: 401 }),
          },
          ASSETS: {
            fetch: async () => new Response(null, { status: 404 }),
          },
        },
      });

      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toMatchObject({
        enabled: true,
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("still fails closed when the bundle attestation has expired and GitHub cannot answer", async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async () =>
        new Response(JSON.stringify({ message: "API rate limit exceeded" }), {
          status: 403,
          headers: {
            "x-ratelimit-remaining": "0",
            "x-ratelimit-reset": "999999999999",
          },
        })) as unknown as typeof fetch;
      const expiredAt = new Date(
        Date.now() - 50 * 60 * 60 * 1000,
      ).toISOString();
      const response = await onPagesRequest({
        request: new Request(
          "https://api.slop.cash/api/v1/private-request-intake",
        ),
        env: {
          SLOP_DB: {} as never,
          PRIVATE_TRACES: {} as never,
          TRACE_AUTH_SECRET: SECRET,
          SLOP_IDENTITY: {
            fetch: async () => new Response(null, { status: 401 }),
          },
          ASSETS: {
            fetch: async () =>
              new Response(
                JSON.stringify({
                  enabled: true,
                  source: "github-public-status",
                  verifiedAt: expiredAt,
                  revision: "a".repeat(40),
                }),
                { status: 200 },
              ),
          },
        },
      });

      expect(response.status).toBe(503);
      await expect(response.json()).resolves.toEqual({
        error: "private_intake_unavailable",
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("serves a cached public private intake verification", async () => {
    const originalFetch = globalThis.fetch;
    const originalCaches = Object.getOwnPropertyDescriptor(
      globalThis,
      "caches",
    );
    const cache = new Map<string, Response>();
    const requests: Array<{ url: string; init: RequestInit }> = [];
    let cachedControl: string | null = null;
    try {
      globalThis.fetch = (async (input, init = {}) => {
        requests.push({ url: String(input), init });
        return new Response(JSON.stringify({ enabled: true }), { status: 200 });
      }) as typeof fetch;
      Object.defineProperty(globalThis, "caches", {
        configurable: true,
        value: {
          default: {
            match: async (request: Request) => cache.get(request.url)?.clone(),
            put: async (request: Request, response: Response) => {
              cachedControl = response.headers.get("cache-control");
              cache.set(request.url, response.clone());
            },
          },
        },
      });
      const context = {
        request: new Request(
          "https://api.slop.cash/api/v1/private-request-intake",
        ),
        env: {
          SLOP_DB: {} as never,
          PRIVATE_TRACES: {} as never,
          TRACE_AUTH_SECRET: SECRET,
          SLOP_IDENTITY: {
            fetch: async () => new Response(null, { status: 401 }),
          },
        },
      };
      const first = await onPagesRequest(context);
      const second = await onPagesRequest(context);

      expect(first.status).toBe(200);
      expect(second.status).toBe(200);
      await expect(first.json()).resolves.toEqual({
        enabled: true,
        source: "github-public-status",
        verifiedAt: expect.any(String),
      });
      expect(requests).toHaveLength(1);
      expect(requests[0]?.url).toBe(
        "https://api.github.com/repos/SlopDotCash/slopdotcash/private-vulnerability-reporting",
      );
      expect(requests[0]?.init).toMatchObject({
        method: "GET",
        redirect: "manual",
        headers: {
          Accept: "application/vnd.github+json",
          "User-Agent": "slop-private-intake-verifier",
          "X-GitHub-Api-Version": "2022-11-28",
        },
      });
      expect(cachedControl).toBe("public, max-age=300");
    } finally {
      globalThis.fetch = originalFetch;
      if (originalCaches === undefined) {
        Reflect.deleteProperty(globalThis, "caches");
      } else {
        Object.defineProperty(globalThis, "caches", originalCaches);
      }
    }
  });

  it("uses the public authority when the optional edge cache fails", async () => {
    const originalFetch = globalThis.fetch;
    const originalCaches = Object.getOwnPropertyDescriptor(
      globalThis,
      "caches",
    );
    let fetches = 0;
    try {
      globalThis.fetch = (async () => {
        fetches += 1;
        return new Response(JSON.stringify({ enabled: true }), { status: 200 });
      }) as unknown as typeof fetch;
      Object.defineProperty(globalThis, "caches", {
        configurable: true,
        value: {
          default: {
            match: async () => {
              throw new Error("cache unavailable");
            },
            put: async () => {
              throw new Error("cache unavailable");
            },
          },
        },
      });

      const response = await onPagesRequest({
        request: new Request(
          "https://api.slop.cash/api/v1/private-request-intake",
        ),
        env: {
          SLOP_DB: {} as never,
          PRIVATE_TRACES: {} as never,
          TRACE_AUTH_SECRET: SECRET,
          SLOP_IDENTITY: {
            fetch: async () => new Response(null, { status: 401 }),
          },
        },
      });

      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toEqual({
        enabled: true,
        source: "github-public-status",
        verifiedAt: expect.any(String),
      });
      expect(fetches).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
      if (originalCaches === undefined) {
        Reflect.deleteProperty(globalThis, "caches");
      } else {
        Object.defineProperty(globalThis, "caches", originalCaches);
      }
    }
  });

  it("reports bounded reset diagnostics for an upstream GitHub rate limit", async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async () =>
        new Response(JSON.stringify({ message: "API rate limit exceeded" }), {
          status: 403,
          headers: {
            "x-ratelimit-remaining": "0",
            "x-ratelimit-reset": "1800000000",
          },
        })) as unknown as typeof fetch;
      const response = await onPagesRequest({
        request: new Request(
          "https://api.slop.cash/api/v1/private-request-intake",
        ),
        env: {
          SLOP_DB: {} as never,
          PRIVATE_TRACES: {} as never,
          TRACE_AUTH_SECRET: SECRET,
          SLOP_IDENTITY: {
            fetch: async () => new Response(null, { status: 401 }),
          },
        },
      });

      expect(response.status).toBe(503);
      await expect(response.json()).resolves.toEqual({
        error: "private_intake_rate_limited",
        resetAt: "2027-01-15T08:00:00.000Z",
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("fails closed when GitHub returns an invalid rate-limit reset", async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async () =>
        new Response(JSON.stringify({ message: "API rate limit exceeded" }), {
          status: 403,
          headers: {
            "x-ratelimit-remaining": "0",
            "x-ratelimit-reset": "999999999999",
          },
        })) as unknown as typeof fetch;
      const response = await onPagesRequest({
        request: new Request(
          "https://api.slop.cash/api/v1/private-request-intake",
        ),
        env: {
          SLOP_DB: {} as never,
          PRIVATE_TRACES: {} as never,
          TRACE_AUTH_SECRET: SECRET,
          SLOP_IDENTITY: {
            fetch: async () => new Response(null, { status: 401 }),
          },
        },
      });

      expect(response.status).toBe(503);
      await expect(response.json()).resolves.toEqual({
        error: "private_intake_unavailable",
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("fails closed on a malformed GitHub response", async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async () =>
        new Response(JSON.stringify({ enabled: "yes" }), {
          status: 200,
        })) as unknown as typeof fetch;
      const response = await onPagesRequest({
        request: new Request(
          "https://api.slop.cash/api/v1/private-request-intake",
        ),
        env: {
          SLOP_DB: {} as never,
          PRIVATE_TRACES: {} as never,
          TRACE_AUTH_SECRET: SECRET,
          SLOP_IDENTITY: {
            fetch: async () => new Response(null, { status: 401 }),
          },
        },
      });

      expect(response.status).toBe(503);
      await expect(response.json()).resolves.toEqual({
        error: "private_intake_unavailable",
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("rejects GitHub redirects without following them", async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async (
        _input: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        expect(init?.redirect).toBe("manual");
        return new Response(null, {
          status: 302,
          headers: { location: "https://example.com/not-github" },
        });
      }) as unknown as typeof fetch;

      const response = await onPagesRequest({
        request: new Request(
          "https://api.slop.cash/api/v1/private-request-intake",
        ),
        env: {
          SLOP_DB: {} as never,
          PRIVATE_TRACES: {} as never,
          TRACE_AUTH_SECRET: SECRET,
          SLOP_IDENTITY: {
            fetch: async () => new Response(null, { status: 401 }),
          },
        },
      });

      expect(response.status).toBe(503);
      await expect(response.json()).resolves.toEqual({
        error: "private_intake_unavailable",
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("accepts arbitrary exact model identities and rejects placeholders", async () => {
    const deps = dependencies();
    const contributor = await token("42", "octocat", ["contributor"]);
    const openIdentity = await createRun(
      deps,
      contributor,
      "create_run_open_identity_0001",
      {
        provider: "x-ai/hosted+edge",
        model: "accounts/x/models/grok-4.5+reasoning",
        client: "grok-build+acp",
        clientVersion: "v1.2.3+build.7",
      },
    );
    expect(openIdentity.status).toBe(201);

    const placeholder = await createRun(
      deps,
      contributor,
      "create_run_bad_identity_0001",
      {
        provider: "provider",
        model: "model",
        client: "client",
        clientVersion: "latest",
      },
    );
    expect(placeholder.status).toBe(400);
    expect(await placeholder.json()).toMatchObject({
      error: "invalid_request",
    });
  });

  it("fails closed instead of throwing when the operator list is absent", async () => {
    const response = await onPagesRequest({
      request: new Request("https://api.slop.cash/api/v1/runs", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      }),
      env: {
        SLOP_DB: {} as never,
        PRIVATE_TRACES: {} as never,
        TRACE_AUTH_SECRET: SECRET,
        SLOP_IDENTITY: {
          fetch: async () => new Response(null, { status: 401 }),
        },
      },
    });
    expect(response.status).toBe(401);
    expect(response.headers.get("x-slop-trace-api-contract")).toBe(
      TRACE_API_CONTRACT_VERSION,
    );
    expect(await response.json()).toMatchObject({ error: "unauthorized" });
  });

  it("cancels an oversized identity response before buffering it", async () => {
    let cancelled = false;
    const identityBody = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(MAX_IDENTITY_RESPONSE_BYTES / 2 + 1));
      },
      cancel() {
        cancelled = true;
      },
    });
    const response = await onPagesRequest({
      request: new Request("https://api.slop.cash/api/v1/auth/session", {
        method: "POST",
        headers: {
          "x-slop-identity-assertion": "valid_slop_identity_assertion_value",
        },
      }),
      env: {
        SLOP_DB: {} as never,
        PRIVATE_TRACES: {} as never,
        TRACE_AUTH_SECRET: SECRET,
        SLOP_IDENTITY: {
          fetch: async () => new Response(identityBody),
        },
      },
    });
    expect(response.status).toBe(500);
    expect(cancelled).toBe(true);
    expect(identityBody.locked).toBe(false);
  });

  it("exchanges a limited identity assertion without granting operator access", async () => {
    const deps = dependencies();
    const response = await handleTraceApi(
      new Request("https://api.slop.cash/api/v1/auth/session", {
        method: "POST",
        headers: {
          "x-slop-identity-assertion": "valid_slop_identity_assertion_value",
        },
      }),
      deps,
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { token: string };
    const denied = await handleTraceApi(
      request(
        `operator/traces/${"a".repeat(64)}/grant`,
        "POST",
        body.token,
        JSON.stringify({ reason: "support investigation" }),
        { "content-type": "application/json" },
      ),
      deps,
    );
    expect(denied.status).toBe(403);
  });

  it("never upgrades a contributor assertion to operator authority", async () => {
    const deps = dependencies();
    deps.operatorGithubIds = new Set(["42"]);
    const response = await handleTraceApi(
      new Request("https://api.slop.cash/api/v1/auth/session", {
        method: "POST",
        headers: {
          "x-slop-identity-assertion": "valid_slop_identity_assertion_value",
        },
      }),
      deps,
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { token: string };
    const denied = await handleTraceApi(
      request(
        `operator/traces/${"a".repeat(64)}/grant`,
        "POST",
        body.token,
        JSON.stringify({ reason: "support investigation" }),
        { "content-type": "application/json" },
      ),
      deps,
    );
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({ error: "forbidden" });
  });

  it("rejects alternate HTTPS authorities", async () => {
    for (const authority of ["slop.cash", "api.slop.cash:444"]) {
      const response = await handleTraceApi(
        new Request(
          `https://${authority}/api/v1/wallet-claims/actors/42/current`,
        ),
        dependencies(),
      );
      expect(response.status).toBe(404);
    }
  });

  it("permits browser reads of public wallet claims only from public site origins", async () => {
    const deps = dependencies();
    const contributor = await token("42", "octocat", ["contributor"]);
    const created = await handleTraceApi(
      request(
        "wallet-claims",
        "POST",
        contributor,
        JSON.stringify({ address: "11111111111111111111111111111111" }),
        { "content-type": "application/json" },
      ),
      deps,
    );
    expect(created.status).toBe(201);
    const { claimId } = (await created.json()) as { claimId: string };

    for (const origin of [
      "https://slop.cash",
      "https://slop.tech",
      "https://eliza.army",
    ]) {
      const current = await handleTraceApi(
        new Request(
          "https://api.slop.cash/api/v1/wallet-claims/actors/42/current",
          { headers: { origin } },
        ),
        deps,
      );
      expect(current.status).toBe(200);
      expect(current.headers.get("access-control-allow-origin")).toBe(origin);
      expect(current.headers.get("vary")).toContain("Origin");

      const immutable = await handleTraceApi(
        new Request(`https://api.slop.cash/api/v1/wallet-claims/${claimId}`, {
          headers: { origin },
        }),
        deps,
      );
      expect(immutable.status).toBe(200);
      expect(immutable.headers.get("access-control-allow-origin")).toBe(origin);
    }

    const missing = await handleTraceApi(
      new Request(
        "https://api.slop.cash/api/v1/wallet-claims/actors/999/current",
        { headers: { origin: "https://slop.cash" } },
      ),
      deps,
    );
    expect(missing.status).toBe(404);
    expect(missing.headers.get("access-control-allow-origin")).toBe(
      "https://slop.cash",
    );

    const untrusted = await handleTraceApi(
      new Request(
        "https://api.slop.cash/api/v1/wallet-claims/actors/42/current",
        { headers: { origin: "https://attacker.example" } },
      ),
      deps,
    );
    expect(untrusted.status).toBe(403);
    expect(untrusted.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("rejects non-canonical body lengths and releases oversized streams", async () => {
    for (const value of ["2e0", "+2"]) {
      await expect(
        readJsonObject(
          new Request("https://api.slop.cash/api/v1/runs", {
            method: "POST",
            headers: { "content-length": value },
            body: "{}",
          }),
        ),
      ).rejects.toThrow(/Content-Length/u);
    }
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(33 * 1024));
      },
      cancel() {
        cancelled = true;
      },
    });
    await expect(
      readJsonObject(
        new Request("https://api.slop.cash/api/v1/runs", {
          method: "POST",
          body,
          duplex: "half",
        } as RequestInit & { duplex: "half" }),
      ),
    ).rejects.toThrow(/exceeds/u);
    expect(cancelled).toBe(true);
    expect(body.locked).toBe(false);

    const malformedJson = await handleTraceApi(
      request(
        "runs",
        "POST",
        await token("42", "octocat", ["contributor"]),
        "{",
        {
          "content-type": "application/json",
          "idempotency-key": "malformed_json_key_0001",
        },
      ),
      dependencies(),
    );
    expect(malformedJson.status).toBe(400);
    expect(await malformedJson.json()).toMatchObject({
      error: "invalid_request",
    });

    const tooLarge = await handleTraceApi(
      new Request("https://api.slop.cash/api/v1/runs", {
        method: "POST",
        headers: {
          authorization: `Bearer ${await token("42", "octocat", ["contributor"])}`,
          "content-length": "999999",
          "content-type": "application/json",
          "idempotency-key": "oversized_json_key_0001",
        },
        body: "{}",
      }),
      dependencies(),
    );
    expect(tooLarge.status).toBe(413);
    expect(await tooLarge.json()).toMatchObject({ error: "payload_too_large" });
  });

  it("rejects malformed secrets, extra claims, and duplicate roles", async () => {
    const now = Math.floor(NOW.getTime() / 1000);
    const claims = {
      iss: "slop.cash" as const,
      aud: "private-trace-api" as const,
      sub: "github:42" as const,
      githubId: "42",
      githubLogin: "octocat",
      roles: ["contributor" as const],
      iat: now,
      exp: now + 600,
      jti: "strict_claims_token_0001",
    };
    await expect(signApiToken(claims, "x".repeat(31))).rejects.toThrow(
      /TRACE_AUTH_SECRET/u,
    );
    await expect(signApiToken(claims, `${"x".repeat(31)}\n`)).rejects.toThrow(
      /TRACE_AUTH_SECRET/u,
    );
    await expect(signApiToken(claims, "x".repeat(129))).rejects.toThrow(
      /TRACE_AUTH_SECRET/u,
    );
    const legacySecret = "x".repeat(32);
    const legacyToken = await signApiToken(claims, legacySecret);
    await expect(
      verifyApiToken({
        authorization: `Bearer ${legacyToken}`,
        secret: legacySecret,
        operatorGithubIds: new Set(),
        nowSeconds: now,
      }),
    ).resolves.toMatchObject({ githubId: "42", roles: ["contributor"] });
    await expect(
      signApiToken({ ...claims, extra: "not-authorized" } as never, SECRET),
    ).rejects.toThrow(/claims/u);
    await expect(
      signApiToken(
        { ...claims, roles: ["contributor", "contributor"] },
        SECRET,
      ),
    ).rejects.toThrow(/claims/u);
    await expect(
      verifyApiToken({
        authorization: `Bearer v1.${"A".repeat(4097)}.${"A".repeat(43)}`,
        secret: SECRET,
        operatorGithubIds: new Set(),
        nowSeconds: now,
      }),
    ).resolves.toBeNull();
  });

  it("rejects contributor tokens longer than the documented ten minutes", async () => {
    const now = Math.floor(NOW.getTime() / 1000);
    const oversized = await signApiToken(
      {
        iss: "slop.cash",
        aud: "private-trace-api",
        sub: "github:42",
        githubId: "42",
        githubLogin: "octocat",
        roles: ["contributor"],
        iat: now,
        exp: now + 601,
        jti: "oversized_token_identifier",
      },
      SECRET,
    );
    const response = await createRun(
      dependencies(),
      oversized,
      "oversized_token_run_key",
    );
    expect(response.status).toBe(401);
  });

  it("requires a valid trace before finalization and is write-only for contributors", async () => {
    const store = new MemoryPersistence();
    const deps = dependencies(store);
    const contributor = await token("42", "octocat", ["contributor"]);
    const created = await createRun(deps, contributor);
    expect(created.status).toBe(201);
    const { serverRunId } = (await created.json()) as { serverRunId: string };

    const premature = await handleTraceApi(
      request(`runs/${serverRunId}/finalize`, "POST", contributor, undefined, {
        "idempotency-key": "finalize_run_key_0001",
      }),
      deps,
    );
    expect(premature.status).toBe(409);
    expect(await premature.json()).toMatchObject({ error: "trace_required" });

    const trace = new TextEncoder().encode('{"event":"complete"}\n');
    const { digest, uploaded } = await uploadTrace(
      deps,
      contributor,
      serverRunId,
      trace,
      "upload_trace_key_0001",
      "application/x-ndjson",
    );
    expect(uploaded.status).toBe(201);
    expect(await uploaded.json()).toMatchObject({
      serverRunId,
      traceObjectId: `sha256:${digest}`,
      state: "trace_uploaded",
    });
    const uploadUrl = (
      (await (
        await handleTraceApi(
          request(
            `runs/${serverRunId}/trace-intents`,
            "POST",
            contributor,
            JSON.stringify({
              sha256: digest,
              sizeBytes: trace.byteLength,
              contentType: "application/x-ndjson",
            }),
            {
              "content-type": "application/json",
              "idempotency-key": "upload_trace_key_0001",
            },
          ),
          deps,
        )
      ).json()) as { uploadUrl: string }
    ).uploadUrl;
    const replayUpload = await handleTraceApi(
      new Request(uploadUrl, {
        method: "PUT",
        body: trace.slice().buffer,
        headers: {
          "content-type": "application/x-ndjson",
          digest: `sha-256=${digest}`,
        },
      }),
      deps,
    );
    expect(replayUpload.status).toBe(410);

    const finalized = await handleTraceApi(
      request(`runs/${serverRunId}/finalize`, "POST", contributor, undefined, {
        "idempotency-key": "finalize_run_key_0002",
      }),
      deps,
    );
    expect(finalized.status).toBe(200);
    expect(await finalized.json()).toMatchObject({ state: "finalized" });

    const readAttempt = await handleTraceApi(
      request(`runs/${serverRunId}`, "GET", contributor),
      deps,
    );
    expect(readAttempt.status).toBe(404);
  });

  it("conceals other contributors' runs and rejects idempotency replay mutation", async () => {
    const deps = dependencies();
    const owner = await token("42", "octocat", ["contributor"]);
    const attacker = await token("43", "attacker", ["contributor"]);
    const created = await createRun(deps, owner);
    const { serverRunId } = (await created.json()) as { serverRunId: string };
    const bytes = new TextEncoder().encode("private trace");
    const digest = await sha256Hex(bytes);
    const denied = await handleTraceApi(
      request(
        `runs/${serverRunId}/trace-intents`,
        "POST",
        attacker,
        JSON.stringify({
          sha256: digest,
          sizeBytes: bytes.byteLength,
          contentType: "text/plain",
        }),
        {
          "content-type": "application/json",
          "idempotency-key": "attack_upload_key_01",
        },
      ),
      deps,
    );
    expect(denied.status).toBe(404);

    const replay = await createRun(deps, owner);
    expect(replay.status).toBe(200);
    const changed = await handleTraceApi(
      request(
        "runs",
        "POST",
        owner,
        JSON.stringify({
          clientRunId: "run_DIFFERENT",
          projectId: "eliza",
          repository: "elizaOS/eliza",
          projectPolicyRevision: "a".repeat(40),
          provider: "openai",
          model: "gpt-5",
          client: "codex",
          clientVersion: "1.0.0",
        }),
        {
          "content-type": "application/json",
          "idempotency-key": "create_run_key_0001",
        },
      ),
      deps,
    );
    expect(changed.status).toBe(409);
  });

  it("rejects progress-event mutation under an idempotency key", async () => {
    const deps = dependencies();
    const contributor = await token("42", "octocat", ["contributor"]);
    const created = await createRun(
      deps,
      contributor,
      "create_event_run_key_0001",
    );
    const { serverRunId } = (await created.json()) as { serverRunId: string };
    const post = (occurredAt: string) =>
      handleTraceApi(
        request(
          `runs/${serverRunId}/events`,
          "POST",
          contributor,
          JSON.stringify({ kind: "checkpoint", occurredAt, source: "agent" }),
          {
            "content-type": "application/json",
            "idempotency-key": "progress_event_key_0001",
          },
        ),
        deps,
      );

    expect((await post("2026-08-15T11:59:00.000Z")).status).toBe(201);
    const mutated = await post("2026-08-15T11:59:01.000Z");
    expect(mutated.status).toBe(409);
    expect(await mutated.json()).toMatchObject({
      error: "idempotency_conflict",
    });
  });

  it("rejects a progress event beyond the server clock tolerance", async () => {
    const store = new MemoryPersistence();
    const deps = dependencies(store);
    const contributor = await token("42", "octocat", ["contributor"]);
    const created = await createRun(
      deps,
      contributor,
      "create_future_event_run_key_0001",
    );
    const { serverRunId } = (await created.json()) as { serverRunId: string };
    const response = await handleTraceApi(
      request(
        `runs/${serverRunId}/events`,
        "POST",
        contributor,
        JSON.stringify({
          kind: "run_completed",
          occurredAt: new Date(NOW.getTime() + 5 * 60_000 + 1).toISOString(),
          source: "agent",
        }),
        {
          "content-type": "application/json",
          "idempotency-key": "future_progress_event_key_0001",
        },
      ),
      deps,
    );

    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_request" });
    expect(store.events.size).toBe(0);
  });

  it("rejects impossible calendar dates in progress events", async () => {
    const deps = dependencies();
    const contributor = await token("42", "octocat", ["contributor"]);
    const created = await createRun(
      deps,
      contributor,
      "create_invalid_date_run_key_0001",
    );
    const { serverRunId } = (await created.json()) as { serverRunId: string };

    const response = await handleTraceApi(
      request(
        `runs/${serverRunId}/events`,
        "POST",
        contributor,
        JSON.stringify({
          kind: "checkpoint",
          occurredAt: "2026-02-30T11:59:00.000Z",
          source: "agent",
        }),
        {
          "content-type": "application/json",
          "idempotency-key": "invalid_date_event_key_0001",
        },
      ),
      deps,
    );

    expect(response.status).toBe(400);
    expect(deps.persistence).toBeInstanceOf(MemoryPersistence);
    expect((deps.persistence as MemoryPersistence).events.size).toBe(0);
  });

  it("rejects digest mismatches before retaining an object", async () => {
    const store = new MemoryPersistence();
    const deps = dependencies(store);
    const contributor = await token("42", "octocat", ["contributor"]);
    const created = await createRun(deps, contributor);
    const { serverRunId } = (await created.json()) as { serverRunId: string };
    const claimed = "0".repeat(64);
    const intentResponse = await handleTraceApi(
      request(
        `runs/${serverRunId}/trace-intents`,
        "POST",
        contributor,
        JSON.stringify({
          sha256: claimed,
          sizeBytes: 21,
          contentType: "text/plain",
        }),
        {
          "content-type": "application/json",
          "idempotency-key": "upload_trace_key_bad1",
        },
      ),
      deps,
    );
    const { uploadUrl } = (await intentResponse.json()) as {
      uploadUrl: string;
    };
    const response = await handleTraceApi(
      new Request(uploadUrl, {
        method: "PUT",
        body: "not the claimed bytes",
        headers: { "content-type": "text/plain", digest: `sha-256=${claimed}` },
      }),
      deps,
    );
    expect(response.status).toBe(422);
    expect(store.bytes.size).toBe(0);
    expect(store.objects.size).toBe(0);
  });

  it("logs the cause of an unexpected failure without echoing it to the client", async () => {
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const deps: TraceApiDependencies = {
        ...dependencies(),
        privateIntakeStatus: async () => {
          throw new Error("intake probe exploded");
        },
      };
      const response = await handleTraceApi(
        new Request("https://api.slop.cash/api/v1/private-request-intake"),
        deps,
      );
      expect(response.status).toBe(500);
      expect(await response.json()).toEqual({
        error: "internal_error",
        message: "Internal error",
      });
      expect(logged).toHaveBeenCalledTimes(1);
      const [label, detail] = logged.mock.calls[0] as [
        string,
        Record<string, unknown>,
      ];
      expect(label).toBe("private trace API failure");
      expect(detail).toMatchObject({
        status: 500,
        method: "GET",
        route: "private-request-intake",
        pathSegments: 1,
        code: null,
        name: "Error",
        message: "intake probe exploded",
      });
      expect(typeof detail.stack).toBe("string");
    } finally {
      logged.mockRestore();
    }
  });

  it("keeps upload capabilities out of the failure log", async () => {
    const store = new MemoryPersistence();
    const deps = dependencies(store);
    const contributor = await token("42", "octocat", ["contributor"]);
    const created = await createRun(
      deps,
      contributor,
      "create_log_run_key_0001",
    );
    const { serverRunId } = (await created.json()) as { serverRunId: string };
    const bytes = new TextEncoder().encode(
      "private trace that must not be logged",
    );
    const digest = await sha256Hex(bytes);
    const intent = await handleTraceApi(
      request(
        `runs/${serverRunId}/trace-intents`,
        "POST",
        contributor,
        JSON.stringify({
          sha256: digest,
          sizeBytes: bytes.byteLength,
          contentType: "text/plain",
        }),
        {
          "content-type": "application/json",
          "idempotency-key": "upload_log_key_0001",
        },
      ),
      deps,
    );
    const { uploadUrl } = (await intent.json()) as { uploadUrl: string };
    const capability = new URL(uploadUrl).pathname.split("/").at(-1) ?? "";
    expect(capability.length).toBeGreaterThan(0);

    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      store.failNextPut = true;
      const response = await handleTraceApi(
        new Request(uploadUrl, {
          method: "PUT",
          body: bytes.slice().buffer,
          headers: {
            "content-type": "text/plain",
            digest: `sha-256=${digest}`,
          },
        }),
        deps,
      );
      expect(response.status).toBe(500);
      expect(logged).toHaveBeenCalledTimes(1);
      const serialized = JSON.stringify(logged.mock.calls[0]);
      expect(serialized).toContain('"route":"trace-uploads"');
      expect(serialized).toContain('"pathSegments":2');
      expect(serialized).toContain("transient R2 failure");
      expect(serialized).not.toContain(capability);
      expect(serialized).not.toContain("private trace that must not be logged");
    } finally {
      logged.mockRestore();
    }
  });

  it("does not burn an upload capability on validation or transient storage failure", async () => {
    const store = new MemoryPersistence();
    const deps = dependencies(store);
    const contributor = await token("42", "octocat", ["contributor"]);
    const created = await createRun(
      deps,
      contributor,
      "create_retry_run_key_0001",
    );
    const { serverRunId } = (await created.json()) as { serverRunId: string };
    const bytes = new TextEncoder().encode("retryable private trace");
    const digest = await sha256Hex(bytes);
    const intent = await handleTraceApi(
      request(
        `runs/${serverRunId}/trace-intents`,
        "POST",
        contributor,
        JSON.stringify({
          sha256: digest,
          sizeBytes: bytes.byteLength,
          contentType: "text/plain",
        }),
        {
          "content-type": "application/json",
          "idempotency-key": "upload_retry_key_0001",
        },
      ),
      deps,
    );
    const { uploadUrl } = (await intent.json()) as { uploadUrl: string };
    const uploadRequest = (contentType = "text/plain") =>
      new Request(uploadUrl, {
        method: "PUT",
        body: bytes.slice().buffer,
        headers: { "content-type": contentType, digest: `sha-256=${digest}` },
      });

    expect(
      (await handleTraceApi(uploadRequest("application/x-ndjson"), deps))
        .status,
    ).toBe(422);
    store.failNextPut = true;
    expect((await handleTraceApi(uploadRequest(), deps)).status).toBe(500);
    expect((await handleTraceApi(uploadRequest(), deps)).status).toBe(201);
  });

  it("completes an upload authorized immediately before capability expiry", async () => {
    const store = new MemoryPersistence();
    const deps = dependencies(store);
    const contributor = await token("42", "octocat", ["contributor"]);
    const created = await createRun(
      deps,
      contributor,
      "create_expiring_upload_run_0001",
    );
    const { serverRunId } = (await created.json()) as { serverRunId: string };
    const bytes = new TextEncoder().encode("authorized before expiry");
    const digest = await sha256Hex(bytes);
    const intentResponse = await handleTraceApi(
      request(
        `runs/${serverRunId}/trace-intents`,
        "POST",
        contributor,
        JSON.stringify({
          sha256: digest,
          sizeBytes: bytes.byteLength,
          contentType: "text/plain",
        }),
        {
          "content-type": "application/json",
          "idempotency-key": "expiring_upload_key_0001",
        },
      ),
      deps,
    );
    const { uploadUrl } = (await intentResponse.json()) as {
      uploadUrl: string;
    };
    const intent = [...store.intents.values()][0];
    intent.expiresAt = new Date(NOW.getTime() + 1).toISOString();
    const times = [
      NOW,
      new Date(NOW.getTime() + 2),
      new Date(NOW.getTime() + 3),
    ];
    deps.now = () => new Date(times.shift() ?? times.at(-1) ?? NOW);

    const response = await handleTraceApi(
      new Request(uploadUrl, {
        method: "PUT",
        body: bytes.slice().buffer,
        headers: { "content-type": "text/plain", digest: `sha-256=${digest}` },
      }),
      deps,
    );

    expect(response.status).toBe(201);
    expect(store.bytes.has(digest)).toBe(true);
    expect(store.uploads.size).toBe(1);
  });

  it("atomically permits only one concurrent upload capability consumer", async () => {
    const store = new MemoryPersistence();
    const deps = dependencies(store);
    const contributor = await token("42", "octocat", ["contributor"]);
    const created = await createRun(
      deps,
      contributor,
      "create_concurrent_run_0001",
    );
    const { serverRunId } = (await created.json()) as { serverRunId: string };
    const bytes = new TextEncoder().encode("one consumer only");
    const digest = await sha256Hex(bytes);
    const intent = await handleTraceApi(
      request(
        `runs/${serverRunId}/trace-intents`,
        "POST",
        contributor,
        JSON.stringify({
          sha256: digest,
          sizeBytes: bytes.byteLength,
          contentType: "text/plain",
        }),
        {
          "content-type": "application/json",
          "idempotency-key": "upload_concurrent_0001",
        },
      ),
      deps,
    );
    const { uploadUrl } = (await intent.json()) as { uploadUrl: string };
    const makeUpload = () =>
      new Request(uploadUrl, {
        method: "PUT",
        body: bytes.slice().buffer,
        headers: { "content-type": "text/plain", digest: `sha-256=${digest}` },
      });
    const responses = await Promise.all([
      handleTraceApi(makeUpload(), deps),
      handleTraceApi(makeUpload(), deps),
    ]);
    const statuses = responses.map(({ status }) => status);
    expect(statuses.filter((status) => status === 201)).toHaveLength(1);
    const loserStatuses = statuses.filter((status) => status !== 201);
    expect(loserStatuses).toHaveLength(1);
    expect([409, 410]).toContain(loserStatuses[0]);
    expect(store.uploads.size).toBe(1);
    expect(store.objects.size).toBe(1);
    expect((await handleTraceApi(makeUpload(), deps)).status).toBe(410);
  });

  it("allows one audited read only to a designated operator", async () => {
    const store = new MemoryPersistence();
    const deps = dependencies(store);
    const contributor = await token("42", "octocat", ["contributor"]);
    const operator = await token("99", "slop-operator", ["operator"]);
    const created = await createRun(deps, contributor);
    const { serverRunId } = (await created.json()) as { serverRunId: string };
    const bytes = new TextEncoder().encode("permanent private trace");
    const digest = await sha256Hex(bytes);
    await uploadTrace(
      deps,
      contributor,
      serverRunId,
      bytes,
      "upload_trace_key_read",
    );
    const grantResponse = await handleTraceApi(
      request(
        `operator/traces/${digest}/grant`,
        "POST",
        operator,
        JSON.stringify({ reason: "investigate reported receipt mismatch" }),
        { "content-type": "application/json" },
      ),
      deps,
    );
    expect(grantResponse.status).toBe(201);
    const { grant } = (await grantResponse.json()) as { grant: string };
    const first = await handleTraceApi(
      request(`operator/traces/${digest}`, "GET", operator, undefined, {
        "x-trace-read-grant": grant,
      }),
      deps,
    );
    expect(await first.text()).toBe("permanent private trace");
    expect(first.headers.get("content-disposition")).toContain("attachment");
    const replay = await handleTraceApi(
      request(`operator/traces/${digest}`, "GET", operator, undefined, {
        "x-trace-read-grant": grant,
      }),
      deps,
    );
    expect(replay.status).toBe(403);
    expect(store.audits.map((event) => event.action)).toEqual([
      "trace.read_grant.created",
      "trace.read_grant.consumed",
    ]);
  });

  it("does not activate or consume a read grant without its audit event", async () => {
    const store = new MemoryPersistence();
    const deps = dependencies(store);
    const contributor = await token("42", "octocat", ["contributor"]);
    const operator = await token("99", "slop-operator", ["operator"]);
    const created = await createRun(deps, contributor);
    const { serverRunId } = (await created.json()) as { serverRunId: string };
    const bytes = new TextEncoder().encode("audited private trace");
    const digest = await sha256Hex(bytes);
    await uploadTrace(
      deps,
      contributor,
      serverRunId,
      bytes,
      "upload_trace_key_audit_failure",
    );

    store.failNextAudit = true;
    const failedGrant = await handleTraceApi(
      request(
        `operator/traces/${digest}/grant`,
        "POST",
        operator,
        JSON.stringify({ reason: "verify atomic grant audit behavior" }),
        { "content-type": "application/json" },
      ),
      deps,
    );
    expect(failedGrant.status).toBe(500);
    expect(store.grants.size).toBe(0);

    const grantResponse = await handleTraceApi(
      request(
        `operator/traces/${digest}/grant`,
        "POST",
        operator,
        JSON.stringify({ reason: "verify atomic read audit behavior" }),
        { "content-type": "application/json" },
      ),
      deps,
    );
    const { grant } = (await grantResponse.json()) as { grant: string };
    store.failNextAudit = true;
    const failedRead = await handleTraceApi(
      request(`operator/traces/${digest}`, "GET", operator, undefined, {
        "x-trace-read-grant": grant,
      }),
      deps,
    );
    expect(failedRead.status).toBe(500);
    const retriedRead = await handleTraceApi(
      request(`operator/traces/${digest}`, "GET", operator, undefined, {
        "x-trace-read-grant": grant,
      }),
      deps,
    );
    expect(retriedRead.status).toBe(200);
    expect(await retriedRead.text()).toBe("audited private trace");
  });

  it("publishes only immutable wallet claim metadata", async () => {
    const deps = dependencies();
    const operator = await token("99", "slop-operator", ["operator"]);
    const created = await handleTraceApi(
      request(
        "operator/wallet-claims",
        "POST",
        operator,
        JSON.stringify({
          githubActorId: "42",
          githubLogin: "octocat",
          address: "11111111111111111111111111111111",
          observedAt: NOW.toISOString(),
          sourceBodySha256: "b".repeat(64),
        }),
        { "content-type": "application/json" },
      ),
      deps,
    );
    expect(created.status).toBe(201);
    const claim = (await created.json()) as {
      claimId: string;
      recordDigest: string;
    };
    const publicResponse = await handleTraceApi(
      new Request(
        `https://api.slop.cash/api/v1/wallet-claims/${claim.claimId}`,
      ),
      deps,
    );
    expect(publicResponse.status).toBe(200);
    expect(await publicResponse.json()).toMatchObject({
      githubActorId: "42",
      address: "11111111111111111111111111111111",
      source: "d1_registry",
      recordDigest: claim.recordDigest,
    });
  });

  it("rejects an operator wallet observation from the future", async () => {
    const store = new MemoryPersistence();
    const deps = dependencies(store);
    const operator = await token("99", "slop-operator", ["operator"]);
    const response = await handleTraceApi(
      request(
        "operator/wallet-claims",
        "POST",
        operator,
        JSON.stringify({
          githubActorId: "42",
          githubLogin: "octocat",
          address: "11111111111111111111111111111111",
          observedAt: new Date(NOW.getTime() + 1).toISOString(),
          sourceBodySha256: "b".repeat(64),
        }),
        { "content-type": "application/json" },
      ),
      deps,
    );

    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({
      error: "invalid_request",
    });
    expect(store.claims.size).toBe(0);
  });

  it("lets a GitHub-authenticated contributor create and supersede one wallet lineage", async () => {
    const deps = dependencies();
    const contributor = await token("42", "octocat", ["contributor"]);
    const first = await handleTraceApi(
      request(
        "wallet-claims",
        "POST",
        contributor,
        JSON.stringify({ address: "11111111111111111111111111111111" }),
        { "content-type": "application/json" },
      ),
      deps,
    );
    expect(first.status).toBe(201);
    const firstClaim = (await first.json()) as {
      claimId: string;
      githubActorId: string;
      source: string;
    };
    expect(firstClaim).toMatchObject({
      githubActorId: "42",
      source: "d1_registry",
    });

    const unchanged = await handleTraceApi(
      request(
        "wallet-claims",
        "POST",
        contributor,
        JSON.stringify({
          address: "11111111111111111111111111111111",
          supersedesClaimId: firstClaim.claimId,
        }),
        { "content-type": "application/json" },
      ),
      deps,
    );
    expect(unchanged.status).toBe(200);
    expect((await unchanged.json()).claimId).toBe(firstClaim.claimId);

    const changed = await handleTraceApi(
      request(
        "wallet-claims",
        "POST",
        contributor,
        JSON.stringify({
          address: "SysvarRent111111111111111111111111111111111",
          supersedesClaimId: firstClaim.claimId,
        }),
        { "content-type": "application/json" },
      ),
      deps,
    );
    expect(changed.status).toBe(201);
    const secondClaim = (await changed.json()) as {
      claimId: string;
      supersedesClaimId: string;
    };
    expect(secondClaim.supersedesClaimId).toBe(firstClaim.claimId);

    const current = await handleTraceApi(
      new Request(
        "https://api.slop.cash/api/v1/wallet-claims/actors/42/current",
      ),
      deps,
    );
    expect(current.status).toBe(200);
    expect((await current.json()).claimId).toBe(secondClaim.claimId);

    const authenticatedCurrent = await handleTraceApi(
      request("wallet-claims/current", "GET", contributor),
      deps,
    );
    expect(authenticatedCurrent.status).toBe(200);
    expect((await authenticatedCurrent.json()).claimId).toBe(
      secondClaim.claimId,
    );

    const stale = await handleTraceApi(
      request(
        "wallet-claims",
        "POST",
        contributor,
        JSON.stringify({
          address: "Vote111111111111111111111111111111111111111",
          supersedesClaimId: firstClaim.claimId,
        }),
        { "content-type": "application/json" },
      ),
      deps,
    );
    expect(stale.status).toBe(409);
    expect(await stale.json()).toMatchObject({ error: "stale_wallet_claim" });
  });

  it("refreshes an unchanged wallet claim after a GitHub login rename", async () => {
    const deps = dependencies();
    const originalActor = await token("42", "old-login", ["contributor"]);
    const original = await handleTraceApi(
      request(
        "wallet-claims",
        "POST",
        originalActor,
        JSON.stringify({ address: "11111111111111111111111111111111" }),
        { "content-type": "application/json" },
      ),
      deps,
    );
    const originalClaim = (await original.json()) as { claimId: string };
    const renamedActor = await token("42", "new-login", ["contributor"]);

    const refreshed = await handleTraceApi(
      request(
        "wallet-claims",
        "POST",
        renamedActor,
        JSON.stringify({
          address: "11111111111111111111111111111111",
          supersedesClaimId: originalClaim.claimId,
        }),
        { "content-type": "application/json" },
      ),
      deps,
    );

    expect(refreshed.status).toBe(201);
    expect(await refreshed.json()).toMatchObject({
      githubActorId: "42",
      githubLogin: "new-login",
      supersedesClaimId: originalClaim.claimId,
    });
  });

  it("does not let an unauthenticated caller create a wallet claim", async () => {
    const response = await handleTraceApi(
      new Request("https://api.slop.cash/api/v1/wallet-claims", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          address: "11111111111111111111111111111111",
        }),
      }),
      dependencies(),
    );
    expect(response.status).toBe(401);
  });

  it("does not activate a wallet claim when its required audit write fails", async () => {
    const store = new MemoryPersistence();
    const deps = dependencies(store);
    const contributor = await token("42", "octocat", ["contributor"]);
    store.failNextAudit = true;
    const failed = await handleTraceApi(
      request(
        "wallet-claims",
        "POST",
        contributor,
        JSON.stringify({ address: "11111111111111111111111111111111" }),
        { "content-type": "application/json" },
      ),
      deps,
    );
    expect(failed.status).toBe(500);
    expect(await store.getCurrentWalletClaim("42")).toBeNull();
    expect(store.audits).toEqual([]);
  });

  it("reports unknown paths as not found instead of demanding authentication", async () => {
    const unknown: Array<[string, string]> = [
      ["private-request-intak", "GET"],
      ["private-request-intake/extra", "GET"],
      ["runs", "GET"],
      ["runs/run_0000000000000001/unknown-action", "POST"],
      ["operator/traces", "GET"],
    ];
    for (const [path, method] of unknown) {
      const response = await handleTraceApi(
        new Request(`https://api.slop.cash/api/v1/${path}`, { method }),
        dependencies(),
      );
      expect(response.status).toBe(404);
      expect(await response.json()).toMatchObject({ error: "not_found" });
    }
  });

  it("still requires authentication before validating a matched run id", async () => {
    const deps = dependencies();
    const unauthenticated = await handleTraceApi(
      new Request(
        "https://api.slop.cash/api/v1/runs/not%20a%20valid%20id/finalize",
        { method: "POST" },
      ),
      deps,
    );
    expect(unauthenticated.status).toBe(401);
    expect(await unauthenticated.json()).toMatchObject({
      error: "unauthorized",
    });
    const bearer = await token("42", "contributor-login", ["contributor"]);
    const invalidRunId = await handleTraceApi(
      request("runs/not%20a%20valid%20id/finalize", "POST", bearer),
      deps,
    );
    expect(invalidRunId.status).toBe(400);
    expect(await invalidRunId.json()).toMatchObject({
      error: "invalid_request",
    });
  });
});
