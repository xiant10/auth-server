/**
 * What every TypeScript t10 service uses to check a bearer token: the same rules as the Go package beside it, with no
 * dependencies. It returns the user and any agent context together, so a service can't read `sub` and hand an agent the
 * user's full rights by accident. A delegated token fails closed if its grant chain can't be fetched.
 */
import { createPublicKey, type JsonWebKey, type KeyObject, verify } from "node:crypto";

const AUDIENCE_T10 = "t10";
/** Matches the 60 seconds modules may cache org reads: how long a revoked grant can go unnoticed on a live token. */
const CHAIN_CACHE_MS = 60_000;
const JWKS_CACHE_MS = 600_000;
const JWKS_MIN_REFRESH_MS = 30_000;
const REQUEST_TIMEOUT_MS = 5_000;
const RENEW_BEFORE_MS = 30_000;

export type VerifierConfig = {
	/** The auth service's public URL, as it appears in `iss`. */
	readonly issuer: string;
	/** Where this service reaches it, which inside a deployment is often a private address. Defaults to `issuer`. */
	readonly url?: string;
	/** This service's own name, as it appears in an audience. */
	readonly service: string;
	/** This service's secret, for fetching grant chains. */
	readonly clientSecret?: string;
};

/** One grant in a chain. The service must pass every link's constraints. */
export type Link = {
	readonly id: string;
	readonly actions: readonly string[];
	readonly audiences: readonly string[];
	readonly constraints: Readonly<Record<string, unknown>>;
	readonly expires_at: string;
};

export type Identity = {
	/** Empty on a service's own token. */
	readonly userId: string;
	readonly tenantId: string;
	/** Set only on a service's own token, which has no user. */
	readonly serviceId?: string;
	readonly scopes: readonly string[];
	/**
	 * Set when an agent is acting for the user. `chain` runs from the root grant to this one. `trigger` says why the run is running,
	 * and `automation` names the automation that started it, both from the signed token.
	 */
	readonly agent?: { readonly runtime: string; readonly grantId: string; readonly trigger: string; readonly automation?: string; readonly chain: readonly Link[] };
};

/** Answer 401. */
export class InvalidTokenError extends Error {}
/** A delegated token's chain could not be confirmed. Refuse the request. */
export class GrantUnavailableError extends Error {}

/**
 * Whether the token may attempt `action`. A person's rights are the service's to judge, so it's always true for them.
 * An agent needs it in its token and on every grant in its chain, on top of what the user may do.
 */
export function allows(identity: Identity, action: string): boolean {
	if (identity.agent === undefined) return identity.userId !== "";
	return identity.scopes.includes(action) && identity.agent.chain.every((link) => link.actions.includes(action));
}

/** Every grant's opaque constraints, root first. All apply. */
export function constraints(identity: Identity): readonly Readonly<Record<string, unknown>>[] {
	return identity.agent?.chain.map((link) => link.constraints) ?? [];
}

type Claims = {
	iss?: unknown;
	aud?: unknown;
	exp?: unknown;
	nbf?: unknown;
	sub?: unknown;
	tid?: unknown;
	scope?: unknown;
	sid?: unknown;
	act?: { sub?: unknown };
	grant?: unknown;
	trg?: unknown;
	automation?: unknown;
};

export class Verifier {
	readonly #config: VerifierConfig;
	readonly #url: string;
	readonly #fetch: typeof fetch;
	readonly #now: () => number;
	#keys = new Map<string, KeyObject>();
	#keysFetchedAt = Number.NEGATIVE_INFINITY;
	#service: { token: string; expiresAt: number } | undefined;
	readonly #chains = new Map<string, { chain: readonly Link[]; fetchedAt: number }>();

	constructor(config: VerifierConfig, options: { readonly fetch?: typeof fetch; readonly now?: () => number } = {}) {
		if (config.issuer === "" || config.service === "") throw new Error("verifier: issuer and service are required");
		this.#config = { ...config, issuer: config.issuer.replace(/\/+$/, "") };
		this.#url = (config.url ?? config.issuer).replace(/\/+$/, "");
		this.#fetch = options.fetch ?? globalThis.fetch;
		this.#now = options.now ?? Date.now;
	}

	/** Check a bearer token and return who it speaks for, or throw. */
	async verify(raw: string): Promise<Identity> {
		const claims = await this.#claims(raw);
		const audience = typeof claims.aud === "string" ? [claims.aud] : Array.isArray(claims.aud) ? claims.aud : [];
		const scopes = typeof claims.scope === "string" ? claims.scope.split(" ").filter((scope) => scope !== "") : [];
		const tenantId = typeof claims.tid === "string" ? claims.tid : "";
		const subject = typeof claims.sub === "string" ? claims.sub : "";
		if (claims.grant !== undefined || claims.act !== undefined) {
			const runtime = claims.act?.sub;
			if (typeof claims.grant !== "string" || claims.grant === "" || typeof runtime !== "string" || !audience.includes(this.#config.service)) {
				throw new InvalidTokenError("delegated token is not for this service");
			}
			const chain = await this.#chain(claims.grant);
			const trigger = typeof claims.trg === "string" ? claims.trg : "";
			const automation = typeof claims.automation === "string" && claims.automation !== "" ? { automation: claims.automation } : {};
			return { userId: subject, tenantId, scopes, agent: { runtime, grantId: claims.grant, trigger, ...automation, chain } };
		}
		if (!audience.includes(AUDIENCE_T10)) throw new InvalidTokenError("audience not accepted");
		if (typeof claims.sid === "string" && claims.sid !== "") return { userId: subject, tenantId, scopes };
		return { userId: "", tenantId, serviceId: subject, scopes };
	}

	async #claims(raw: string): Promise<Claims> {
		const parts = raw.split(".");
		if (parts.length !== 3) throw new InvalidTokenError("malformed token");
		const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];
		let header: { alg?: unknown; kid?: unknown; crit?: unknown };
		let claims: Claims;
		try {
			header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString("utf8")) as typeof header;
			claims = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8")) as Claims;
		} catch {
			throw new InvalidTokenError("malformed token");
		}
		if (header.alg !== "ES256" || header.crit !== undefined) throw new InvalidTokenError("token algorithm not accepted");
		const key = await this.#key(typeof header.kid === "string" ? header.kid : "");
		const signed = verify(
			"sha256",
			Buffer.from(`${encodedHeader}.${encodedPayload}`, "ascii"),
			{ key, dsaEncoding: "ieee-p1363" },
			Buffer.from(encodedSignature, "base64url"),
		);
		if (!signed) throw new InvalidTokenError("bad signature");
		const now = this.#now() / 1000;
		if (claims.iss !== this.#config.issuer) throw new InvalidTokenError("issuer not accepted");
		if (typeof claims.exp !== "number" || now >= claims.exp) throw new InvalidTokenError("token expired");
		if (typeof claims.nbf === "number" && now < claims.nbf) throw new InvalidTokenError("token not yet valid");
		return claims;
	}

	async #key(kid: string): Promise<KeyObject> {
		const age = this.#now() - this.#keysFetchedAt;
		if (age > JWKS_CACHE_MS || (!this.#keys.has(kid) && age >= JWKS_MIN_REFRESH_MS)) {
			// A failed fetch keeps the old keys: tokens signed by them stay good through an auth outage.
			await this.#fetchKeys().catch(() => undefined);
			this.#keysFetchedAt = this.#now();
		}
		const key = this.#keys.get(kid);
		if (key === undefined) throw new InvalidTokenError("unknown kid");
		return key;
	}

	async #fetchKeys(): Promise<void> {
		const response = await this.#fetch(`${this.#url}/.well-known/jwks.json`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
		if (!response.ok) throw new Error(`jwks status ${response.status}`);
		const body = (await response.json()) as { keys?: (JsonWebKey & { kid?: string })[] };
		const keys = new Map<string, KeyObject>();
		for (const jwk of body.keys ?? []) {
			if (jwk.kty === "EC" && jwk.crv === "P-256" && jwk.kid !== undefined) keys.set(jwk.kid, createPublicKey({ key: jwk, format: "jwk" }));
		}
		this.#keys = keys;
	}

	async #chain(grantId: string): Promise<readonly Link[]> {
		const cached = this.#chains.get(grantId);
		if (cached !== undefined && this.#now() - cached.fetchedAt < CHAIN_CACHE_MS) return cached.chain;
		this.#chains.delete(grantId);
		try {
			const chain = await this.#fetchChain(grantId);
			for (const [id, entry] of this.#chains) {
				if (this.#now() - entry.fetchedAt >= CHAIN_CACHE_MS) this.#chains.delete(id);
			}
			this.#chains.set(grantId, { chain, fetchedAt: this.#now() });
			return chain;
		} catch (error) {
			throw new GrantUnavailableError(error instanceof Error ? error.message : String(error));
		}
	}

	async #fetchChain(grantId: string): Promise<readonly Link[]> {
		const token = await this.#ownToken();
		const response = await this.#fetch(`${this.#url}/v1/grants/${encodeURIComponent(grantId)}/chain`, {
			headers: { authorization: `Bearer ${token}` },
			signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
		});
		if (!response.ok) throw new Error(`chain status ${response.status}`);
		const { chain } = (await response.json()) as { chain?: Link[] };
		if (chain === undefined || chain.length === 0) throw new Error("empty chain");
		return chain;
	}

	async #ownToken(): Promise<string> {
		if (this.#service !== undefined && this.#service.expiresAt - this.#now() > RENEW_BEFORE_MS) return this.#service.token;
		const response = await this.#fetch(`${this.#url}/v1/token`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ grant_type: "client_credentials", client_id: this.#config.service, client_secret: this.#config.clientSecret ?? "" }),
			signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
		});
		if (!response.ok) throw new Error(`service token status ${response.status}`);
		const body = (await response.json()) as { access_token: string; expires_in: number };
		this.#service = { token: body.access_token, expiresAt: this.#now() + body.expires_in * 1000 };
		return body.access_token;
	}
}
