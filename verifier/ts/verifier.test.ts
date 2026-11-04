// Run with: node --test verifier/ts/verifier.test.ts
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { describe, it } from "node:test";
import { allows, constraints, GrantUnavailableError, InvalidTokenError, Verifier } from "./verifier.ts";

const ISSUER = "https://auth.example";
const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const other = generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = { ...publicKey.export({ format: "jwk" }), kid: "k1" };
const now = Date.now();

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");

function token(claims: Record<string, unknown>, header: Record<string, unknown> = { alg: "ES256", kid: "k1" }, key = privateKey) {
	const input = `${b64(header)}.${b64({ iss: ISSUER, exp: now / 1000 + 300, ...claims })}`;
	return `${input}.${sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
}

const CHAIN = [
	{ id: "grt_root", actions: ["agent:use", "crm:read"], audiences: ["crm"], constraints: { region: "north" }, expires_at: "" },
	{ id: "grt_leaf", actions: ["crm:read"], audiences: ["crm"], constraints: { deal: "d1" }, expires_at: "" },
];

function server(options: { chain?: () => Response; down?: boolean } = {}) {
	const calls: string[] = [];
	const stub = (async (input: string | URL | Request) => {
		const url = new URL(String(input));
		calls.push(url.pathname);
		if (url.hostname !== "auth.internal") throw new Error(`called ${url.hostname}`);
		if (url.pathname === "/.well-known/jwks.json") return options.down ? new Response("", { status: 500 }) : Response.json({ keys: [jwk] });
		if (url.pathname === "/v1/token") return Response.json({ access_token: "service", expires_in: 300 });
		return options.chain?.() ?? Response.json({ chain: CHAIN });
	}) as typeof fetch;
	return { stub, calls };
}

function verifier(stub: typeof fetch, clock: () => number = () => now, service = "crm") {
	return new Verifier({ issuer: ISSUER, url: "http://auth.internal/", service, clientSecret: "s" }, { fetch: stub, now: clock });
}

const AGENT = { sub: "usr_1", tid: "ten_1", aud: ["crm"], scope: "crm:read", act: { sub: "svc_pi" }, grant: "grt_leaf" };

describe("Verifier", () => {
	it("returns a person with no agent", async () => {
		const got = await verifier(server().stub).verify(token({ sub: "usr_1", tid: "ten_1", aud: ["t10"], sid: "ses_1", scope: "agent:use" }));
		assert.equal(got.userId, "usr_1");
		assert.equal(got.agent, undefined);
		assert.equal(allows(got, "anything:at-all"), true);
	});

	it("returns why a run is running", async () => {
		const got = await verifier(server().stub).verify(token({ ...AGENT, trg: "schedule", automation: "au_brief" }));
		assert.equal(got.agent?.trigger, "schedule");
		assert.equal(got.agent?.automation, "au_brief");
	});

	it("returns an agent with its whole chain", async () => {
		const got = await verifier(server().stub).verify(token(AGENT));
		assert.equal(got.userId, "usr_1");
		assert.equal(got.agent?.runtime, "svc_pi");
		assert.equal(got.agent?.trigger, "");
		assert.deepEqual(got.agent?.chain.map((link) => link.id), ["grt_root", "grt_leaf"]);
		assert.equal(allows(got, "crm:read"), true);
		assert.equal(allows(got, "agent:use"), false);
		assert.deepEqual(constraints(got), [{ region: "north" }, { deal: "d1" }]);
	});

	it("needs an action on every link", async () => {
		const chain = [{ ...CHAIN[0]!, actions: ["agent:use"] }, CHAIN[1]!];
		const got = await verifier(server({ chain: () => Response.json({ chain }) }).stub).verify(token(AGENT));
		assert.equal(allows(got, "crm:read"), false);
	});

	it("keeps a service apart from a person", async () => {
		const got = await verifier(server().stub).verify(token({ sub: "svc_pi", aud: ["t10"] }));
		assert.equal(got.userId, "");
		assert.equal(got.serviceId, "svc_pi");
		assert.equal(allows(got, "agent:use"), false);
	});

	for (const [name, raw] of Object.entries({
		"another service's token": token({ ...AGENT, aud: ["deals"] }),
		"a grant with no actor": token({ sub: "usr_1", aud: ["crm"], grant: "grt_leaf" }),
		"an actor with no grant": token({ sub: "usr_1", aud: ["t10"], sid: "s", act: { sub: "svc_pi" } }),
		"an unknown audience": token({ sub: "usr_1", aud: ["room:x"], sid: "s" }),
		"an expired token": token({ sub: "usr_1", aud: ["t10"], sid: "s", exp: now / 1000 - 1 }),
		"no expiry": token({ sub: "usr_1", aud: ["t10"], sid: "s", exp: "soon" }),
		"a future token": token({ sub: "usr_1", aud: ["t10"], sid: "s", nbf: now / 1000 + 100 }),
		"the wrong issuer": token({ sub: "usr_1", aud: ["t10"], sid: "s", iss: "https://evil.example" }),
		"another key": token({ sub: "usr_1", aud: ["t10"], sid: "s" }, undefined, other.privateKey),
		"an unknown kid": token({ sub: "usr_1", aud: ["t10"], sid: "s" }, { alg: "ES256", kid: "nope" }),
		"alg none": token({ sub: "usr_1", aud: ["t10"], sid: "s" }, { alg: "none", kid: "k1" }),
		"a critical header": token({ sub: "usr_1", aud: ["t10"], sid: "s" }, { alg: "ES256", kid: "k1", crit: ["x"] }),
		garbage: "a.b.c",
		"not a token": "nope",
	})) {
		it(`refuses ${name}`, async () => {
			await assert.rejects(verifier(server().stub).verify(raw), InvalidTokenError);
		});
	}

	it("fails closed when the chain can't be fetched", async () => {
		const refused = server({ chain: () => Response.json({ error: "invalid_grant" }, { status: 400 }) });
		await assert.rejects(verifier(refused.stub).verify(token(AGENT)), GrantUnavailableError);
		const empty = server({ chain: () => Response.json({ chain: [] }) });
		await assert.rejects(verifier(empty.stub).verify(token(AGENT)), GrantUnavailableError);
	});

	it("caches a chain for a minute, and no longer", async () => {
		let clock = now;
		const { stub, calls } = server();
		const v = verifier(stub, () => clock);
		await v.verify(token(AGENT));
		clock += 59_000;
		await v.verify(token(AGENT));
		assert.equal(calls.filter((path) => path.endsWith("/chain")).length, 1);
		clock += 2_000;
		await v.verify(token(AGENT));
		assert.equal(calls.filter((path) => path.endsWith("/chain")).length, 2);
	});

	it("keeps verifying people through an auth outage", async () => {
		let clock = now;
		const state = { down: false };
		const up = server();
		const stub = (async (input: string | URL | Request) => {
			if (state.down) throw new Error("connection refused");
			return up.stub(input);
		}) as typeof fetch;
		const v = verifier(stub, () => clock);
		const raw = token({ sub: "usr_1", aud: ["t10"], sid: "s", exp: now / 1000 + 3600 });
		await v.verify(raw);
		state.down = true;
		clock += 700_000;
		assert.equal((await v.verify(raw)).userId, "usr_1");
	});
});
