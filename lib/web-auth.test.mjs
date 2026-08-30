import assert from "node:assert/strict";
import test from "node:test";

async function loadSubject() {
  return import("./web-auth.ts");
}

function authorization(username, password) {
  return `Basic ${Buffer.from(`${username}:${password}`, "utf8").toString("base64")}`;
}

test("enables password authentication only for a non-empty configured password", async () => {
  const { isWebPasswordEnabled } = await loadSubject();
  assert.equal(isWebPasswordEnabled(undefined), false);
  assert.equal(isWebPasswordEnabled(""), false);
  assert.equal(isWebPasswordEnabled("secret"), true);
});

test("accepts only the fixed pi username and configured password", async () => {
  const { isValidBasicAuthorization } = await loadSubject();
  assert.equal(isValidBasicAuthorization(authorization("pi", "secret"), "secret"), true);
  assert.equal(isValidBasicAuthorization(authorization("admin", "secret"), "secret"), false);
  assert.equal(isValidBasicAuthorization(authorization("pi", "wrong"), "secret"), false);
});

test("supports UTF-8 passwords and colons in the password", async () => {
  const { isValidBasicAuthorization } = await loadSubject();
  const password = "口令:with:colons";
  assert.equal(isValidBasicAuthorization(authorization("pi", password), password), true);
});

test("rejects missing, malformed, and non-canonical authorization values", async () => {
  const { isValidBasicAuthorization } = await loadSubject();
  const valid = authorization("pi", "secret");

  assert.equal(isValidBasicAuthorization(null, "secret"), false);
  assert.equal(isValidBasicAuthorization("Bearer token", "secret"), false);
  assert.equal(isValidBasicAuthorization("Basic !!!", "secret"), false);
  assert.equal(isValidBasicAuthorization(`${valid}!`, "secret"), false);
  assert.equal(isValidBasicAuthorization(
    `Basic ${Buffer.from("missing-separator", "utf8").toString("base64")}`,
    "secret",
  ), false);
});

test("does not authenticate when password protection is disabled", async () => {
  const { isValidBasicAuthorization } = await loadSubject();
  assert.equal(isValidBasicAuthorization(authorization("pi", ""), ""), false);
  assert.equal(isValidBasicAuthorization(authorization("pi", "secret"), undefined), false);
});

test("accepts a freshly issued session cookie", async () => {
  const { issueWebSessionCookieValue, isValidWebSessionCookieValue } = await loadSubject();
  assert.equal(isValidWebSessionCookieValue(issueWebSessionCookieValue("secret"), "secret"), true);
});

test("rejects expired session cookies", async () => {
  const { createWebSessionCookieValue, issueWebSessionCookieValue, isValidWebSessionCookieValue } = await loadSubject();
  assert.equal(isValidWebSessionCookieValue(createWebSessionCookieValue(Date.now() - 1000, "secret"), "secret"), false);
  assert.equal(isValidWebSessionCookieValue(createWebSessionCookieValue(Date.now() + 60_000, "secret"), "secret"), true);
  // A cookie signed for one password must not validate under another.
  assert.equal(isValidWebSessionCookieValue(issueWebSessionCookieValue("secret"), "other"), false);
});

test("rejects tampered or malformed session cookies", async () => {
  const { issueWebSessionCookieValue, isValidWebSessionCookieValue } = await loadSubject();
  const value = issueWebSessionCookieValue("secret");
  const [payload, signature] = value.split(".");

  const flipped = (input, at) =>
    input.slice(0, at) + (input[at] === "A" ? "B" : "A") + input.slice(at + 1);

  assert.equal(isValidWebSessionCookieValue(null), false);
  assert.equal(isValidWebSessionCookieValue(""), false);
  assert.equal(isValidWebSessionCookieValue("no-separator"), false);
  assert.equal(isValidWebSessionCookieValue(`${payload}.${signature}.extra`), false);
  assert.equal(isValidWebSessionCookieValue(`${flipped(payload, 2)}.${signature}`), false);
  assert.equal(isValidWebSessionCookieValue(`${payload}.${flipped(signature, 2)}`), false);
  assert.equal(isValidWebSessionCookieValue(`${payload}.!!!`), false);
  // Valid signature for a payload that is not JSON.
  const { createHmac } = await import("node:crypto");
  const rawPayload = Buffer.from("not-json", "utf8");
  const rawSignature = createHmac("sha256", Buffer.alloc(32)).update(rawPayload).digest();
  assert.equal(
    isValidWebSessionCookieValue(`${rawPayload.toString("base64url")}.${rawSignature.toString("base64url")}`),
    false,
  );
});

test("reads the session cookie from request headers", async () => {
  const {
    WEB_AUTH_COOKIE,
    getWebSessionCookieValue,
    issueWebSessionCookieValue,
  } = await loadSubject();
  const value = issueWebSessionCookieValue("secret");
  assert.equal(getWebSessionCookieValue(new Request("http://127.0.0.1/")), null);
  assert.equal(
    getWebSessionCookieValue(new Request("http://127.0.0.1/", { headers: { cookie: `${WEB_AUTH_COOKIE}=${value}` } })),
    value,
  );
  assert.equal(
    getWebSessionCookieValue(
      new Request("http://127.0.0.1/", { headers: { cookie: `other=1; ${WEB_AUTH_COOKIE}=${value}; x=y` } }),
    ),
    value,
  );
});

test("verifyWebPassword checks the plain password against the configured one", async () => {
  const { verifyWebPassword } = await loadSubject();
  assert.equal(verifyWebPassword("secret", "secret"), true);
  assert.equal(verifyWebPassword("wrong", "secret"), false);
  assert.equal(verifyWebPassword("", "secret"), false);
  assert.equal(verifyWebPassword("secret", ""), false);
  assert.equal(verifyWebPassword("secret", undefined), false);
});

test("isWebAuthenticated accepts Basic Auth or a session cookie, and passes through when disabled", async () => {
  const { isWebAuthenticated, issueWebSessionCookieValue, WEB_AUTH_COOKIE } = await loadSubject();
  const noAuth = new Request("http://127.0.0.1/");
  const basic = new Request("http://127.0.0.1/", { headers: { authorization: authorization("pi", "secret") } });
  const cookie = new Request("http://127.0.0.1/", { headers: { cookie: `${WEB_AUTH_COOKIE}=${issueWebSessionCookieValue("secret")}` } });

  assert.equal(isWebAuthenticated(noAuth, "secret"), false);
  assert.equal(isWebAuthenticated(basic, "secret"), true);
  assert.equal(isWebAuthenticated(cookie, "secret"), true);
  assert.equal(isWebAuthenticated(noAuth, ""), true);
  assert.equal(isWebAuthenticated(noAuth, undefined), true);
});
