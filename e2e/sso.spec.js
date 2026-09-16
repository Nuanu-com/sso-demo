import { expect, test } from "@playwright/test";

// These run against .env.test: a fake client, and SSO_SKIP_DISCOVERY so nothing
// here needs an identity provider. What is under test is the half of the flow
// this app owns - the request it builds, and what it does with what comes back.

const CLIENT_ID = "00000000-0000-4000-8000-000000000000";
const REDIRECT_URI = "http://localhost:3001/auth/callback";

/** Follows nothing: the Location header is the thing being asserted on. */
async function authorizationRedirect(request) {
  const response = await request.get("/auth/login", { maxRedirects: 0 });

  expect(response.status()).toBe(303);

  return new URL(response.headers()["location"]);
}

test.describe("landing page", () => {
  test("offers sign-in and describes the flow", async ({ page }) => {
    await page.goto("/");

    await expect(page.getByRole("heading", { name: "Sign in with Nuanu SSO" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Sign in", exact: true })).toBeVisible();
    await expect(page.getByText("Authorization request")).toBeVisible();
  });

  test("shows the endpoints it will use", async ({ page }) => {
    await page.goto("/");

    await expect(page.getByText("http://sso.invalid/web/openid/auth")).toBeVisible();
    await expect(page.getByText(CLIENT_ID)).toBeVisible();
  });

  test("no console errors on load", async ({ page }) => {
    const errors = [];
    page.on("console", (msg) => msg.type() === "error" && errors.push(msg.text()));
    page.on("pageerror", (err) => errors.push(err.message));

    await page.goto("/");

    expect(errors).toEqual([]);
  });
});

test.describe("authorization request", () => {
  test("carries every parameter the SSO server needs", async ({ request }) => {
    const url = await authorizationRedirect(request);

    expect(`${url.origin}${url.pathname}`).toBe("http://sso.invalid/web/openid/auth");

    const params = url.searchParams;

    expect(params.get("response_type")).toBe("code");
    expect(params.get("client_id")).toBe(CLIENT_ID);
    expect(params.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(params.get("scope")).toContain("openid");
    expect(params.get("code_challenge_method")).toBe("S256");

    // Unpadded base64url of a SHA-256 digest is always 43 characters.
    expect(params.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(params.get("state")).toBeTruthy();
    expect(params.get("nonce")).toBeTruthy();
  });

  test("never puts the client secret or code verifier in the browser", async ({ request }) => {
    const url = await authorizationRedirect(request);

    expect(url.toString()).not.toContain("test-client-secret");
    expect(url.searchParams.get("code_verifier")).toBeNull();
  });

  test("generates fresh values per attempt", async ({ request }) => {
    const first = await authorizationRedirect(request);
    const second = await authorizationRedirect(request);

    for (const param of ["state", "nonce", "code_challenge"]) {
      expect(first.searchParams.get(param)).not.toBe(second.searchParams.get(param));
    }
  });

  test("passes prompt through", async ({ request }) => {
    const response = await request.get("/auth/login?prompt=none", { maxRedirects: 0 });
    const url = new URL(response.headers()["location"]);

    expect(url.searchParams.get("prompt")).toBe("none");
  });
});

test.describe("callback", () => {
  test("reports an error returned by the identity provider", async ({ page }) => {
    // The error arrives in the query string, not as a status code, and has to be
    // read before anything looks for a code.
    await page.goto("/auth/callback?error=login_required&error_description=no+active+session");

    await expect(page.getByText("login_required")).toBeVisible();
    await expect(page.getByText("no active session")).toBeVisible();
  });

  test("rejects a callback with no sign-in in progress", async ({ page }) => {
    await page.goto("/auth/callback?code=whatever&state=whatever");

    await expect(page.getByRole("heading", { name: "No sign-in in progress" })).toBeVisible();
  });

  test("rejects a state that does not match the one this session sent", async ({ page, context }) => {
    // Start a real attempt first, so there is a stored state to fail against.
    await context.request.get("/auth/login", { maxRedirects: 0 });

    await page.goto("/auth/callback?code=whatever&state=not-the-stored-one");

    await expect(page.getByRole("heading", { name: "State mismatch" })).toBeVisible();
  });

  test("a replayed callback finds nothing left to match", async ({ page, context }) => {
    const response = await context.request.get("/auth/login", { maxRedirects: 0 });
    const state = new URL(response.headers()["location"]).searchParams.get("state");

    // The pending attempt is cleared on first use, so the correct state only
    // works once - which is what stops a callback URL being replayed.
    await page.goto(`/auth/callback?code=whatever&state=${state}`);
    await expect(page.getByRole("heading", { name: "No sign-in in progress" })).toBeHidden();

    await page.goto(`/auth/callback?code=whatever&state=${state}`);
    await expect(page.getByRole("heading", { name: "No sign-in in progress" })).toBeVisible();
  });
});

test.describe("protected pages", () => {
  test("the dashboard sends a signed-out visitor home", async ({ page }) => {
    await page.goto("/dashboard");

    await expect(page).toHaveURL("http://localhost:3001/");
    await expect(page.getByRole("heading", { name: "Sign in with Nuanu SSO" })).toBeVisible();
  });

  test("refreshing without a session is refused", async ({ request }) => {
    const response = await request.post("/auth/refresh");

    expect(response.status()).toBe(401);
    expect(await response.json()).toMatchObject({ error: "not signed in" });
  });
});

test.describe("logout", () => {
  test("hands the browser to the provider and verifies the state it returns", async ({ page, context }) => {
    const response = await context.request.get("/auth/logout", { maxRedirects: 0 });

    expect(response.status()).toBe(303);

    const url = new URL(response.headers()["location"]);

    expect(`${url.origin}${url.pathname}`).toBe("http://sso.invalid/web/openid/logout");
    expect(url.searchParams.get("post_logout_redirect_uri")).toBe(
      "http://localhost:3001/auth/logout/callback",
    );

    const state = url.searchParams.get("state");
    expect(state).toBeTruthy();

    // The state has to survive the session being cleared, or it can never be
    // checked on the way back.
    await page.goto(`/auth/logout/callback?state=${state}`);

    await expect(page.getByText("state verified")).toBeVisible();
  });

  test("notices a logout state it did not send", async ({ page, context }) => {
    await context.request.get("/auth/logout", { maxRedirects: 0 });

    await page.goto("/auth/logout/callback?state=not-the-one-we-sent");

    await expect(page.getByText("state mismatch")).toBeVisible();
  });
});
