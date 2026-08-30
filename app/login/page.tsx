"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

function safeNext(raw: string | null): string {
  if (raw && raw.startsWith("/") && !raw.startsWith("//")) return raw;
  return "/";
}

export default function LoginPage() {
  const next = useMemo(() => {
    if (typeof window === "undefined") return "/";
    return safeNext(new URLSearchParams(window.location.search).get("next"));
  }, []);
  const [password, setPassword] = useState("");
  const [checking, setChecking] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [authenticated, setAuthenticated] = useState(false);

  // If the session cookie is still valid, offer Continue/Sign out instead of
  // the form (no auto-redirect: /login is the only place to sign out).
  useEffect(() => {
    let cancelled = false;
    fetch("/api/home", { cache: "no-store" })
      .then((res) => {
        if (!cancelled && res.ok) setAuthenticated(true);
      })
      .catch(() => undefined)
      .finally(() => {
        if (!cancelled) setChecking(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleSubmit = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (submitting) return;
      setSubmitting(true);
      setError(null);
      try {
        const res = await fetch("/api/auth/web/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password }),
        });
        if (res.ok) {
          window.location.replace(next);
          return;
        }
        const body = (await res.json().catch(() => null)) as { error?: string } | null;
        setError(res.status === 401 ? "Incorrect password" : (body?.error ?? "Sign-in failed"));
      } catch {
        setError("Sign-in failed");
      } finally {
        setSubmitting(false);
      }
    },
    [next, password, submitting],
  );

  const handleSignOut = useCallback(async () => {
    setSubmitting(true);
    try {
      await fetch("/api/auth/web/logout", { method: "POST" });
    } catch {
      // Cookie stays until it expires; the form still works.
    }
    setAuthenticated(false);
    setSubmitting(false);
    setPassword("");
    setError(null);
  }, []);

  return (
    <main className="flex min-h-dvh items-center justify-center bg-bg p-4 font-mono-font text-text">
      <div className="w-full max-w-sm">
        <div className="mb-6 text-center">
          <h1 className="text-xl font-semibold">Pi Web</h1>
          <p className="mt-1 text-sm text-text-muted">Sign in to continue</p>
        </div>
        <div className="rounded-lg border border-border bg-bg-panel p-6">
          {authenticated ? (
            <div>
              <p className="text-sm">You are already signed in.</p>
              <div className="mt-4 flex gap-2">
                <button
                  type="button"
                  onClick={() => window.location.replace(next)}
                  className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent-hover"
                >
                  Continue
                </button>
                <button
                  type="button"
                  onClick={handleSignOut}
                  disabled={submitting}
                  className="rounded-md border border-border bg-bg px-4 py-2 text-sm text-text transition-colors hover:bg-bg-hover disabled:opacity-50"
                >
                  Sign out
                </button>
              </div>
            </div>
          ) : (
            <form onSubmit={handleSubmit} noValidate={false}>
              <label htmlFor="pi-web-password" className="mb-1 block text-sm font-medium">
                Password
              </label>
              <input
                id="pi-web-password"
                type="password"
                autoFocus
                autoComplete="current-password"
                value={password}
                onChange={(event) => {
                  setPassword(event.target.value);
                  setError(null);
                }}
                disabled={checking || submitting}
                required
                className="w-full rounded-md border border-border bg-bg px-3 py-2 text-sm outline-none transition-colors focus:border-accent disabled:opacity-50"
                placeholder="PI_WEB_PASSWORD"
              />
              {error && <p className="mt-2 text-sm text-red-500">{error}</p>}
              <button
                type="submit"
                disabled={checking || submitting || password.length === 0}
                className="mt-4 w-full rounded-md bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
              >
                {submitting ? "Signing in…" : "Sign in"}
              </button>
            </form>
          )}
        </div>
        <p className="mt-4 text-center text-xs text-text-dim">
          Protected by <code>PI_WEB_PASSWORD</code>
        </p>
      </div>
    </main>
  );
}
