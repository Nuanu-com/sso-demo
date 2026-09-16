import { useEffect, useRef, useState } from "preact/hooks";

// Access token lifetime, live. Go renders a static version of this inside the
// island node, so the page is readable before Preact loads and this replaces it
// on mount.
//
// expiresInSeconds is a duration rather than a timestamp on purpose: a browser
// clock a few minutes off a server clock would otherwise show a perfectly good
// token as expired.
export default function SessionStatus({
  expiresInSeconds = 0,
  hasRefreshToken = false,
  refreshPath = "/auth/refresh",
}) {
  const [remaining, setRemaining] = useState(Math.max(0, Math.round(expiresInSeconds)));
  const [status, setStatus] = useState(null);
  const [refreshing, setRefreshing] = useState(false);

  // Anchored to performance.now() rather than counted down tick by tick: an
  // interval that fires late (a backgrounded tab) would otherwise drift.
  const anchor = useRef({ at: performance.now(), from: Math.max(0, Math.round(expiresInSeconds)) });

  useEffect(() => {
    const tick = () => {
      const elapsed = (performance.now() - anchor.current.at) / 1000;
      setRemaining(Math.max(0, Math.round(anchor.current.from - elapsed)));
    };

    tick();

    const timer = setInterval(tick, 1000);

    return () => clearInterval(timer);
  }, []);

  async function refresh() {
    setRefreshing(true);
    setStatus(null);

    try {
      const response = await fetch(refreshPath, {
        method: "POST",
        headers: { Accept: "application/json" },
        // The session cookie is what identifies which refresh token to rotate.
        credentials: "same-origin",
      });

      const body = await response.json();

      if (!response.ok) {
        setStatus({ tone: "error", text: body.error ?? `refresh failed (${response.status})` });
        return;
      }

      anchor.current = { at: performance.now(), from: body.expires_in };
      setRemaining(body.expires_in);
      setStatus({
        tone: "ok",
        text: body.rotated_refresh
          ? "Refreshed. The refresh token rotated - the previous one is now dead."
          : "Refreshed.",
      });
    } catch (error) {
      setStatus({ tone: "error", text: String(error) });
    } finally {
      setRefreshing(false);
    }
  }

  const expired = remaining <= 0;

  return (
    <div class="rounded-lg border border-border p-4">
      <div class="flex flex-wrap items-center justify-between gap-4">
        <div class="grid gap-1">
          <p class="text-sm text-muted-foreground">Access token expires in</p>
          <p class={`font-mono text-2xl ${expired ? "text-destructive" : ""}`}>
            {expired ? "expired" : formatDuration(remaining)}
          </p>
        </div>

        <div class="flex items-center gap-3">
          {hasRefreshToken ? (
            <button type="button" class="btn" data-variant="outline" onClick={refresh} disabled={refreshing}>
              {refreshing ? "Refreshing…" : "Refresh now"}
            </button>
          ) : (
            <p class="text-sm text-muted-foreground">No refresh token in this session.</p>
          )}
        </div>
      </div>

      {status && (
        <p class={`mt-3 text-sm ${status.tone === "error" ? "text-destructive" : "text-muted-foreground"}`}>
          {status.text}
        </p>
      )}
    </div>
  );
}

function formatDuration(totalSeconds) {
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;

  if (minutes >= 60) {
    const hours = Math.floor(minutes / 60);
    return `${hours}h ${String(minutes % 60).padStart(2, "0")}m`;
  }

  return `${minutes}:${String(seconds).padStart(2, "0")}`;
}
