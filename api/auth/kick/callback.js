const crypto = require("crypto");

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).send("Method not allowed");
  }

  const cookies = Object.fromEntries(
    (req.headers.cookie || "")
      .split(";")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const i = part.indexOf("=");
        return [part.slice(0, i), part.slice(i + 1)];
      })
  );

  const clearCookies = [
    "kw_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
    "kw_oauth_verifier=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
  ];

  const cleanup = () => res.setHeader("Set-Cookie", clearCookies);

  const { code, state, error } = req.query || {};

  if (error) {
    cleanup();
    return res.status(400).send("Login canceled or denied by Kick.");
  }

  if (
    typeof code !== "string" ||
    typeof state !== "string" ||
    !cookies.kw_oauth_state ||
    !cookies.kw_oauth_verifier
  ) {
    cleanup();
    return res.status(400).send("Invalid or expired OAuth session. Please try again.");
  }

  const safeEqual = (a, b) => {
    const x = Buffer.from(a);
    const y = Buffer.from(b);
    return x.length === y.length && crypto.timingSafeEqual(x, y);
  };

  if (!safeEqual(state, cookies.kw_oauth_state)) {
    cleanup();
    return res.status(400).send("OAuth state validation failed. Please try again.");
  }

  const { KICK_CLIENT_ID, KICK_CLIENT_SECRET, KICK_REDIRECT_URI } = process.env;

  if (!KICK_CLIENT_ID || !KICK_CLIENT_SECRET || !KICK_REDIRECT_URI) {
    cleanup();
    return res.status(500).send("OAuth configuration is incomplete.");
  }

  try {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: KICK_CLIENT_ID,
      client_secret: KICK_CLIENT_SECRET,
      redirect_uri: KICK_REDIRECT_URI,
      code,
      code_verifier: cookies.kw_oauth_verifier
    });

    const tokenResponse = await fetch("https://id.kick.com/oauth/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
      },
      body
    });

    if (!tokenResponse.ok) {
      cleanup();
      return res.status(502).send("Kick token exchange failed. Please try again.");
    }

    const tokens = await tokenResponse.json();

    if (!tokens.access_token) {
      cleanup();
      return res.status(502).send("Kick did not return an access token.");
    }

    // Do not expose tokens to the browser or log them.
    // Secure server-side session storage must be added before production use.
    cleanup();
    return res.status(200).send(
      "Kick authorization succeeded. Secure session storage is not configured yet; no login session was saved. You may close this page."
    );
  } catch {
    cleanup();
    return res.status(502).send("Could not contact Kick. Please try again.");
  }
};

