
const crypto = require("crypto");

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");

  if (req.method !== "GET") {
    return res.status(405).send("Method not allowed");
  }

  const cookies = Object.fromEntries(
    (req.headers.cookie || "")
      .split(";")
      .map(part => part.trim())
      .filter(Boolean)
      .map(part => {
        const i = part.indexOf("=");
        return [part.slice(0, i), part.slice(i + 1)];
      })
  );

  const clearOAuthCookies = [
    "kw_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
    "kw_oauth_verifier=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
  ];

  const fail = (status, message) => {
    res.setHeader("Set-Cookie", clearOAuthCookies);
    return res.status(status).send(message);
  };

  const { code, state, error } = req.query || {};

  if (error) {
    return fail(400, "Login canceled or denied by Kick.");
  }

  if (
    typeof code !== "string" ||
    typeof state !== "string" ||
    !cookies.kw_oauth_state ||
    !cookies.kw_oauth_verifier
  ) {
    return fail(400, "Invalid or expired OAuth session.");
  }

  const x = Buffer.from(state);
  const y = Buffer.from(cookies.kw_oauth_state);

  if (x.length !== y.length || !crypto.timingSafeEqual(x, y)) {
    return fail(400, "OAuth state validation failed.");
  }

  const {
    KICK_CLIENT_ID,
    KICK_CLIENT_SECRET,
    KICK_REDIRECT_URI,
    KICK_SESSION_SECRET
  } = process.env;

  if (
    !KICK_CLIENT_ID ||
    !KICK_CLIENT_SECRET ||
    !KICK_REDIRECT_URI ||
    !KICK_SESSION_SECRET
  ) {
    return fail(500, "OAuth configuration is incomplete.");
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

    const response = await fetch("https://id.kick.com/oauth/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json"
      },
      body
    });

    if (!response.ok) {
      return fail(502, "Kick token exchange failed.");
    }

    const tokens = await response.json();

    if (!tokens.access_token) {
      return fail(502, "Kick did not return an access token.");
    }

    const { EncryptJWT } = await import("jose");

    const key = crypto
      .createHash("sha256")
      .update(KICK_SESSION_SECRET)
      .digest();

    const session = await new EncryptJWT({
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token || null
    })
      .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
      .setIssuedAt()
      .setExpirationTime("30d")
      .encrypt(key);

    if (Buffer.byteLength(session, "utf8") > 3800) {
      return fail(500, "Session is too large for a cookie.");
    }

    res.setHeader("Set-Cookie", [
      ...clearOAuthCookies,
      `kw_session=${session}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`
    ]);

    return res.redirect(302, "/");
  } catch {
    return fail(502, "Could not complete Kick login.");
  }
};
