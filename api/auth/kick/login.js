const crypto = require("crypto");

module.exports = function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).send("Method not allowed");
  }

  const clientId = process.env.KICK_CLIENT_ID;
  const redirectUri = process.env.KICK_REDIRECT_URI;

  if (!clientId || !redirectUri) {
    return res.status(500).send("OAuth is not configured");
  }

  const state = crypto.randomBytes(32).toString("hex");
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");

  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  const cookieOptions = `; HttpOnly; SameSite=Lax; Path=/; Max-Age=600${secure}`;

  res.setHeader("Set-Cookie", [
    `kw_oauth_state=${state}${cookieOptions}`,
    `kw_oauth_verifier=${verifier}${cookieOptions}`
  ]);

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
   scope: "user:read channel:read",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256"
  });

  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Location", `https://id.kick.com/oauth/authorize?${params}`);
  return res.status(302).end();
};

