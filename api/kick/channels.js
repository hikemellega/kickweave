
const crypto = require("crypto");

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "GET") {
    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  const slug = req.query.slug;

  if (
    typeof slug !== "string" ||
    !/^[a-zA-Z0-9_-]{2,25}$/.test(slug)
  ) {
    return res.status(400).json({
      error: "Invalid channel name"
    });
  }

  const secret = process.env.KICK_SESSION_SECRET;

  if (!secret) {
    return res.status(500).json({
      error: "Session configuration missing"
    });
  }

  const session = (req.headers.cookie || "")
    .split(";")
    .map(item => item.trim())
    .find(item => item.startsWith("kw_session="))
    ?.slice("kw_session=".length);

  if (!session) {
    return res.status(401).json({
      error: "Not authenticated"
    });
  }

  let accessToken;

  try {
    const { jwtDecrypt } = await import("jose");

    const key = crypto
      .createHash("sha256")
      .update(secret)
      .digest();

    const { payload } = await jwtDecrypt(session, key);

    accessToken = payload.access_token;

    if (typeof accessToken !== "string") {
      throw new Error("Invalid token");
    }
  } catch {
    return res.status(401).json({
      error: "Invalid session"
    });
  }

  try {
    const url = new URL(
      "https://api.kick.com/public/v1/channels"
    );

    url.searchParams.set("slug", slug);

    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json"
      }
    });

    if (!response.ok) {
      return res.status(502).json({
        error: "Kick API request failed",
        status: response.status
      });
    }

    const data = await response.json();

    return res.status(200).json(data);
  } catch {
    return res.status(502).json({
      error: "Could not contact Kick"
    });
  }
};
