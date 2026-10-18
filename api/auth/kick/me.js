
const crypto = require("crypto");

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const secret = process.env.KICK_SESSION_SECRET;

  if (!secret) {
    return res.status(500).json({
      error: "Session configuration missing"
    });
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

  const session = cookies.kw_session;

  if (!session) {
    return res.status(401).json({
      authenticated: false
    });
  }

  try {
    const { jwtDecrypt } = await import("jose");

    const key = crypto
      .createHash("sha256")
      .update(secret)
      .digest();

    const { payload } = await jwtDecrypt(session, key, {
      keyManagementAlgorithms: ["dir"],
      contentEncryptionAlgorithms: ["A256GCM"]
    });

    if (typeof payload.access_token !== "string") {
      throw new Error("Invalid session");
    }

    return res.status(200).json({
      authenticated: true
    });
  } catch {
    return res.status(401).json({
      authenticated: false
    });
  }
};
