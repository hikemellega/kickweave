
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

  const {
    KICK_CLIENT_ID,
    KICK_CLIENT_SECRET
  } = process.env;

  if (!KICK_CLIENT_ID || !KICK_CLIENT_SECRET) {
    return res.status(500).json({
      error: "Kick credentials not configured"
    });
  }

  try {
    const tokenResponse = await fetch(
      "https://id.kick.com/oauth/token",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded",
          Accept: "application/json"
        },
        body: new URLSearchParams({
          grant_type: "client_credentials",
          client_id: KICK_CLIENT_ID,
          client_secret: KICK_CLIENT_SECRET
        })
      }
    );

    if (!tokenResponse.ok) {
      return res.status(502).json({
        error: "App token request failed",
        status: tokenResponse.status
      });
    }

    const tokenData = await tokenResponse.json();

    if (!tokenData.access_token) {
      return res.status(502).json({
        error: "No app access token returned"
      });
    }

    const url = new URL(
      "https://api.kick.com/public/v1/channels"
    );

    url.searchParams.set("slug", slug);

    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        Accept: "application/json"
      }
    });

    if (!response.ok) {
      return res.status(502).json({
        error: "Kick channels request failed",
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
