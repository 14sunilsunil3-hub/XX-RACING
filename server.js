const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "xxracing_secret_key_2026";
const COOKIE_NAME = "xxr_session";

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// In-memory demo user store (replace with database like MongoDB for production)
const users = {};

function parseCookies(req) {
  const list = {};
  const rc = req.headers.cookie;
  if (!rc) return list;

  rc.split(";").forEach((cookie) => {
    const parts = cookie.split("=");
    const key = parts.shift().trim();
    const val = decodeURIComponent(parts.join("="));
    list[key] = val;
  });
  return list;
}

function signToken(mobile) {
  const payload = Buffer.from(
    JSON.stringify({ mobile: mobile, exp: Date.now() + 24 * 60 * 60 * 1000 })
  ).toString("base64url");

  const sig = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("base64url");

  return `${payload}.${sig}`;
}

function verifySession(req) {
  try {
    const cookies = parseCookies(req);
    const token = cookies[COOKIE_NAME];
    if (!token) return null;

    const parts = token.split(".");
    if (parts.length !== 2) return null;

    const [payload, sig] = parts;
    const expectedSig = crypto
      .createHmac("sha256", SESSION_SECRET)
      .update(payload)
      .digest("base64url");

    if (sig.length !== expectedSig.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) {
      return null;
    }

    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!data || !data.mobile || !data.exp || Date.now() > data.exp) {
      return null;
    }

    return data.mobile;
  } catch (err) {
    return null;
  }
}

function setSessionCookie(res, mobile) {
  const token = signToken(mobile);
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`
  );
}

// Root "/" -> Server checks login status
app.get("/", (req, res) => {
  const loggedInMobile = verifySession(req);
  if (!loggedInMobile) {
    return res.redirect("/auth.html");
  }
  return res.sendFile(path.join(__dirname, "index.html"));
});

// Direct "/index.html" -> Server checks login status
app.get("/index.html", (req, res) => {
  const loggedInMobile = verifySession(req);
  if (!loggedInMobile) {
    return res.redirect("/auth.html");
  }
  return res.sendFile(path.join(__dirname, "index.html"));
});

// "/auth.html" -> If already logged in, server can send index.html or show auth.html
app.get("/auth.html", (req, res) => {
  return res.sendFile(path.join(__dirname, "auth.html"));
});

// API: Current user check
app.get("/api/me", (req, res) => {
  const mobile = verifySession(req);
  if (!mobile) {
    return res.status(401).json({ loggedIn: false });
  }
  return res.json({ loggedIn: true, mobile: mobile });
});

// API: Register
app.post("/api/register", (req, res) => {
  const mobile = String(req.body.mobile || "").trim();
  const password = String(req.body.password || "");
  const confirmPassword = String(req.body.confirmPassword || "");

  if (!/^[0-9]{10}$/.test(mobile)) {
    return res.status(400).json({ ok: false, message: "Valid 10-digit mobile number daalein." });
  }
  if (password.length < 6) {
    return res.status(400).json({ ok: false, message: "Password kam se kam 6 characters ka hona chahiye." });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({ ok: false, message: "Create Password aur Confirm Password match nahi kar rahe hain." });
  }

  users[mobile] = password;
  return res.json({ ok: true, message: "Register successful! Ab Login karein." });
});

// API: Login
app.post("/api/login", (req, res) => {
  const mobile = String(req.body.mobile || "").trim();
  const password = String(req.body.password || "");

  if (!/^[0-9]{10}$/.test(mobile)) {
    return res.status(400).json({ ok: false, message: "Valid 10-digit mobile number daalein." });
  }
  if (!users[mobile]) {
    return res.status(401).json({ ok: false, message: "Ye mobile number registered nahi hai. Pehle Register karein." });
  }
  if (users[mobile] !== password) {
    return res.status(401).json({ ok: false, message: "Galat password! Forgot Password? try karein." });
  }

  setSessionCookie(res, mobile);
  return res.json({ ok: true, redirect: "/index.html", mobile: mobile });
});

// API: Reset Password (Forgot Password popup)
app.post("/api/reset-password", (req, res) => {
  const mobile = String(req.body.mobile || "").trim();
  const otp = String(req.body.otp || "").trim();
  const newPassword = String(req.body.newPassword || "");
  const confirmPassword = String(req.body.confirmPassword || "");

  if (!/^[0-9]{10}$/.test(mobile)) {
    return res.status(400).json({ ok: false, message: "Valid 10-digit mobile number daalein." });
  }
  if (!/^[0-9]{6}$/.test(otp)) {
    return res.status(400).json({ ok: false, message: "Valid 6-digit OTP daalein." });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ ok: false, message: "Password kam se kam 6 characters ka hona chahiye." });
  }
  if (newPassword !== confirmPassword) {
    return res.status(400).json({ ok: false, message: "Password aur Confirm Password match nahi kar rahe hain." });
  }

  users[mobile] = newPassword;
  return res.json({ ok: true, message: "Password reset ho gaya hai! Ab naye password se Login karein." });
});

// API: Logout
app.post("/api/logout", (req, res) => {
  clearSessionCookie(res);
  return res.json({ ok: true, redirect: "/auth.html" });
});

app.listen(PORT, () => {
  console.log(`XXRACING server running at http://localhost:${PORT}`);
});
