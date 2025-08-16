import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import User from "../models/User.js";
import { auth } from "../middleware/auth.js";
import { sendEmail } from "../utils/sendEmail.js";

const router = express.Router();

/* ------------------------ Helpers ------------------------ */

const hashValue = (value) =>
  crypto.createHash("sha256").update(value).digest("hex");

const signAccessToken = (user) =>
  jwt.sign(
    { userId: user._id, role: user.role },
    process.env.JWT_ACCESS_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_TTL || "15m",
    }
  );

const signRefreshToken = (user) =>
  jwt.sign({ userId: user._id }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.REFRESH_TOKEN_TTL || "7d",
  });

/* ------------------------ Register ------------------------ */

router.post("/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email & password required" });

    const exists = await User.findOne({ email });
    if (exists)
      return res.status(400).json({ message: "Email already registered" });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({
      name,
      email,
      password: hashed,
      role: role || "user",
    });

    res.status(201).json({ message: "User registered", userId: user._id });
  } catch (err) {
    res.status(500).json({ message: "Register failed", error: err.message });
  }
});

/* ------------------------ Login ------------------------ */

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: "Invalid credentials" });

    // Create tokens
    const accessToken = signAccessToken(user);
    const refreshToken = signRefreshToken(user);

    // Store HASH of refreshToken in DB (security)
    const tokenHash = hashValue(refreshToken);
    user.refreshTokens.push({ tokenHash });
    await user.save();

    res.json({ accessToken, refreshToken });
  } catch (err) {
    res.status(500).json({ message: "Login failed", error: err.message });
  }
});

/* ------------------------ Refresh Token ------------------------ */

router.post("/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken)
      return res.status(400).json({ message: "No refresh token" });

    let payload;
    try {
      payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET); // { userId, iat, exp }
    } catch {
      return res.status(403).json({ message: "Invalid refresh token" });
    }

    const user = await User.findById(payload.userId);
    if (!user) return res.status(403).json({ message: "User not found" });

    const tokenHash = hashValue(refreshToken);
    const exists = user.refreshTokens.some((t) => t.tokenHash === tokenHash);
    if (!exists)
      return res
        .status(403)
        .json({
          message: "Refresh token not recognized (maybe logged out/rotated)",
        });

    // ROTATE refresh token (best practice)
    // 1) Remove old
    user.refreshTokens = user.refreshTokens.filter(
      (t) => t.tokenHash !== tokenHash
    );
    // 2) Issue new pair
    const newAccessToken = signAccessToken(user);
    const newRefreshToken = signRefreshToken(user);
    user.refreshTokens.push({ tokenHash: hashValue(newRefreshToken) });
    await user.save();

    return res.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Token refresh failed", error: err.message });
  }
});

/* ------------------------ Logout ------------------------ */

router.post("/logout", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken)
      return res.status(400).json({ message: "No refresh token" });

    let payload;
    try {
      payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch {
      // even if invalid, treat as logged out (idempotent)
      return res.json({ message: "Logged out" });
    }

    const user = await User.findById(payload.userId);
    if (user) {
      const tokenHash = hashValue(refreshToken);
      user.refreshTokens = user.refreshTokens.filter(
        (t) => t.tokenHash !== tokenHash
      );
      await user.save();
    }

    res.json({ message: "Logged out" });
  } catch (err) {
    res.status(500).json({ message: "Logout failed", error: err.message });
  }
});

/* ------------------------ Protected Example ------------------------ */

router.get("/profile", auth, async (req, res) => {
  const user = await User.findById(req.user.userId).select(
    "-password -refreshTokens -resetPasswordTokenHash -resetPasswordExpiry"
  );
  res.json({ user });
});

/* ------------------------ Forgot Password ------------------------ */

router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email required" });

    const user = await User.findOne({ email });
    if (!user) {
      // Do NOT reveal that user doesn't exist (privacy). Still say "email sent".
      return res.json({
        message: "If that email exists, a reset link has been sent",
      });
    }

    // Create raw reset token (random), store only HASH in DB
    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = hashValue(rawToken);

    user.resetPasswordTokenHash = tokenHash;
    user.resetPasswordExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    await user.save();

    const resetLink = `${process.env.APP_URL}/reset-password/${rawToken}`;

    await sendEmail({
      to: user.email,
      subject: "Reset your password",
      text: `Click the link to reset your password: ${resetLink}`,
      html: `<p>Click the link to reset your password:</p><p><a href="${resetLink}">${resetLink}</a></p><p>This link expires in 1 hour.</p>`,
    });

    res.json({ message: "If that email exists, a reset link has been sent" });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Failed to send reset link", error: err.message });
  }
});

/* ------------------------ Reset Password ------------------------ */

router.post("/reset-password/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const { newPassword } = req.body;
    if (!newPassword)
      return res.status(400).json({ message: "New password required" });

    const tokenHash = hashValue(token);

    const user = await User.findOne({
      resetPasswordTokenHash: tokenHash,
      resetPasswordExpiry: { $gt: new Date() },
    });

    if (!user)
      return res
        .status(400)
        .json({ message: "Invalid or expired reset token" });

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetPasswordTokenHash = undefined;
    user.resetPasswordExpiry = undefined;

    // Security: revoke all refresh tokens after password change
    user.refreshTokens = [];
    await user.save();

    res.json({ message: "Password reset successful. Please login again." });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Password reset failed", error: err.message });
  }
});

export default router;
