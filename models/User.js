import mongoose from "mongoose";

const refreshTokenSchema = new mongoose.Schema(
  {
    tokenHash: { type: String, required: true }, // store HASH of refresh token
    createdAt: { type: Date, default: Date.now },
  },
  { _id: false }
);

const userSchema = new mongoose.Schema(
  {
    name: { type: String },
    email: { type: String, unique: true, index: true, required: true },
    password: { type: String, required: true },

    // For forgot/reset password
    resetPasswordTokenHash: { type: String },
    resetPasswordExpiry: { type: Date },

    // Multiple device logins allowed; store hashed refresh tokens
    refreshTokens: [refreshTokenSchema],
    role: { type: String, enum: ["user", "admin"], default: "user" }, // for RBAC later
  },
  { timestamps: true }
);

export default mongoose.model("User", userSchema);
