import "dotenv/config.js";
import express from "express";
import { connectDB } from "./config/db.js";
import authRoutes from "./routes/auth.js";

const app = express();

app.use(express.json());
app.use("/api/auth", authRoutes);

// Health check
app.get("/", (req, res) => {
  res.send("Auth API is running");
});

const start = async () => {
  await connectDB();
  const port = process.env.PORT || 3000;
  app.listen(port, () =>
    console.log(`Server running on http://localhost:${port}`)
  );
};

start();
