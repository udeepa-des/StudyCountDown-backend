require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

// CORS Configuration
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json());

// MongoDB Connection with Retry Logic
const connectWithRetry = () => {
  console.log("Attempting MongoDB connection...");
  mongoose
    .connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    })
    .then(() => console.log("Connected to MongoDB"))
    .catch((err) => {
      console.error("MongoDB connection error:", err.message);
      if (retries-- > 0) {
        console.log(`Retrying connection... (${retries} left)`);
        setTimeout(connectWithRetry, 5000);
      } else {
        console.error("Failed to connect to MongoDB after retries");
        process.exit(1);
      }
    });
};

let retries = 5; // Note: Fixed typo from 'retries' to 'retries'
connectWithRetry();

// User Model
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  studyPlans: [
    {
      subject: String,
      hours: Number,
      milestone: String,
      completed: Boolean,
    },
  ],
  targetDate: Date,
});

const User = mongoose.model("User", UserSchema);

// Auth Middleware
const authenticate = async (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "Access denied" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded._id);
    if (!req.user) return res.status(401).json({ error: "User not found" });
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
};

// Routes
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
    res.status(201).json({ user, token });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({ error: "Email already exists" });
    }
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
    res.json({ user, token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error during login" });
  }
});

app.get("/api/user", authenticate, async (req, res) => {
  res.json(req.user);
});

app.post("/api/plans", authenticate, async (req, res) => {
  try {
    req.user.studyPlans.push(req.body);
    await req.user.save();
    res.status(201).json(req.user.studyPlans);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Health Check Endpoint
app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    dbState: mongoose.connection.readyState,
    timestamp: new Date().toISOString(),
  });
});

// Request Logger
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`);
  next();
});

// Error Handling Middleware (must be last)
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Internal server error" });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
