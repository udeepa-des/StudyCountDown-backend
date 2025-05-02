require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

// Enhanced CORS Configuration
const allowedOrigins = [
  "https://mindstreamer.netlify.app",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://localhost:5000",
  "http://127.0.0.1:5000",
];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
  optionsSuccessStatus: 200,
};

// Apply CORS middleware
app.use(cors(corsOptions));
app.options("/", cors(corsOptions));
app.use(express.json());

// MongoDB Connection with Retry Logic
const connectWithRetry = () => {
  console.log("Attempting MongoDB connection...");
  const mongoURI = process.env.MONGODB_URI || "";

  mongoose
    .connect(mongoURI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    })
    .then(() => console.log("Connected to MongoDB"))
    .catch((err) => {
      console.error("MongoDB connection error:", err.message);
      console.log("Retrying connection in 5 seconds...");
      setTimeout(connectWithRetry, 5000);
    });
};

connectWithRetry();

// User Model
const UserSchema = new mongoose.Schema(
  {
    name: String,
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    avatar: String,
    studyPlans: [
      {
        subject: String,
        hours: Number,
        milestone: String,
        completed: Boolean,
      },
    ],
    targetDate: Date,
  },
  { timestamps: true }
);

const User = mongoose.model("User", UserSchema);

// Auth Middleware
const authenticate = async (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token)
    return res.status(401).json({ error: "Access denied. No token provided." });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded._id);

    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
};

// Routes
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validate input
    if (!name || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already in use" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      name,
      email,
      password: hashedPassword,
    });

    await user.save();

    // Generate token
    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.status(201).json({
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
      },
      token,
    });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ error: "Server error during registration" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate token
    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
      },
      token,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error during login" });
  }
});

// Add this route to your server
app.put("/api/user/settings", authenticate, async (req, res) => {
  try {
    const { name, avatar, emailNotifications, mobileNotifications } = req.body;

    if (name) req.user.name = name;
    if (avatar) req.user.avatar = avatar;
    // Add other settings you want to update

    await req.user.save();

    res.json({
      message: "Settings updated successfully",
      user: {
        _id: req.user._id,
        name: req.user.name,
        email: req.user.email,
        avatar: req.user.avatar,
      },
    });
  } catch (err) {
    console.error("Settings update error:", err);
    res.status(500).json({ error: "Error updating settings" });
  }
});

app.get("/api/user", authenticate, async (req, res) => {
  try {
    res.json({
      _id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      avatar: req.user.avatar,
      studyPlans: req.user.studyPlans,
      targetDate: req.user.targetDate,
    });
  } catch (err) {
    console.error("User fetch error:", err);
    res.status(500).json({ error: "Error fetching user data" });
  }
});

app.post("/api/plans", authenticate, async (req, res) => {
  try {
    req.user.studyPlans.push(req.body);
    await req.user.save();
    res.status(201).json(req.user.studyPlans);
  } catch (err) {
    console.error("Plan creation error:", err);
    res.status(400).json({ error: err.message });
  }
});

app.get("/api/users/:userId", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Health Check Endpoint
app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    dbState: mongoose.connection.readyState,
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
  });
});

// Update target date
app.put("/api/target-date", authenticate, async (req, res) => {
  try {
    const { targetDate } = req.body;
    req.user.targetDate = targetDate;
    await req.user.save();
    res.json({ message: "Target date updated successfully", targetDate });
  } catch (err) {
    console.error("Target date update error:", err);
    res.status(500).json({ error: "Error updating target date" });
  }
});

// Update study plans
app.put("/api/plans", authenticate, async (req, res) => {
  try {
    req.user.studyPlans = req.body;
    await req.user.save();
    res.json({
      message: "Study plans updated successfully",
      plans: req.user.studyPlans,
    });
  } catch (err) {
    console.error("Study plans update error:", err);
    res.status(500).json({ error: "Error updating study plans" });
  }
});

// Request Logger
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(err.stack);

  // Handle CORS errors
  if (err.message === "Not allowed by CORS") {
    return res.status(403).json({
      error: "CORS policy: Origin not allowed",
      allowedOrigins: allowedOrigins,
    });
  }

  // Handle other errors
  res.status(500).json({
    error: "Internal server error",
    message: err.message,
  });
});

// Start server
const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || "0.0.0.0";

const server = app.listen(PORT, HOST, () => {
  console.log(`Server running on http://${HOST}:${PORT}`);
  console.log(`Allowed CORS origins: ${allowedOrigins.join(", ")}`);
});

// Handle server errors
server.on("error", (error) => {
  console.error("Server error:", error);

  if (error.code === "EADDRINUSE") {
    console.error(`Port ${PORT} is already in use`);
  }

  process.exit(1);
});

// Handle process termination
process.on("SIGINT", () => {
  console.log("Shutting down server...");
  server.close(() => {
    mongoose.connection.close(false, () => {
      console.log("MongoDB connection closed");
      process.exit(0);
    });
  });
});
