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
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
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

//for cleaning up guest accounts
setInterval(
  async () => {
    try {
      const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const result = await User.deleteMany({
        isGuest: true,
        createdAt: { $lt: oneDayAgo },
      });
      console.log(`Cleaned up ${result.deletedCount} guest accounts`);
    } catch (err) {
      console.error("Guest account cleanup error:", err);
    }
  },
  24 * 60 * 60 * 1000,
);

// User Model
const UserSchema = new mongoose.Schema(
  {
    name: String,
    email: { type: String, unique: true, required: true },
    phone: { type: String, unique: true },
    password: { type: String, required: true },
    resetPasswordCode: String,
    resetPasswordExpires: Date,
    avatar: String,
    background: String,
    studyPlans: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "StudyPlan",
      },
    ],
    targetDate: Date,
    targetName: String,
    isGuest: { type: Boolean, default: false },
  },
  { timestamps: true },
);

// StudyPlan Model
const StudyPlanSchema = new mongoose.Schema({
  subject: String,
  topic: String,
  hours: Number,
  daysPerWeek: Number,
  startDate: Date,
  endDate: Date,
  priority: {
    type: String,
    enum: ["low", "medium", "high"],
    default: "medium",
  },
  resources: String,
  milestone: String,
  notes: String,
  completed: {
    type: Boolean,
    default: false,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  progress: {
    type: Number,
    default: 0,
  },
  studiedDays: {
    type: [String],
    default: [],
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },
});

const StudyPlan = mongoose.model("StudyPlan", StudyPlanSchema);

const nodemailer = require("nodemailer");
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
    const { name, email, phone, password } = req.body;

    // Validate input
    if (!name || !email || !phone || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // Check if email or phone already exists
    const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
    if (existingUser) {
      if (existingUser.email === email) {
        return res.status(400).json({ error: "Email already in use" });
      } else {
        return res.status(400).json({ error: "Phone number already in use" });
      }
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      name,
      email,
      phone,
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
        phone: user.phone,
        background: user.background,
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
        background: user.background,
      },
      token,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error during login" });
  }
});

// Guest login endpoint
app.post("/api/guest-login", async (req, res) => {
  try {
    // Create a temporary guest user
    const guestUser = new User({
      name: "Guest User",
      email: `guest-${Date.now()}@example.com`,
      password: await bcrypt.hash(Math.random().toString(36).slice(2), 10),
      isGuest: true,
    });

    await guestUser.save();

    // Generate token
    const token = jwt.sign({ _id: guestUser._id }, process.env.JWT_SECRET, {
      expiresIn: "1d", // Shorter expiration for guest accounts
    });

    res.json({
      user: {
        _id: guestUser._id,
        name: guestUser.name,
        email: guestUser.email,
        isGuest: true,
        avatar: guestUser.avatar,
        background: guestUser.background,
      },
      token,
    });
  } catch (err) {
    console.error("Guest login error:", err);
    res.status(500).json({ error: "Error creating guest account" });
  }
});

// Configure email transporter (add to your server setup)
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// Forgot Password Route
app.post("/api/forgot-password", async (req, res) => {
  console.log("forgot-passwordssss");
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      // Don't reveal whether email exists for security
      return res.json({
        message: "If an account exists, a reset code has been sent",
      });
    }

    // Generate random 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();

    // Set code and expiration (10 minutes from now)
    user.resetPasswordCode = code;
    user.resetPasswordExpires = Date.now() + 600000; // 10 minutes
    await user.save();

    // Verify email configuration
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
      console.log("Reset code (for development):", code);
      return res.json({
        message:
          "Reset code generated (email not sent - missing configuration)",
        code: process.env.NODE_ENV === "development" ? code : undefined,
      });
    }

    // Send email with reset code
    const mailOptions = {
      to: user.email,
      from:
        process.env.EMAIL_FROM ||
        `noreply@${process.env.EMAIL_USER.split("@")[1]}`,
      subject: "Password Reset Code",
      text: `Your password reset code is: ${code}\n\nThis code will expire in 10 minutes.`,
      html: `<p>Your password reset code is: <strong>${code}</strong></p>
             <p>This code will expire in 10 minutes.</p>`,
    };

    console.log("mailOptions: ", mailOptions);

    await transporter.sendMail(mailOptions);

    res.json({ message: "Reset code sent to email" });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({
      error: "Error processing request",
      details: process.env.NODE_ENV === "development" ? err.message : undefined,
    });
  }
});

// Reset Password Route
app.post("/api/reset-password", async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;

    // Find user by email
    const user = await User.findOne({
      email,
      resetPasswordCode: code,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ error: "Invalid or expired reset code" });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password and clear reset fields
    user.password = hashedPassword;
    user.resetPasswordCode = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ error: "Error resetting password" });
  }
});

// Add this route to your server
app.put("/api/user/settings", authenticate, async (req, res) => {
  console.log("setting req: ", req.body);
  try {
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ error: "User not found" });

    const {
      name,
      avatar,
      emailNotifications,
      mobileNotifications,
      background,
    } = req.body;

    if (name) user.name = name;
    if (avatar) user.avatar = avatar;
    if (background !== undefined) user.background = background;

    // Save additional settings if those fields exist in schema
    if (emailNotifications !== undefined)
      user.emailNotifications = emailNotifications;
    if (mobileNotifications !== undefined)
      user.mobileNotifications = mobileNotifications;

    await user.save();

    res.json({
      message: "Settings updated successfully",
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        background: user.background,
      },
    });
  } catch (err) {
    console.error("Settings update error:", err.message, err.errors);
    res.status(500).json({ error: "Error updating settings" });
  }
});

app.get("/api/user", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).populate("studyPlans");
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch (err) {
    console.error("User fetch error:", err);
    res.status(500).json({ error: "Error fetching user data" });
  }
});

app.post("/api/plans", authenticate, async (req, res) => {
  try {
    // Create the plan with the authenticated user's ID
    const planData = { ...req.body, owner: req.user._id };
    const plan = new StudyPlan(planData);
    const savedPlan = await plan.save();

    // Add the plan to the user's studyPlans array
    await User.findByIdAndUpdate(
      req.user._id,
      { $push: { studyPlans: savedPlan._id } },
      { new: true, useFindAndModify: false }, // optional, depending on your Mongoose version
    );

    res.status(201).json(savedPlan);
  } catch (err) {
    console.error("Plan creation error:", err);

    if (err.name === "ValidationError") {
      return res.status(400).json({
        error: "Validation Error",
        details: err.message,
      });
    }

    res.status(500).json({ error: "Error creating study plan" });
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

// Add target date
app.post("/api/target-date", authenticate, async (req, res) => {
  try {
    const { targetDate, targetName } = req.body;

    if (!targetDate || !targetName) {
      return res
        .status(400)
        .json({ error: "Both target date and name are required" });
    }

    req.user.targetDate = targetDate;
    req.user.targetName = targetName;
    await req.user.save();

    res.json({
      message: "Target added successfully",
      targetDate,
      targetName,
    });
  } catch (err) {
    console.error("Target add error:", err);
    res.status(500).json({ error: "Error adding target" });
  }
});

// Update target date
app.put("/api/target-date", authenticate, async (req, res) => {
  try {
    const { targetDate, targetName } = req.body;

    if (!targetDate || !targetName) {
      return res
        .status(400)
        .json({ error: "Both target date and name are required" });
    }

    req.user.targetDate = targetDate;
    req.user.targetName = targetName;
    await req.user.save();

    res.json({
      message: "Target updated successfully",
      targetDate,
      targetName,
    });
  } catch (err) {
    console.error("Target update error:", err);
    res.status(500).json({ error: "Error updating target" });
  }
});

// DELETE endpoint for removing target date
app.delete("/api/target-date", authenticate, async (req, res) => {
  try {
    // Check if target exists before deleting
    if (!req.user.targetDate) {
      return res.status(404).json({ error: "No target date found to delete" });
    }

    // Remove targetDate and targetName fields
    req.user.targetDate = undefined;
    req.user.targetName = undefined;
    await req.user.save();

    res.json({
      message: "Target date deleted successfully",
      deleted: true,
    });
  } catch (err) {
    console.error("Target deletion error:", err);
    res.status(500).json({ error: "Error deleting target date" });
  }
});

// Mark today as studied
app.patch("/api/plans/:planId/mark-day", authenticate, async (req, res) => {
  try {
    const today = new Date();
    const dateStr = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, "0")}-${String(today.getDate()).padStart(2, "0")}`;

    const updatedPlan = await StudyPlan.findOneAndUpdate(
      { _id: req.params.planId, owner: req.user._id },
      { $addToSet: { studiedDays: dateStr } }, // $addToSet = no duplicates ever
      { new: true },
    );

    if (!updatedPlan) {
      return res
        .status(404)
        .json({ error: "Plan not found or no permission." });
    }

    res.json(updatedPlan);
  } catch (err) {
    console.error("Mark day error:", err);
    res.status(500).json({ error: "Error marking day as studied" });
  }
});

// Update study plans
app.put("/api/plans/:planId", authenticate, async (req, res) => {
  try {
    const { planId } = req.params;
    const updates = req.body;

    delete updates.owner;
    delete updates._id;

    const updatedPlan = await StudyPlan.findOneAndUpdate(
      { _id: planId, owner: req.user._id },
      { $set: updates },
      { new: true },
    );

    if (!updatedPlan) {
      return res
        .status(404)
        .json({ error: "Plan not found or you don't have permission." });
    }
    res.json(updatedPlan);
  } catch (err) {
    console.error("Plan update error:", err);
    res.status(500).json({ error: "Error updating plan" });
  }
});

app.delete("/api/plans/:planId", authenticate, async (req, res) => {
  try {
    const { planId } = req.params;
    const plan = await StudyPlan.findOneAndDelete({
      _id: planId,
      owner: req.user._id,
    });

    if (!plan) {
      return res
        .status(404)
        .json({ error: "Plan not found or you don't have permission." });
    }

    await User.findByIdAndUpdate(req.user._id, {
      $pull: { studyPlans: planId },
    });
    res.json({ message: "Plan deleted successfully", planId });
  } catch (err) {
    console.error("Plan deletion error:", err);
    res.status(500).json({ error: "Error deleting plan" });
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
