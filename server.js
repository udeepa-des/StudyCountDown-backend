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
    notificationEmail: String,
    // phone: { type: String, unique: true },
    password: { type: String, required: true },
    resetPasswordCode: String,
    resetPasswordExpires: Date,
    avatar: String,
    background: String,
    reminders: [
      {
        id: String,
        label: String,
        date: String,
        time: String,
        advanceNotice: String,
        advanceUnit: String,
        isActive: Boolean,
        triggered: Boolean,
        createdAt: Date,
      },
    ],
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
    const { name, email, password } = req.body;

    // Validate input
    if (!name || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // Check if email or phone already exists
    const existingUser = await User.findOne({ $or: [{ email }] });
    if (existingUser) {
      if (existingUser.email === email) {
        return res.status(400).json({ error: "Email already in use" });
      }
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

app.get("/api/reminders", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(user.reminders || []);
  } catch (err) {
    console.error("Error fetching reminders:", err);
    res.status(500).json({ error: "Error fetching reminders" });
  }
});

app.post("/api/reminders", authenticate, async (req, res) => {
  try {
    const { reminders } = req.body;

    if (!Array.isArray(reminders)) {
      return res.status(400).json({ error: "Reminders must be an array" });
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Update user's reminders
    user.reminders = reminders;
    await user.save();

    res.json({
      message: "Reminders saved successfully",
      reminders: user.reminders,
    });
  } catch (err) {
    console.error("Error saving reminders:", err);
    res.status(500).json({ error: "Error saving reminders" });
  }
});

app.post("/api/reminders/add", authenticate, async (req, res) => {
  try {
    const reminder = req.body;

    if (!reminder.label || !reminder.date) {
      return res.status(400).json({ error: "Label and date are required" });
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Add new reminder with timestamp
    const newReminder = {
      ...reminder,
      createdAt: new Date().toISOString(),
      triggered: false,
    };

    user.reminders.push(newReminder);
    await user.save();

    res.json({
      message: "Reminder added successfully",
      reminder: newReminder,
    });
  } catch (err) {
    console.error("Error adding reminder:", err);
    res.status(500).json({ error: "Error adding reminder" });
  }
});

app.put("/api/reminders/:reminderId", authenticate, async (req, res) => {
  try {
    const { reminderId } = req.params;
    const updates = req.body;

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Find and update the reminder
    const reminderIndex = user.reminders.findIndex((r) => r.id === reminderId);
    if (reminderIndex === -1) {
      return res.status(404).json({ error: "Reminder not found" });
    }

    user.reminders[reminderIndex] = {
      ...user.reminders[reminderIndex],
      ...updates,
    };
    await user.save();

    res.json({
      message: "Reminder updated successfully",
      reminder: user.reminders[reminderIndex],
    });
  } catch (err) {
    console.error("Error updating reminder:", err);
    res.status(500).json({ error: "Error updating reminder" });
  }
});

// Delete a reminder
app.delete("/api/reminders/:reminderId", authenticate, async (req, res) => {
  try {
    const { reminderId } = req.params;

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Remove the reminder
    user.reminders = user.reminders.filter((r) => r.id !== reminderId);
    await user.save();

    res.json({
      message: "Reminder deleted successfully",
      reminders: user.reminders,
    });
  } catch (err) {
    console.error("Error deleting reminder:", err);
    res.status(500).json({ error: "Error deleting reminder" });
  }
});

// Toggle reminder active status
app.patch(
  "/api/reminders/:reminderId/toggle",
  authenticate,
  async (req, res) => {
    try {
      const { reminderId } = req.params;

      const user = await User.findById(req.user._id);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const reminder = user.reminders.find((r) => r.id === reminderId);
      if (!reminder) {
        return res.status(404).json({ error: "Reminder not found" });
      }

      reminder.isActive = !reminder.isActive;
      await user.save();

      res.json({
        message: "Reminder toggled successfully",
        reminder,
      });
    } catch (err) {
      console.error("Error toggling reminder:", err);
      res.status(500).json({ error: "Error toggling reminder" });
    }
  },
);

app.post("/api/send-reminder", authenticate, async (req, res) => {
  try {
    const { reminderId, label, targetName, targetDate, reminderTime } =
      req.body;
    const user = req.user;

    const notificationEmail = user.notificationEmail || user.email;

    // Calculate time remaining
    const now = new Date();
    const target = new Date(targetDate);
    const diffTime = target - now;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    const notifications = [];
    let emailSent = false;

    // Send Email notification
    if (notificationEmail && user.emailNotifications !== false) {
      try {
        const mailOptions = {
          to: notificationEmail,
          from:
            process.env.EMAIL_FROM ||
            `noreply@${process.env.EMAIL_USER.split("@")[1]}`,
          subject: `⏰ Reminder: ${label || targetName} is approaching!`,
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #4361ee;">⏰ Reminder Alert</h2>
              <p>Hello ${user.name || "User"},</p>
              <p>This is a reminder for: <strong>"${label || targetName}"</strong></p>
              <div style="background: #f0f4ff; padding: 20px; border-radius: 10px; margin: 20px 0;">
                <p style="margin: 0; font-size: 24px; font-weight: bold; color: #4361ee;">
                  ${diffDays > 0 ? `${diffDays} days remaining` : "Today!"}
                </p>
              </div>
              <p>Date & Time: ${new Date(targetDate).toLocaleString()}</p>
              <p>Reminder: ${reminderTime || "At event time"}</p>
              <p style="color: #666; font-size: 14px;">Stay focused and keep working towards your goal!</p>
              <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;" />
              <p style="color: #999; font-size: 12px;">This is an automated reminder from MindStreamer.</p>
            </div>
          `,
          text: `⏰ Reminder Alert: ${label || targetName}\n\n${diffDays > 0 ? `${diffDays} days remaining` : "Today!"}\nDate & Time: ${new Date(targetDate).toLocaleString()}\nReminder: ${reminderTime || "At event time"}`,
        };

        await transporter.sendMail(mailOptions);
        emailSent = true;
        notifications.push({ type: "email", sent: true });
      } catch (err) {
        console.error("Email sending failed:", err);
        notifications.push({ type: "email", sent: false, error: err.message });
      }
    }

    res.json({
      message: "Reminder processed",
      emailSent,
      details: notifications,
    });
  } catch (err) {
    console.error("Reminder error:", err);
    res.status(500).json({
      error: "Error sending reminder",
      details: process.env.NODE_ENV === "development" ? err.message : undefined,
    });
  }
});

// Add this route to your server
app.put("/api/user/settings", authenticate, async (req, res) => {
  console.log("settings req: ", req.body);
  try {
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ error: "User not found" });

    const { name, avatar, email, emailNotifications, background } = req.body;

    if (name) user.name = name;
    if (avatar) user.avatar = avatar;
    if (background !== undefined) user.background = background;

    if (email !== undefined) {
      user.notificationEmail = email;
    }

    // if (email && email !== user.email) {
    //   const existingUser = await User.findOne({ email });
    //   if (existingUser && existingUser._id.toString() !== user._id.toString()) {
    //     return res.status(400).json({ error: "Email already in use" });
    //   }
    //   user.email = email;
    // }

    if (emailNotifications !== undefined)
      user.emailNotifications = emailNotifications;

    await user.save();

    res.json({
      message: "Settings updated successfully",
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        notificationEmail: user.notificationEmail,
        avatar: user.avatar,
        background: user.background,
        emailNotifications: user.emailNotifications,
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

    const userData = user.toObject();
    userData.notificationEmail = user.notificationEmail || user.email;
    userData.reminders = user.reminders || [];
    res.json(userData);
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
