require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json());

// MongoDB Connection (using MongoDB Atlas free tier)
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
    socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => {
    console.error("MongoDB connection error:", err.message);
    process.exit(1); // Exit if DB connection fails
  });

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
  if (!token) return res.status(401).send("Access denied");

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded._id);
    next();
  } catch (err) {
    res.status(401).send("Invalid token");
  }
};

// Routes
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
    res.status(201).send({ user, token });
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
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
  res.send(req.user);
});

app.post("/api/plans", authenticate, async (req, res) => {
  try {
    req.user.studyPlans.push(req.body);
    await req.user.save();
    res.status(201).send(req.user.studyPlans);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

let retries = 5;
const connectWithRetry = () => {
  mongoose
    .connect(process.env.MONGODB_URI, {
      /* options */
    })
    .catch((err) => {
      if (retries-- > 0) {
        console.log(`Retrying connection... (${retries} left)`);
        setTimeout(connectWithRetry, 5000);
      } else {
        console.error("Failed to connect to MongoDB after retries");
        process.exit(1);
      }
    });
};
connectWithRetry();

app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    dbState: mongoose.connection.readyState,
  });
});

app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`);
  next();
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Something broke!" });
});
