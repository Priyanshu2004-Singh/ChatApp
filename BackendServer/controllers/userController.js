import { User } from "../modals/user.modal.js";
import bcrypt from "bcrypt";
import { addRegisterLog } from "../logs/registerLogs.js";

export const registerUser = async (req, res) => {
  try {
    const body = req.body || {};
    // Accept either `userName` (client) or `name` (server) fields
    const userName = body.userName ?? body.name ?? "";
    const email = body.email ?? "";
    const password = body.password ?? "";

    // Basic validation
    if (!userName || !email || !password) {
      return res
        .status(400)
        .json({ message: "Username, email and password are required" });
    }

    // Check if user already exists
    const existing = await User.findOne({ email: email.trim().toLowerCase() });
    if (existing) {
      return res
        .status(409)
        .json({ message: "User with this email already exists" });
    }

    // Create and save user - password hashing is handled in the model pre-save hook
    const user = new User({
      userName: userName.trim(),
      email: email.trim().toLowerCase(),
      password,
    });
    const saved = await user.save();

    // Return sanitized user (exclude password)
    const { _id } = saved;

    // Best-effort: write a registration log entry (doesn't block or fail the request on error)
    try {
      const logEntry = {
        id: _id,
        userName: saved.userName,
        email: saved.email,
        timestamp: new Date().toISOString(),
        ip:
          req.ip ||
          req.headers?.["x-forwarded-for"] ||
          req.connection?.remoteAddress ||
          null,
      };
      // fire-and-forget; addRegisterLog handles errors internally
      addRegisterLog(logEntry).catch((err) =>
        console.error("Register log error:", err)
      );
    } catch (e) {
      console.error("Error preparing register log:", e);
    }

    return res.status(201).json({
      message: "User Registered Successfully",
      user: { id: _id, userName: saved.userName, email: saved.email },
    });
  } catch (error) {
    console.error("Error registering user:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const loginUser = async (req, res) => {
  try {
    const body = req.body || {};
    const email = body.email ?? "";
    const password = body.password ?? "";

    // Basic validation
    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    // Find user by email
    const user = await User.findOne({ email: email.trim().toLowerCase() });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(401)
        .json({ message: "Email or password is incorrect" });
    }

    // Return sanitized user (exclude password)
    const { _id, userName } = user;
    console.log(user);
    return res.status(200).json({
      message: "Login Successful",
      user: { id: _id, userName, email: user.email },
    });
  } catch (error) {
    console.error("Error logging in user:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};
