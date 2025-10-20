// controllers/authController.js
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import db from "../db.js";
 // make sure this is default export

// ================= REGISTER USER =================
export const registerUser = async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  // Check if email already exists
  const checkEmailSql = "SELECT * FROM users WHERE email = ?";
  db.query(checkEmailSql, [email], async (err, results) => {
    if (err) return res.status(500).json({ message: "Database error" });
    if (results.length > 0) {
      return res.status(400).json({ message: "Email already registered" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql =
      "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)";
    db.query(sql, [name, email, hashedPassword, role || "user"], (err, result) => {
      if (err) {
        console.error("Registration error:", err);
        return res.status(500).json({ message: "Server error during registration" });
      }
      res.status(201).json({ message: "User registered successfully!" });
    });
  });
};
// ================= LOGIN USER (with auto-register if not found) =================
export const loginUser = async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const cleanEmail = String(email).trim().toLowerCase();

    // 1) Try to find the user
    const sqlFind = "SELECT * FROM users WHERE LOWER(TRIM(email)) = ? LIMIT 1";
    db.query(sqlFind, [cleanEmail], async (err, results) => {
      if (err) {
        console.error("DB error (find user):", err);
        return res.status(500).json({ message: "Database error" });
      }

      // If user exists -> verify password
      if (results && results.length > 0) {
        const user = results[0];
        // normalize PHP $2y$ prefix to $2a$ if needed
        const dbHash = (user.password || "").replace(/^\$2y\$/, "$2a$");
        const match = await bcrypt.compare(password, dbHash);
        if (!match) return res.status(400).json({ message: "Invalid password" });

        const token = jwt.sign(
          { id: user.id, email: user.email, role: user.role || "user" },
          process.env.JWT_SECRET,
          { expiresIn: "1d" }
        );

        return res.json({
          message: "Login successful!",
          token,
          user: { id: user.id, name: user.name, email: user.email, role: user.role || "user" },
        });
      }

      // If not found -> auto-register (create) then return token
      const generatedName = (name && String(name).trim()) || cleanEmail.split("@")[0] || "User";
      const hashedPassword = await bcrypt.hash(password, 10);

      const insertSql = "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)";
      db.query(insertSql, [generatedName, cleanEmail, hashedPassword, "user"], (err2, result2) => {
        if (err2) {
          console.error("DB error (create user):", err2);
          // duplicate email could still occur in race conditions
          if (err2.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ message: "Email already exists" });
          }
          return res.status(500).json({ message: "Database error" });
        }

        const newUserId = result2.insertId;
        const token = jwt.sign({ id: newUserId, email: cleanEmail, role: "user" }, process.env.JWT_SECRET, { expiresIn: "1d" });

        return res.status(201).json({
          message: "User created and logged in",
          token,
          user: { id: newUserId, name: generatedName, email: cleanEmail, role: "user" },
        });
      });
    });
  } catch (e) {
    console.error("loginUser error:", e);
    return res.status(500).json({ message: "Server error" });
  }
};

// ================= LOGIN ADMIN =================
export const loginAdmin = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: "Email and password required" });

  const cleanEmail = String(email).trim().toLowerCase();

  // Helper to compare bcrypt hash safely (handles PHP $2y$ -> $2a$)
  const safeCompare = async (plain, hash) => {
    if (typeof hash !== "string") return false;
    // normalize PHP's $2y$ -> $2a$ (bcryptjs expects $2a$/$2b$)
    const normalized = hash.replace(/^\$2y\$/, "$2a$");
    try {
      return await bcrypt.compare(plain, normalized);
    } catch (e) {
      console.error("bcrypt compare error:", e);
      return false;
    }
  };

  try {
    // 1) Try users table where role = 'admin'
    const sqlUser = "SELECT * FROM users WHERE LOWER(TRIM(email)) = ? AND role = 'admin' LIMIT 1";
    db.query(sqlUser, [cleanEmail], async (err, results) => {
      if (err) {
        console.error("DB error (users):", err);
        return res.status(500).json({ message: "Database error" });
      }

      if (results && results.length > 0) {
        const admin = results[0];
        const match = await safeCompare(password, admin.password);
        if (!match) return res.status(400).json({ message: "Invalid password" });

        const token = jwt.sign({ id: admin.id, email: admin.email, role: admin.role || "admin" }, process.env.JWT_SECRET, { expiresIn: "1d" });
        return res.json({
          message: "Admin login successful!",
          token,
          admin: { id: admin.id, name: admin.name, email: admin.email, role: admin.role || "admin" },
        });
      }

      // 2) If not found in users, try the separate admin table (common in PHP apps)
      const sqlAdmin = "SELECT * FROM admin WHERE LOWER(TRIM(email)) = ? LIMIT 1";
      db.query(sqlAdmin, [cleanEmail], async (err2, results2) => {
        if (err2) {
          console.error("DB error (admin table):", err2);
          return res.status(500).json({ message: "Database error" });
        }
        if (!results2 || results2.length === 0) {
          return res.status(400).json({ message: "Admin not found" });
        }

        const adminRow = results2[0];
        const match2 = await safeCompare(password, adminRow.password);
        if (!match2) return res.status(400).json({ message: "Invalid password" });

        const token = jwt.sign({ id: adminRow.id, email: adminRow.email, role: "admin" }, process.env.JWT_SECRET, { expiresIn: "1d" });
        return res.json({
          message: "Admin login successful!",
          token,
          admin: { id: adminRow.id, name: adminRow.name, email: adminRow.email, role: "admin" },
        });
      });
    });
  } catch (e) {
    console.error("loginAdmin error:", e);
    return res.status(500).json({ message: "Server error" });
  }
};
