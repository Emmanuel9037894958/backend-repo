import express from "express";
import { registerUser, loginUser, loginAdmin } from "../controllers/authController.js";

const router = express.Router();

router.post("/register", registerUser);
router.post("/login", loginUser);        // normal user login
router.post("/admin-login", loginAdmin);

export default router;
