const express = require("express")
const { register,login,logout, verifyEmail,resetPassword,forgotPassword} = require("../controller/authController")
const { authenticateUser } = require("../middleware/authentication")
const router = express.Router()

router.route("/register").post(register)
router.route("/login").post(login)
router.delete('/logout',authenticateUser, logout);
router.post('/verify-email', verifyEmail);
router.post("/reset-password",resetPassword);
router.post("/forgot-password",forgotPassword)
module.exports = router