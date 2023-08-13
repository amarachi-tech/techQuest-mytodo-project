const express = require("express")
const { login, createUser, logout, changePassword } = require("../controllers/authController")
const router = express.Router()

router.use(express.json())
router.post("/register", createUser)

router.post("/login", login)

router.post("/changepass", changePassword)

router.get("/logout", logout)
module.exports = router