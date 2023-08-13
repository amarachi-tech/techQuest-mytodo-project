const express = require("express")
const router = express.Router()
const { getCompletedTodos, getOneTodo, getAllTodos, updateAtodo, getIncompletedTodos, addATodo, getMyTodos } = require("../controllers/todoController")
const { isAuthorized } = require("../middleware/authorization")



router.use(express.json())

// @desc get completed todos
router.get("/completed", getCompletedTodos)

// "/incomplete"
router.get("/incomplete", getIncompletedTodos)

// @desc get all todos
router.get("/", getAllTodos)

// @desc Add a todo
router.post("/",isAuthorized, addATodo)

router.get("/mytodos", isAuthorized, getMyTodos)

//@desc get one todo and the user that created it 
router.get("/:_id", getOneTodo)

// update a todo
router.put("/:_id", isAuthorized, updateAtodo)

module.exports = router


