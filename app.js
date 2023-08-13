const express = require("express")
const app = express()
const todosRouter = require("./router/todos")
const userRouter = require("./router/users")
const authRouter = require("./router/authentication")
const { User, Todo } = require("./model/db")
const md5 = require("md5")
const cors = require("cors")
const jwt = require("jsonwebtoken")
const cookieParser = require("cookie-parser")
// express route
// get one todo plus the user
app.use(cors())
app.use(cookieParser())
app.use("/todos", todosRouter)
app.use("/users", userRouter)
app.use("/auth", authRouter)

const PORT = process.env.PORT || 3000
app.listen(PORT, function(){
    console.log("server running on port 3000")
})