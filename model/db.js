const mongoose = require("mongoose")
require("dotenv").config()

const todoSchema = new mongoose.Schema({
    task : String,
    completed : {type : Boolean, default : false},
    userId :  {type : mongoose.Schema.ObjectId, ref : "user", required : [true, "all todos must be posted by a user"]},
})

const userSchema = new mongoose.Schema({
    name : String,
    username : {type : String, required : [true, "username must be provided"], unique : true},
    password : {type : String, minLength : [6, "cannot save {VALUE} in {PATH}"], required : [true, "password must be provided"] },
    todos :  [{type : mongoose.Schema.ObjectId, ref : "todo"}],
    updatedpassword: {type: Date, default: Date.now()}
})

module.exports.User = new mongoose.model("user", userSchema)
module.exports.Todo = new mongoose.model("todo", todoSchema)


mongoose.connect(process.env.MONGODBURL)
.then(()=> console.log(" database running"))

