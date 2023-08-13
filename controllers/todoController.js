const { Todo, User } = require("../model/db")
const {asyncErrorhandler} = require("../Errorhandler/asyncerrorhandler")
const jwt = require("jsonwebtoken")
module.exports.getCompletedTodos =  asyncErrorhandler(async function(req,res){
    const todos = await Todo.find({completed : true})
    res.json({data : todos, success: true})
})

module.exports.getIncompletedTodos =  asyncErrorhandler(async function(req,res){
    const todos = await Todo.find({completed : false})
    res.json({data : todos, success: true})
})

module.exports.getOneTodo = asyncErrorhandler( async function(req,res){
        const todo = await Todo.findById(req.params._id).populate("userId", "-password")  
       return res.json({data : todo, success : true})
})  
// 64be5e53ab0db32e13ced284
module.exports.getAllTodos = asyncErrorhandler(async function(req,res){
       const todos = await Todo.find({})
       res.json({data : todos, success : true})
})

// get the todos of this particular user 
module.exports.getMyTodos = asyncErrorhandler(async function(req,res){
    //   this would run if the user exists
      return res.json({data: req.user.todos, message : `this is the todos of ${req.user.username}`, success : true})
})


/*
WHAT WE ARE SENDING [EXPECTING FROM req.body]
{
    "task" : "Buy mercedes",
    "userId" : "64bf95676076529a9a234527"
}
*/
module.exports.addATodo = asyncErrorhandler(async function(req,res){
    const newTodo = await Todo.create({...req.body, userId: req.user._id})
    await User.updateOne({_id : req.user._id}, {$push : {todos : newTodo._id}})
    res.json({message : "successfully created", success : true})
})

module.exports.updateAtodo = asyncErrorhandler(async function(req, res){
    // check if the todo belongs to the user
        //find a todo using its id from database
        const todo = await Todo.findOne({_id : req.params._id, userId : req.user._id})
        //return error message if no todo found
        if(!todo) return res.json({message: "You are unauthorized to update this todo", success: false})
        //update the todo if found
        await Todo.updateOne({_id: req.params._id}, req.body)
        return res.json({message: "todo updated successfully", success: true})
})



