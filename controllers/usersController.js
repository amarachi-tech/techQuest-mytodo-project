const { asyncErrorhandler } = require("../Errorhandler/asyncerrorhandler");
const { User } = require("../model/db");
const jwt = require("jsonwebtoken")

module.exports.getAllUsers = asyncErrorhandler(async function(req,res){
    const users = await User.find()
    return res.json({data : users, success : true})
})

module.exports.getAUser = asyncErrorhandler(async function(req,res){
    const username = req.params.id
    const user = await User.findOne({username}, "-password -_id").populate("todos")
    return res.json({data : user, success : true}) 
})

module.exports.getMyProfile = asyncErrorhandler(async function(req,res, next){

    return res.json({data: req.user, message : "this should be your profile", success : true})
})
