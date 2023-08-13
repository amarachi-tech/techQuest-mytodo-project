const bcrypt = require("bcryptjs")
const { asyncErrorhandler } = require("../Errorhandler/asyncerrorhandler")
const { User } = require("../model/db")
const jwt = require("jsonwebtoken")
const fs = require("fs")
require("dotenv").config()


module.exports.createUser = asyncErrorhandler(async(req,res)=>{
    const {password, ...others} = req.body
    if(password.length < 6  || password.length > 15) return res.json({message : "password length must be less than 15 and greater than 5", success : false})
    const salt = await bcrypt.genSalt(3)
    const hashedPassword = await bcrypt.hash(password, salt)
    const newUser = {password:hashedPassword, ...others}
    const user = await User.create(newUser);
    // after user has succefully been created now we want to create a token
    // we want create a token to identify this user across our application:
    // jwt create token using sign
    const token = jwt.sign({_id : user._id }, process.env.JWTSECRET)
    res.cookie("authorization", token)
    return res.json ({data: user, message: "new user created"})
})


module.exports.login = asyncErrorhandler(async(req,res)=>{
    //access username and password from req.body
    const {username, password} = req.body
    //find the user with the username
    const user = await User.findOne({username})
    //if no user with the username is found send an error message
    if(!user) return res.json({data: null, message: "no user found"})
    //compare the entered password with the users existin password
    const check = await bcrypt.compare(password, user.password)
    //return an error message if password not match
    if(!check) return res.json({data: null, message: "authentication failed"})

    // anything here would run if the password match
    const token = jwt.sign({_id : user._id }, process.env.JWTSECRET)
    res.cookie("authorization", token)
    return res.json({message : "succesfully logged in", success : true})
})

module.exports.logout = asyncErrorhandler(async function(_,res){
    //logout a user
    res.cookie("authorization", "", {maxAge : 1})
    return res.json({message : "Succesfully logged out", success : true})
})



//change password

module.exports.changePassword = asyncErrorhandler(async function(req, res){
    if(req.body.password.length < 6) return res.status(401).json({message: "Password most be greater than 6", success: false})
    //hashpassword using bcrypt
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    //upadate the new password after passwor is hashed
    await User.updateOne({_id: req.user._id}, {password: hashedPassword})
    return res.status(200).json({message: "successfully Update", success: true})
})