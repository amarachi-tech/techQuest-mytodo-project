module.exports.asyncErrorhandler = function(fn){
    return async function(req,res,next){
        try{
            await fn(req,res,next)
        }catch(err){
            if(err.name == 'JsonWebTokenError'){
                return res.json({data : null , success : false , message : "invalid token, please log back in"})
            }
            return res.json({data : null , success : false , message : err.message})
        }
    }
}