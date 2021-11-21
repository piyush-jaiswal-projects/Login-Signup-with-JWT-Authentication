
const jwt = require('jsonwebtoken'); //jsonwebtoken module
const { refresh } = require("./control"); //importing refresh function 


//function to authenticate incoming request from client
exports.verify = function (req, res, next) {
    let accessToken = req.cookies.jwt;

    if (!accessToken) {
        console.log(">> Attempt of unauthorized access detected.");
        return res.status(403).send("<h1>Unauthorized Access!</h1><br><h2>Please sign up or login.</h2>");
    }

    let payload;
    //verifying access token 
    try {
        payload = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
        next(); //middleware function
    }
    catch (e) {
        console.log(">> Access"+e.name + "----middleware");  //catching error and its type
        if (e.name == "TokenExpiredError") {
            refresh(req, res);                  // function to re-issue access token
        }
    }
}
