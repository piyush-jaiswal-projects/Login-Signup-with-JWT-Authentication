
require('dotenv').config()
const mongoose = require("mongoose");  //importing mongoose
const jwt = require("jsonwebtoken");

//connecting to database
mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });

const userSchema = {  //defining schema for our data
    username: String,
    password: String,
    refreshToken: String
};

const User = mongoose.model("User", userSchema);


//login function: handles user login
exports.login = function (req, res) {

    const userName = req.body.username;
    const passWord = req.body.password;

    //ensuring no blank request
    if (userName == null || passWord == null) {

        console.log(">> Attempt of unauthorized access detected.");
        res.status(401).send("<h2>Unauthorized Access!</h2>");

    }
    else {

        //checking if user already registered 
        User.findOne({ username: userName }, function (err, foundUser) {

            if (foundUser) {
                if (foundUser.password == passWord) {  //checking password
                    console.log(">> User login detected: " + foundUser.username);
                    issueTokens(req, res);             //function to issue tokens
                    res.send("<h2>Login Success!</h2><br> --verified--");

                } else {
                    console.log(">> Attempt of unauthorized access detected.");
                    res.status(401).send("<h2>Unauthorized Access!</h2><br>Invalid password.");
                }
            } else {
                res.send("<h2>Username not registered, please Sign Up.</h2>");
            }
        });
    }

}


//signup function: handles signup operation
exports.signup = function (req, res) {
    User.findOne({ username: req.body.username }, function (err, foundUser) {
        if (!foundUser) {  //ensuring no duplicate entry or signup              

            //creating new user document
            const newUser = new User({
                username: req.body.username,
                password: req.body.password
            });

            newUser.save(function (errors) {   //saving user data to database
                if (!errors) {
                    res.send("<h2>Successfully registered.</h2>")
                    console.log(">> New User Registered Successfully:  " + req.body.username);
                } else {
                    res.send("<h2>Registration failed</h2>");
                }
            });
        }
        else {
            res.send("<h2>Already registered. Please login.</h2>");
        }
    })

}


//function to re-issue access token when it gets expired
exports.refresh = function (req, res) {

    let accessToken = req.cookies.jwt;

    if (!accessToken) {   //checks whether access token exists or not
        console.log(">> Attempt of unauthorized access detected.");
        return res.status(403).send("<h2></h2>Unauthorized Access</h2>");
    }

    User.findOne(
        { username: req.body.username }, function (err, foundUser) { //looking for refresh token in database
            if (foundUser) {
                refreshToken = foundUser.refreshToken;

                //verifying the refresh token
                try {
                    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
                }
                catch (e) {
                    console.log(">> Verifying Refresh Token Error:" + e); //catching and logging error
                    console.log(">> Attempt of unauthorized access detected.");
                    return res.status(401).send("<h2>Unauthorized Access</h2>");
                }

            } else {
                console.log(">> Attempt of unauthorized access detected.");
                res.status(401).send("<h2>Unauthorized Access</h2>");
            }
        }

    )

    let payload = { username: req.body.username };
    let newToken = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, //creating new access Token
        {
            algorithm: "HS256",
            expiresIn: process.env.ACCESS_TOKEN_LIFE
        });
    //secure: true can be added
    res.cookie("jwt", newToken, { httpOnly: true });
    console.log(">> New Access Token Issued. User can continue accessing protected content.");
    console.log(">> New Access Token : " + newToken);

    //redirecting user to protectedContent after new access token issued
    res.redirect("/protectedContent");

}


//function to issue tokens on successful login
function issueTokens(req, res) {
    let payload = { username: req.body.username };
    let accessToken = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
        algorithm: "HS256",
        expiresIn: process.env.ACCESS_TOKEN_LIFE
    });
    let refreshToken = jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {
        algorithm: "HS256",
        expiresIn: process.env.REFRESH_TOKEN_LIFE
    });


    User.updateOne(  //adding refresh token to database for future reference
        { username: req.body.username },
        { $set: { refreshToken: refreshToken } },
        function (err) {
            if (!err) {
                console.log(">> Refresh Token Added to database.");
            }
            else {
                console.log(">> Refresh Token adding to DB - Error Occurred: " + err);
            }
        }
    );

    //secure: true can be added
    res.cookie("jwt", accessToken, { httpOnly: true });  //sending cookies
    console.log(">> Tokens issued");
    console.log(">> Access Token: " + accessToken);
    console.log(">> Refresh Token: " + refreshToken);
}









