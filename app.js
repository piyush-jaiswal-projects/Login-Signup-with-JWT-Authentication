
require('dotenv').config() //loads environment variables from .env file

//modules
const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");

//importing functions
const { login, signup } = require("./control");
const { verify } = require('./middleware');


const app = express();
app.use(bodyParser.json());
app.use(cookieParser());
app.set('view engine', 'ejs'); //ejs as templating engine
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public")); //static files in public directory


//login route. login function defined in control.js
app.post("/login", login);

//signup route. signup function defined in control.js
app.post("/signup", signup);

//protected content accessed through protectedContent route
app.get("/protectedContent", verify, function (req, res) {

    console.log(">> Authenticated user accessing protected content.");

    res.send("<h1>Protected Content</h1><br><h2>This content can be accessed only after complete authentication.</h2>");
});


//listening on port 3000
app.listen(3000, function () {
    console.log(">> Server started successfully at port 3000");
});
