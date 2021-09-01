//package for using environmental variables
require('dotenv').config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

//express-session for creating cookies
const session = require('express-session');

//packages for handling hashing and salting passwords, authentication via mongoose
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended:true
}));

//tell app to use session package, set it up with some configuration
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
}));

//tell app to use passport and initialize passport. Use passport for session.
app.use(passport.initialize());
app.use(passport.session());


//connect to MongoDb and create user db, userDB
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

//mongoose.set("useCreateIndex", true);

//create schema for user in db
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});

//add passportLocalMongoose plugin, will hash and salt passwords
userSchema.plugin(passportLocalMongoose);


//create model/collection of users
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

//passport will serialize and deserialize user info
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

//GET Requests
app.get("/", function(req,res){
  res.render("home");
});

app.get("/login", function(req,res){
  res.render("login");
});

app.get("/register", function(req,res){
  res.render("register");
});

//if user is already logined, redirect to secrets page, else just back to login page
app.get("/secrets", function(req,res){
  if(req.isAuthenticated()){
    res.render("secrets");
  }else{
    res.redirect("/login");
  }
});


app.get("/logout", function(req,res){

  //logout user, deleting cookies.
  //after, if they try to access secrets page while logged out, will instead be directed to login page.
  req.logout();
  res.redirect("/");
})


//POST request to register a user
app.post("/register", function(req,res){

//register user with passport
User.register({username: req.body.username}, req.body.password, function(err, user){
  if(err){
    console.log(err);
    res.redirect("/register");
  }else{
    //authenticate passport on local- will salt and hash password- if succesful will trigger callback
    passport.authenticate("local")(req,res,function(){
    res.redirect("/secrets");
    })
  }
})
});


//post request to login a user- use md5 to hash password for match
app.post("/login", function(req,res){

  //create user to authenticate for login using request body
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  //authenticate user via passport
  req.login(user, function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local");
      res.redirect("/secrets");
    }
  })

});

app.listen(3000, function(){
  console.log("Server started on port 3000.");
});
