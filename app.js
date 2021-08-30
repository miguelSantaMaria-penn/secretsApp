//package for using environmental variables
require('dotenv').config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

//use bcrypt hashing/salting package
const bcrypt = require("bcrypt");

//number of times for bcrypt to hash + salt repeatedly
const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended:true
}));

//connect to MongoDb and create user db, userDB
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

//create schema for user in db
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});

/*add encrypt package as a plugin to user Schema
must be done before model/collection is created
set password as the field to be encrypted
will encrypt when save is called, decrypt when find is called*/



//create model/collection of users
const User = new mongoose.model("User", userSchema);

//GET Home page

app.get("/", function(req,res){
  res.render("home");
});

app.get("/login", function(req,res){
  res.render("login");
});

app.get("/register", function(req,res){
  res.render("register");
});

//POST request to register a user
app.post("/register", function(req,res){

  bcrypt.hash(req.body.password, saltRounds, function(err, hash){
    const newUser = new User(
      {email: req.body.username,
      password: hash
    });

   //save users
   newUser.save(function(err){
     if(err){
       console.log(err);
     }else{
       res.render("secrets");
     }
   });
 });

});

//post request to login a user- use md5 to hash password for match
app.post("/login", function(req,res){
  const username = req.body.username;
  const password = req.body.password;

  User.findOne({email: username}, function(err,foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        bcrypt.compare(password, foundUser.password, function(err,results){
          if(results === true){
            res.render("secrets");
          }
        });
      }
    }
  })
});

app.listen(3000, function(){
  console.log("Server started on port 3000.");
});
