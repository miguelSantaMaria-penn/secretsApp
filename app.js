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

//after creating google console registration, use with passport
const GoogleStrategy = require('passport-google-oauth20').Strategy;

//to use find or create function from package
const findOrCreate = require("mongoose-findorcreate");

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
  googleId: String,
  secret: String
});

//add passportLocalMongoose plugin, will hash and salt passwords
userSchema.plugin(passportLocalMongoose);

//add findOrCreate function as a plugin
userSchema.plugin(findOrCreate);


//create model/collection of users
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

//passport will serialize and deserialize user info for any authentication type
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//use google authentication strategy we acquired earlier
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    passReqToCallback   : true
  },
  function(request, accessToken, refreshToken, profile, done) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));

//GET Requests
app.get("/", function(req,res){
  res.render("home");
});

app.get("/auth/google", passport.authenticate("google", {scope:
    [ 'email', 'profile' ]
})
);

//after user authenticates with google. If succesful redirect to root. Else login.
app.get( '/auth/google/secrets',
    passport.authenticate( 'google', {
        successRedirect: '/secrets',
        failureRedirect: '/login'
}));


app.get("/login", function(req,res){
  res.render("login");
});

app.get("/register", function(req,res){
  res.render("register");
});

//if user is already logined, redirect to secrets page, else just back to login page
app.get("/secrets", function(req,res){
//find fields where secrets are not null
User.find({"secret": {$ne: null}}, function(err,foundUsers){
  if(err){
    console.log(err);
  }else{
    if(foundUsers){
      res.render("secrets", {usersWithSecrets: foundUsers});
    }
  }
})
});

//get submit package
app.get("/submit", function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
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

//POST request for submitting secrets
app.post("/submit", function(req,res){
  const submittedSecret = req.body.secret;

  //find user, passport allows this via body
  User.findById(req.user._id, function(err, foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
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
      res.redirect("/login");
    }else{
      passport.authenticate("local",{failureRedirect: '/login'})(req,res,function(){
                res.redirect("/secrets");
            });
    }
  })

});


app.listen(3000, function(){
  console.log("Server started on port 3000.");
});
