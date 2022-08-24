//jshint esversion:6
require('dotenv').config(); //configure it to access .env
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//const encrypt = require("mongoose-encryption");
//const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose"); //will salt and hash our value
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');


const app = express();

//console.log(md5("123456"));
//console.log(process.env);

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session()); //use passport to manage session

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

//for local strategy only
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function(user, done){
  done(null, user);
});
//lambda expression form
passport.deserializeUser((user, done) => {
  done(null, user);
});

//Google strategy set up
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    //install mongoose findOrCreate Plugin to make the psedu code below work
    User.findOrCreate({ googleId: profile.id }, function (err, user, created) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
  res.render("home");
});

//use passport to authenticate our user using the Google strategy which
//was set up above, ask google for their profiles
app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] }));

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){
  // if(req.isAuthenticated()){
  //   res.render("secrets");
  // }else{
  //   res.redirect("/login");
  // }

  User.find({"secret": {$ne: null}}, function(error, foundUsers){
    if(error){
      console.log(error);
    }else{
      if(foundUsers){
        res.render("secrets", {usersWithSecret: foundUsers});
      }
    }
  })
});

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
})

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

  console.log(req.user._id);

  User.findById(req.user._id, function(error, foundUser){
    if(error){
      console.log(error);
    }else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
})

app.get("/logout", function(req, res){
  req.logout(function(error){
    if(!error){res.redirect("/");}
  });
});


app.post("/register", function(req, res){
  //the method below comes from the passport-local-mongoose, help us
  //avoid creating new user, saving user and interacting with Mongoose directly
  User.register({username: req.body.username}, req.body.password, function(error, user){
    if(error){
      console.log(error);
      res.redirect("/register");
    }else{
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  })


});

app.post("/login", function(req, res){
  const user = new User({
    username: req.body.name,
    password: req.body.password
  })

  req.login(user, function(error){
    if(error){
      console.log(error);
    }else{
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      }); //send a cookies and tell the browser to hold on that cookies
    }
  })


});






app.listen(3000, function(){
  console.log("Server started on port 3000");
})
