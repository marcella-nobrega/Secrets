require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const encrypt = require("mongoose-encryption");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const FacebookStrategy = require('passport-facebook').Strategy;


const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebook_id : String,
  secret: String
});


userSchema.plugin(passportLocalMongoose);

userSchema.plugin(findOrCreate);


const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});



passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
    console.log(profile);}


));


passport.use(new FacebookStrategy({
  clientID: process.env.FB_ID,
  clientSecret: process.env.FB_SECRET,
  callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
function(accessToken, refreshToken, profile, done) {
    //Check the DB to find a User with the profile.id
    User.findOne({ facebook_id: profile.id }, function(err, user) {//See if a User already exists with the Facebook ID
      if(err) {
        console.log(err);  // handle errors!
      }

      if (user) {
        done(null, user); //If User already exists login as stated on line 10 return User
      } else { //else create a new User
        user = new User({
          facebook_id: profile.id, //pass in the id and displayName params from Facebook
          name: profile.displayName
        });
        user.save(function(err) { //Save User if there are no errors else redirect to login route
          if(err) {
            console.log(err);  // handle errors!
          } else {
            console.log("saving user ...");
            done(null, user);
          }
        });
      }
    });
  }
));

app.get("/", function(req, res) {
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", {
    scope: ["profile"]
  }));

  app.get("/login/facebook", passport.authenticate("facebook", {
    scope: [ "email" ]
  }));

app.get("/auth/google/secrets",
  passport.authenticate("google", {
    failureRedirect: "/login"
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

  app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login", failureMessage: true }),
  function(req, res) {
    res.redirect("/secrets");
  });


app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets", function(req, res) {
  User.find({"secret": {$ne: null}}, function(err, foundUser){
    if(err){console.log(err);}
    else{if(foundUser){
      res.render("secrets", {usersWithSecrets: foundUser});
    }}
  })
});

app.get("/submit", function(req,res){
  if(req.isAuthenticated()) {
    res.render("submit");
  } else{
    res.redirect("/login");
  }
});

app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
})

app.post("/register", function(req, res) {

  User.register({
    username: req.body.username
  }, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });


});

app.post("/login", function(req, res) {

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });

});

app.post("/submit", function(req,res){

  const submittedSecret = req.body.secret;

  User.findById(req.user.id, function(err,foundUser){
    if(err){console.log(err);}
    else{if(foundUser){
      foundUser.secret = submittedSecret,
      foundUser.save(function(){
        res.redirect("/secrets");
      });
    }}
  });
});


app.listen(process.env.PORT || 3000, function() {
  console.log("Server started on port 3000");
});
