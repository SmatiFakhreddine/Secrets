import express from "express";
import bodyParser from "body-parser";
import { createClient } from "@supabase/supabase-js";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import path from "path";
import { fileURLToPath } from 'url';
import env from "dotenv";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
env.config();

const app = express();
const port = process.env.SERVER_PORT;
const saltRounds = 10;

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');
app.use(express.static(__dirname + "/public"));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(passport.initialize());
app.use(passport.session());

// Supabase database connection
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    res.redirect("/secrets")
  } else {
    res.render("home.ejs");
  }
});

app.get("/login", (req, res) => {
  if (req.isAuthenticated()) { 
    res.redirect("/secrets")
  } else {
    res.render("login.ejs");
  }
  
});

app.get("/register", (req, res) => {
  if (req.isAuthenticated()) { 
    res.redirect("/secrets")
  } else {
    res.render("register.ejs");
  }
  
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {

    try {
      const result = await supabase.from('users').select('secret').eq('email', req.user.email);
      const secret = result.data[0].secret;
      if (secret) {
        res.render("secrets.ejs", { secret: secret });
      } else {
        res.render("secrets.ejs", { secret: "Post your secret Now!" });
      }
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await supabase.from('users').select('*').eq('email', email);
    
    if (checkResult.data.length > 0) {
      res.render("register.ejs", {message: "User Found"});
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await supabase.from('users').insert([{email: email, password: hash}]).select();
          const user = result.data[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/submit", async function (req, res) {
  const submittedSecret = req.body.secret;
  console.log(req.user);
  try {
    await supabase.from('users').update({ secret: submittedSecret }).eq('email', req.user.email);
    res.redirect("/secrets");
  } catch (err) {
    console.log(err);
  }
});

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await supabase.from('users').select('*').eq('email', username);
      if (result.data.length > 0) {
        const user = result.data[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log(profile);
        const result = await supabase.from('users').select('*').eq('email', profile.email);
        if (result.data.length === 0) {
          const newUser = await supabase.from('users').insert([{email: profile.email, password: "google"}]).select();
          return cb(null, newUser.data[0]);
        } else {
          return cb(null, result.data[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
