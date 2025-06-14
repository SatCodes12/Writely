import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
    })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
    if(req.isAuthenticated()){
        res.redirect("/home");
    }
    else{
        res.render("welcome.ejs");
    }
});

app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});

app.get("/logout", (req, res) => {
    req.logout(function (err) {
        if (err) {
            return next(err);
        }
        res.redirect("/");
    });
});

app.get("/auth/google",
    passport.authenticate("google", {
        scope: ["profile", "email"],
    })
);

app.get("/auth/google/home",
    passport.authenticate("google", {
        successRedirect: "/home",
        failureRedirect: "/login",
    })
);

app.get("/home", async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const result = await db.query(
                "select * from posts join users on posts.user_id = users.id where users.id <> $1 order by posts.id desc", [req.user.id]
            );
            res.render("home.ejs", {posts: result.rows});
        } catch (error) {
            console.error(error);
            res.status(500).send("Internal Server Error");
        }
    } else {
        res.redirect("/login");
    }
});

app.get("/authorposts/:id", async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const id = req.params.id;
            const result = await db.query(
                "select * from posts join users on posts.user_id = users.id where users.id = $1 order by posts.id desc", [id]
            );
            res.render("authorposts.ejs", {authorName: result.rows[0].name, posts: result.rows});
        } catch (error) {
            console.error(error);
            res.status(500).send("Internal Server Error");
        }
    } else {
        res.redirect("/login");
    }
});

app.get("/profile", async (req, res) => {
    if (!req.isAuthenticated()) {
        res.redirect("/login");
    }
    else {
        try {
            const user = req.user;
            const result = await db.query("select count(*) from posts where user_id = $1", [user.id]);
            const totalPosts = parseInt(result.rows[0].count, 10);

            res.render("profile.ejs", {
                username: user.username,
                name: user.name,
                email: user.email,
                totalPosts: totalPosts,
            });
        } catch (error) {
            console.log("Error fetching profile data:", error);
            res.status(500).send("Internal Server Error");
        }
    }
});

app.get("/myposts", async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const result = await db.query("select * from posts where user_id=$1 order by id desc", [req.user.id]);
            res.render("userposts.ejs", {posts: result.rows});
        } catch (error) {
            console.error(error);
            res.status(500).send("Internal Server Error");
        }
    } else {
        res.redirect("/login");
    }
});

app.get("/newpost", (req, res) => {
    if(!req.isAuthenticated()){
        res.redirect("/login");
    }
    else{
        res.render("modify.ejs", {
            heading: "New Post",
            submit: "Create Post"
        });
    }
});

app.get("/editpost/:id", async (req, res) => {
    if(!req.isAuthenticated()){
        res.redirect("/login");
    }
    else{
        try {
            const id = req.params.id;
            const result = await db.query("select * from posts where id=$1", [id]);
            res.render("modify.ejs", {
                heading: "Edit Post",
                post: result.rows[0],
                submit: "Submit Changes"
            });
        } catch (error) {
            console.log("Error fetching post:", error);
            res.status(500).send("Internal Server Error");
        }
    }
});

app.get("/deletepost/:id", async (req, res) => {
    if(!req.isAuthenticated()){
        res.redirect("/login");
    }
    else{
        try {
            const id = req.params.id;
            await db.query("delete from posts where id=$1 and user_id=$2", [id, req.user.id]);
            res.redirect("/myposts");
        } catch (error) {
            console.log("Error deleting post:", error);
            res.status(500).send("Internal Server Error");
        }
    }
});

app.post("/post", async (req, res) => {
    if(!req.isAuthenticated()){
        res.redirect("/login");
    }
    else{
        const title = req.body.title;
        const content = req.body.content;

        try {
            await db.query(
                "insert into posts (user_id, title, content) values ($1,$2,$3)", [req.user.id,title,content]
            );
            res.redirect("/myposts");
        } catch (error) {
            console.log("Error adding post:", error);
            res.status(500).send("Internal Server Error");
        }
    }
});

app.post("/post/:id", async (req, res) => {
    if(!req.isAuthenticated()){
        res.redirect("/login");
    }
    else{
        const id = parseInt(req.params.id);
        const title = req.body.title;
        const content = req.body.content;

        try {
            await db.query(
                "update posts set title=$1, content=$2 where id=$3 and user_id=$4", 
                [title, content, id, req.user.id]
            );
            res.redirect("/myposts");
        } catch (error) {
            console.log("Error editing post:", error);
            res.status(500).send("Internal Server Error");
        }
    }
});

app.post("/login",
    passport.authenticate("local", {
        successRedirect: "/home",
        failureRedirect: "/login",
    })
);

app.post("/register", async (req, res) => {
    const name = req.body.name;
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;

    try {
        const checkResult = await db.query("select * from users where email = $1", [email]);
        if (checkResult.rows.length > 0) {
            res.redirect("/login");
        }
        else {
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.log(err);
                }
                else {
                    const result = await db.query(
                        "insert into users(name, username, email, password) values($1, $2, $3, $4) returning *",
                        [name, username, email, hash]
                    )
                    const user = result.rows[0];
                    req.login(user, (err) => {
                        res.redirect("/home");
                    });
                }
            })
        }
    } catch (error) {
        console.log(error);
    }
});

passport.use("local",
    new Strategy(
        { usernameField: "email" },
        async function verify(email, password, cb) {
            try {
                const result = await db.query("select * from users where email = $1", [email]);
                if (result.rows.length > 0) {
                    const user = result.rows[0];
                    const storedHashedPassword = user.password;
                    bcrypt.compare(password, storedHashedPassword, (err, valid) => {
                        if (err) {
                            console.log(err);
                        }
                        else {
                            if (valid) {
                                return cb(null, user);
                            }
                            else {
                                return cb(null, false);
                            }
                        }
                    })
                }
                else {
                    return cb("User not found");
                }
            } catch (error) {
                console.log(error);
            }
        })
);

passport.use("google",
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: process.env.CALLBACK_URL,
            userProfileURL: process.env.USERPROFILE_URL,
            scope: [
                "profile",
                "email",
            ],
        },
        async (accessToken, refreshToken, profile, cb) => {
            try {
                const name = profile.displayName;
                const email = profile.emails?.[0]?.value;
                const username = email.split('@')[0];

                const result = await db.query("select * from users where email = $1", [email]);
                if (result.rows.length === 0) {
                    const newUser = await db.query(
                        "insert into users(name, username, email, password) values($1, $2, $3, $4) returning *",
                        [name, username, email, "google"]
                    )
                    return cb(null, newUser.rows[0]);
                }
                else {
                    return cb(null, result.rows[0]);
                }
            } catch (error) {
                console.log(error);
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
    console.log(`Server running on port ${port}`);
});