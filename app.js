import express from "express";
import { MongoClient } from "mongodb";
import MongoStore from "connect-mongo";
import session from "express-session";
import Joi from "joi";
import bcrypt from "bcrypt";
import "dotenv/config"; // Load .env file

const app = express();
const port = process.env.PORT ?? "3000";
const saltRounds = 12;

// Verify that the MONGODB environment variables are defined
if (process.env.MONGODB_USERNAME === undefined) {
    throw new Error("MONGODB_USERNAME environment variable not defined.");
}
if (process.env.MONGODB_PASSWORD === undefined) {
    throw new Error("MONGODB_PASSWORD environment variable not defined.");
}
if (process.env.MONGODB_HOST === undefined) {
    throw new Error("MONGODB_HOST environment variable not defined.");
}
if (process.env.MONGODB_DBNAME === undefined) {
    throw new Error("MONGODB_DBNAME environment variable not defined.");
}

const mongodbUri = `mongodb+srv://${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DBNAME}?retryWrites=true`;

const mongoClient = new MongoClient(mongodbUri, {});
const mongodbDatabase = mongoClient.db(process.env.MONGODB_DBNAME);

// Load the session secret from the environment variable or throw an error if not defined
const nodeSessionSecret =
    process.env.NODE_SESSION_SECRET ??
    (() => {
        throw new Error("NODE_SESSION_SECRET environment variable not defined.");
    })();
const mongodbSessionSecret =
    process.env.MONGODB_SESSION_SECRET ??
    (() => {
        throw new Error("MONGODB_SESSION_SECRET environment variable not defined.");
    })();

const sessionExpireTime = 1000 * 60 * 60; // 1 hour

const mongoStore = MongoStore.create({
    mongoUrl: mongodbUri,
    collectionName: "1537sessions",
    crypto: {
        secret: mongodbSessionSecret,
    },
});

function loginUser(req, user) {
    req.session.user = {};
    req.session.user.name = user.name;
    req.session.user.email = user.email;
    req.session.user.admin = user.admin ?? false;
}

function authenticatedMiddleware(req, res, next) {
    if (req.session.user !== undefined) {
        next();
    }
    else {
        res.redirect("/");
    }
}

function adminMiddleware(req, res, next) {
    if (req.session.user !== undefined) {
        if(req.session.user.admin === true) {
            next();
        }
        else {
            res.status(403).render("403", { user: req.session.user });
        }
    }
    else {
        res.redirect("/login");
    }
}

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: true }));

app.use(express.static("./public"));

app.use(session({
    secret: nodeSessionSecret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
    cookie: {
        maxAge: sessionExpireTime,
    },
}))

app.get("/", (req, res) => {
    res.render("index", { user: req.session.user })
})

app.get("/signup", (req, res) => {
    res.render("signup", { user: req.session.user });
})

app.post("/signupSubmit", async (req, res) => {
    const { name, email, password } = req.body;
    const schema = Joi.object({
        name: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().max(30).required(),
        password: Joi.string().max(20).required()
    });
    const validationResult = schema.validate({
        name,
        email,
        password,
    });
    if (validationResult.error !== undefined) {
        res.render("signupSubmit", { errorText: validationResult.error, user: req.session.user });
        return;
    }
    const user = await mongodbDatabase.collection("1537users").findOne({
        email,
    });
    if (user !== null) {
        res.render("signupSubmit", { errorText: "User already exists with that email.", user: req.session.user });
        return;
    }
    const passwordHash = await bcrypt.hash(req.body.password, saltRounds);
    mongodbDatabase
        .collection("1537users")
        .insertOne({
            name: req.body.name,
            email: req.body.email,
            admin: false,
            passwordHash,
        })
        .then(() => {
            loginUser(req, { name, email });
            res.redirect("/members");
        })
        .catch((err) => {
            console.error("Error inserting user into database:", err);
            res.status(500).send("Internal server error.");
        });
})

app.get("/login", (req, res) => {
    res.render("login", { user: req.session.user });
})

app.post("/loginSubmit", async (req, res) => {
    const { email, password } = req.body;
    const schema = Joi.object({
        email:    Joi.string().email().max(30).required(),
        password: Joi.string().max(20).required()
    });
    const validationResult = schema.validate({
        email,
        password,
    });
    if (validationResult.error !== undefined) {
        res.render("loginSubmit", { errorText: validationResult.error, user: req.session.user });
        return;
    }
    const user = await mongodbDatabase.collection("1537users").findOne({
        email,
    });
    if (user === null) {
        res.render("loginSubmit", { errorText: "Couldn't find user with that email.", user: req.session.user });
        return;
    }
    const passwordCorrect = await bcrypt.compare(req.body.password, user.passwordHash);
    if(!passwordCorrect) {
        res.render("loginSubmit", { errorText: "Incorrect password.", user: req.session.user });
        return;
    }
    loginUser(req, user);
    res.redirect("/members");
})

app.get("/members", authenticatedMiddleware, (req, res) => {
    res.render("members", { user: req.session.user });
})

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
})

app.get("/admin", adminMiddleware, async (req, res) => {
    const users = await mongodbDatabase
        .collection("1537users")
        .find()
        .toArray();
    res.render("admin", { user: req.session.user, users });
})

app.post("/admin/promoteUser/:email", adminMiddleware, async (req, res) => {
    mongodbDatabase.collection("1537users").updateOne({
        email: req.params.email,
    }, {
        $set: {
            admin: true,
        }
    });
    res.redirect("/admin");
})

app.post("/admin/demoteUser/:email", adminMiddleware, async (req, res) => {
    mongodbDatabase.collection("1537users").updateOne({
        email: req.params.email,
    }, {
        $set: {
            admin: false,
        }
    });
    res.redirect("/admin");
})

// Serve a 404 page for any other routes
app.use((req, res) => {
    res.status(404).render("404", { user: req.session.user });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
