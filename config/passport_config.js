const passport = require("passport");
const { validatePassword } = require("../utils/password");
const LocalStrategy = require("passport-local").Strategy;
const { ObjectId } = require("mongodb");
const { MongoClient, ServerApiVersion } = require("mongodb");
require("dotenv").config();
const uri = process.env.MONGO_URI;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const usersCollection = client.db("BookInventory").collection("users");

const customFields = {
  usernameField: "email",
  passwordField: "password",
};

const verifyCallback = async (username, password, done) => {
  const users = await usersCollection.find({ email: username }).toArray();
  const user = users[0];

  try {
    let isValid = validatePassword(password, user.password);
    if (isValid) return done(null, user);
    else return done(null, false);
  } catch (error) {
    done(error);
  }
};
const strategy = new LocalStrategy(customFields, verifyCallback);

passport.use(strategy);

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser(async (userId, done) => {
  try {
    const users = await usersCollection
      .find({ _id: new ObjectId(userId) })
      .toArray();
    const user = users[0];
    done(null, user);
  } catch (error) {
    done(error);
  }
});

module.exports = passport;
