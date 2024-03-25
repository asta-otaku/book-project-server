const { ObjectId } = require("mongodb");
const { MongoClient, ServerApiVersion } = require("mongodb");
const { validatePassword } = require("../utils/password");
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

// Middleware to check if user has been authenticated
const isAuth = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  else {
    res.status(403).json({
      Message: "User has not been authenticated",
    });
  }
};

const validateEmailAndPassword = async (req, res, next) => {
  const { email, password } = req.body;
  const users = await usersCollection.find({ email }).toArray();
  if (users.length < 1) {
    return res.status(401).json({
      Message: "Invalid Email/Password",
    });
  }
  const user = users[0];

  const isValidPassword = validatePassword(password, user.password);
  if (isValidPassword) return next();
  else {
    return res.status(401).json({
      Message: "Invalid Email/Password",
    });
  }
};
// Middleware to check if user has been verified
const isVerified = async (req, res, next) => {
  const users = await usersCollection.find({ email: req.body.email }).toArray();
  const user = users[0];

  console.log(user.verified);
  if (user.verified) {
    return next();
  } else {
    res.status(403).json({
      Message: "User not verified",
    });
  }
};

module.exports = { isAuth, isVerified, validateEmailAndPassword };
