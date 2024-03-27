const { MongoClient, ServerApiVersion } = require("mongodb");
const { validatePassword } = require("../utils/password");
require("dotenv").config();
const { sign, verify } = require("jsonwebtoken");
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

const validateEmailAndPassword = async (req, res, next) => {
  const { username, password } = req.body;
  const user = await usersCollection.findOne({ email: username });
  if (!user) {
    return res.status(401).json({
      Message: "Invalid Email/Password",
    });
  }

  const isValidPassword = validatePassword(password, user.password);
  if (isValidPassword) {
    const token = sign({ user: user }, process.env.JWT_SECRET);
    // Send token to response headers
    // res.header("Authorization", `Bearer ${token}`);
    res.status(200).json({ message: token });
  } else {
    return res.status(401).json({
      Message: "Invalid Email/Password",
    });
  }
  return next();
};
// Middleware to check if user has been verified
const isVerified = async (req, res, next) => {
  const user = await usersCollection.findOne({ email: req.body.username });

  if (!user) {
    return res.status(404).json({
      Message: "User not found",
    });
  }

  if (!user.verified) {
    req.Message = "User not verified";
  }
};

//middleware to authorize token
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader.split(" ")[1];

  if (!token) {
    return res
      .status(401)
      .json({ message: "Unauthorized, Token not provided" });
  }
  verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Forbidden, Invalid token" });
    }
    req.user = decoded;
    next();
  });
}

module.exports = { isVerified, validateEmailAndPassword, verifyToken };
