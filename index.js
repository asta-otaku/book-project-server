const express = require("express");
const app = express();
const cors = require("cors");
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer");
const speakeasy = require("speakeasy");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const port = process.env.PORT || 5000;
const ObjectId = require("mongodb").ObjectId;
const passport = require("./config/passport_config");
require("dotenv").config();
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

// Middleware
app.use(
  cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.set("trust proxy", 1);
app.use(
  session({
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      ttl: 14 * 24 * 60 * 60,
      autoRemove: "native",
      collectionName: "my-sessions",
      dbName: "BookInventory",
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // Change to true if using HTTPS
      maxAge: 14 * 24 * 60 * 60 * 1000,
      httpOnly: true,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.send("Hello World!");
});

// MongoDB Connection

const { MongoClient, ServerApiVersion } = require("mongodb");
const { generatePassword } = require("./utils/password");
const {
  isVerified,
  validateEmailAndPassword,
  isAuth,
} = require("./middlewares/roles");
const uri = process.env.MONGO_URI;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Generate secret key
const secret = speakeasy.generateSecret({ length: 3 });

// Initialize nodemailer
const transporter = nodemailer.createTransport({
  host: "smtp-relay.brevo.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.TRANSPORTER_EMAIL,
    pass: process.env.TRANSPORTER_PASSWORD,
  },
});

// Users collection
const usersCollection = client.db("BookInventory").collection("users");

app.get("/users", isAuth, async (req, res) => {
  const users = await usersCollection.find({}).toArray();

  res.json({ users });
});

app.get("/users/user-info", isAuth, async (req, res) => {
  try {
    const userInfo = req.user; // user property is added to the request object by passport
    res.status(200).json({
      userInfo: userInfo,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      Message: "Internal Server Error",
    });
  }
});

app.post("/users/signup", async (req, res) => {
  // check if the user already exists
  const users = await usersCollection.find({ email: req.body.email }).toArray();
  if (users.length > 0) {
    return res.status(409).send("User already exists");
  }

  // if it doesn't create
  try {
    const otp = speakeasy.totp({
      secret: secret.base32,
      encoding: "base32",
    });

    const newUser = req.body;
    newUser.password = generatePassword(newUser.password);
    newUser.otp = otp;
    (newUser.verified = false), console.log(otp);

    const mailOptions = {
      from: "afolabiibrahim08@gmail.com",
      to: req.body.email,
      subject: "One-Time Passcode (OTP)",
      text: `Your One-Time Passcode (OTP) is: ${otp}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
        res.status(500).send("Failed to send OTP");
      } else {
        console.log("Email sent: " + info.response);
        res.status(200).send("OTP sent successfully");
      }
    });
    const result = await usersCollection.insertOne(newUser);
    res.status(200).json({
      user: result,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send(`500 Internal Server Error`);
  }
});

app.post(
  "/users/login",
  validateEmailAndPassword,
  isVerified,
  passport.authenticate("local", {
    failureRedirect: "/login",
    failureFlash: true,
  }),
  async (req, res) => {
    res.status(200).json({ status: 200, Message: "Login successful" });
  }
);

app.post("/users/forgot-password", async (req, res) => {
  const users = await usersCollection.find({ email: req.body.email }).toArray();
  if (users.length === 0) {
    return res.status(404).json({
      Message: "User not found",
    });
  }

  try {
    const otp = speakeasy.totp({
      secret: secret.base32,
      encoding: "base32",
    });

    await usersCollection.updateOne(
      {
        email: req.body.email,
      },
      {
        $set: { otp: otp },
      }
    );

    const mailOptions = {
      from: process.env.TRANSPORTER_EMAIL,
      to: req.body.email,
      subject: "One-Time Passcode (OTP)",
      text: `Your One-Time Passcode (OTP) is: ${otp}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
        res.status(500).send("Failed to send OTP");
      } else {
        console.log("Email sent: " + info.response);
        res.status(200).send("OTP sent successfully");
      }
    });
  } catch (error) {
    console.log(error);
    res.status(500).send(`500 Internal Server Error`);
  }
});

app.post("/users/reset-password", async (req, res) => {
  const users = await usersCollection.find({ email: req.body.email }).toArray();
  if (users.length === 0) {
    return res.status(404).json({
      Message: "User not found",
    });
  }
  const user = users[0];
  try {
    const { email, otp, password } = req.body;

    if (user.otp === otp) {
      await usersCollection.updateOne(
        {
          email,
        },
        {
          $set: { password: generatePassword(password) },
        }
      );
      res.status(200).json({
        Message: "Password Reset Successfully",
      });
    } else {
      res.status(403).json({
        Message: "User OTP Invalid",
      });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({
      Message: "Internal Server Error",
    });
  }
});

app.post("/users/verify", async (req, res) => {
  try {
    const { email, otp } = req.body;
    const users = await usersCollection.find({ email }).toArray();
    // look up user in db and compare otp, if otp from req matches otp in db changed verified of user from false to true
    const user = users[0];
    if (user.otp === otp) {
      await usersCollection.updateOne(
        {
          email,
        },
        {
          $set: { verified: true },
        }
      );
      res.status(200).json({
        Message: "User Verified Successfully",
      });
    } else {
      res.status(403).json({
        Message: "User OTP Invalid",
      });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({
      Message: "Internal Server Error",
    });
  }
});

app.post("/create-checkout-session", async (req, res) => {
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ["card"],
    line_items: req.body.items.map((item) => ({
      price_data: {
        currency: "usd",
        product_data: {
          name: "Book",
        },
        unit_amount: 1000,
      },
      quantity: item.quantity,
    })),
    mode: "payment",
    success_url: `${process.env.CLIENT_URL}/success`,
    cancel_url: `${process.env.CLIENT_URL}/cancel`,
  });

  res.json({ id: session.id });
});

// Handle logout
app.post("/users/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ error: "Logout failed" });
    }

    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ error: "Session destroy failed" });
      }

      res.clearCookie("connect.sid");
      res.json({ msg: "Logged out successfully" });
    });
  });
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    // Create a collection of documents
    const bookCollections = client.db("BookInventory").collection("books");

    // Get all books from the database
    app.get("/all-books/", async (req, res) => {
      let query = {};
      if (req.query?.category) {
        query = { category: req.query.category };
      }
      const result = await bookCollections.find(query).toArray();
      res.json(result);
    });

    // Get single book
    app.get("/book/:id", async (req, res) => {
      const id = req.params.id;
      const result = await bookCollections.findOne({ _id: new ObjectId(id) });
      res.json(result);
    });

    // Insert a book to the database using post method
    app.post("/upload-book", isAuth, async (req, res) => {
      const newBook = req.body;
      const result = await bookCollections.insertOne(newBook);
      res.json(result);
    });

    // Update a book using patch method
    app.patch("/update-book/:id", isAuth, async (req, res) => {
      const id = req.params.id;
      const updatedBook = req.body;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          ...updatedBook,
        },
      };
      const result = await bookCollections.updateOne(filter, updateDoc);
      res.json(result);
    });

    // Delete a book using delete method
    app.delete("/delete-book/:id", isAuth, async (req, res) => {
      const id = req.params.id;
      const result = await bookCollections.deleteOne({ _id: new ObjectId(id) });
      res.json(result);
    });

    // app.post("/users/logout", (req, res) => {
    //   req.logout((err) => {
    //     if (err) return res.status(500).json({ error: err });
    //     req.session.destroy(function (err) {
    //       if (!err) {
    //         res
    //           .status(200)
    //           .clearCookie("connect.sid", { path: "/" })
    //           .json({ status: "Success" });
    //       } else {
    //         // handle error case...
    //         res.status(500).json({ error: err });
    //       }
    //     });
    //   });
    // });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});

module.exports = client;
