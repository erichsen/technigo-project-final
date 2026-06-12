import bcrypt from "bcrypt"
import crypto from "crypto"
import express from "express"
import cors from "cors"
import mongoose from "mongoose"

const mongoUrl = process.env.MONGO_URL || "mongodb://localhost/final-project"
mongoose.connect(mongoUrl)
mongoose.Promise = Promise

const { Schema, model } = mongoose

const userSchema = new Schema({
  name: {
    type: String,
    unique: true
  },
  email: {
    type: String,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  accessToken: {
    type: String,
    default: () => crypto.randomBytes(128).toString("hex")
  }
})

const User = model("User", userSchema)

// Middleware to check if user is logged in by verifying their access token
const authenticateUser = async (req, res, next) => {
  const user = await User.findOne({ accessToken: req.header("Authorization") })
  if (user) {
    req.user = user // Attach user to the request so routes can access it
    next() // Allow the request to continue
  } else {
    res.status(401).json({ loggedOut: true })
  }
}



// Defines the port the app will run on. Defaults to 8080, but can be overridden
// when starting the server. Example command to overwrite PORT env variable value:
// PORT=9000 npm start
const port = process.env.PORT || 8080
const app = express()

// Add middlewares to enable cors and json body parsing
app.use(cors())
app.use(express.json())

// Start defining your routes here
// http://localhost:8080/
app.get("/", (req, res) => {
  res.send("Hello Technigo!")
})

// Register a new family member
app.post("/users", async (req, res) => {
  try {
    const { name, email, password } = req.body
    const salt = bcrypt.genSaltSync()
    const user = new User({ name, email, password: bcrypt.hashSync(password, salt) })
    await user.save()
    res.status(201).json({ id: user._id, accessToken: user.accessToken })
  } catch (err) {
    res.status(400).json({ error: "Could not create user", details: err })
  }
})

// Login - returns accessToken if credentials are correct
app.post("/sessions", async (req, res) => {
  const user = await User.findOne({ email: req.body.email })
  if (user && bcrypt.compareSync(req.body.password, user.password)) {
    res.json({ userId: user._id, accessToken: user.accessToken })
  } else {
    res.status(401).json({ error: "Invalid email or password" })
  }
})

// Protected route - only accessible with a valid access token
app.get("/profile", authenticateUser, (req, res) => {
  res.json({ message: `Welcome ${req.user.name}!` })
})

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`)
})