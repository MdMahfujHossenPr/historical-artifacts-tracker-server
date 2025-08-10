import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import dotenv from "dotenv";
import admin from "firebase-admin";
import bcrypt from "bcrypt";

dotenv.config();

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});


// Configs
const app = express();
const port = process.env.PORT || 5000;
const uri = process.env.MONGODB_URI;
const jwtSecret = process.env.JWT_SECRET;

if (!uri || !jwtSecret) {
  console.error("❌ MONGODB_URI or JWT_SECRET missing in .env");
  process.exit(1);
}

const corsOptions = {
  origin: [
    "http://localhost:5173",
    "https://artifact-tracker.netlify.app",
  ],
  credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json());

// MongoDB client & collections holder
let client;
let db;
let artifactsCollection;
let likedCollection;
let usersCollection;

// JWT verify middleware
const verifyJWT = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send({ error: "Unauthorized access: No token" });
  }
  const token = authHeader.split(" ")[1];
  try {
    const decodedUser = await admin.auth().verifyIdToken(token);
    req.user = decodedUser;
    next();
  } catch (error) {
    console.error("Firebase token verify failed:", error.message);
    return res.status(403).send({ error: "Forbidden: Invalid token" });
  }
};

// Connect to MongoDB and start server
async function startServer() {
  try {
    client = new MongoClient(uri, {
      serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
      },
    });

    await client.connect();
    console.log("✅ MongoDB connected");

    db = client.db("historicalArtifactsDB");
    artifactsCollection = db.collection("artifacts");
    likedCollection = db.collection("likes");
    usersCollection = db.collection("users");

    setupRoutes();

    app.listen(port, () => {
      console.log(`🚀 Server running at http://localhost:${port}`);
    });
  } catch (error) {
    console.error("❌ Startup error:", error);
    process.exit(1);
  }
}

// Define all routes in one function
function setupRoutes() {
  // Health Check
  app.get("/", (req, res) => {
    res.status(200).json({ message: "✅ Server running", version: "1.0.0" });
  });

  // JWT token generation
  app.post("/jwt", (req, res) => {
    const user = req.body;
    if (!user || !user.email)
      return res.status(400).send({ error: "User email required" });
    const token = jwt.sign(user, jwtSecret, { expiresIn: "7d" });
    res.send({ token });
  });

  // Users - GET all
  app.get("/api/users", async (req, res) => {
    try {
      const users = await usersCollection.find().toArray();
      if (users.length === 0)
        return res.status(404).json({ message: "No users found" });
      res.status(200).json(users);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Server error while fetching users" });
    }
  });

  // Users - Register
  app.post("/api/users", async (req, res) => {
    let { name, photoURL, email, password, method } = req.body;
    if (typeof email === "string") email = email.trim().toLowerCase();
    if (typeof photoURL === "string") photoURL = photoURL.trim();

    try {
      if (!email || !name || !photoURL || !method) {
        return res.status(400).json({ message: "Missing required fields" });
      }
      const existingUser = await usersCollection.findOne({ email });
      if (existingUser)
        return res.status(400).json({ message: "User already exists" });

      if (method === "google") {
        const user = { name, photoURL, email, authType: "google" };
        const result = await usersCollection.insertOne(user);
        return res.status(201).json({ message: "Google user created", user: result });
      }

      if (method === "manual") {
        if (!password)
          return res.status(400).json({ message: "Password required" });
        if (
          password.length < 6 ||
          !/[A-Z]/.test(password) ||
          !/[a-z]/.test(password)
        ) {
          return res.status(400).json({
            message: "Password must be 6+ chars with upper & lower case letters",
          });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = { name, photoURL, email, password: hashedPassword, authType: "manual" };
        const result = await usersCollection.insertOne(user);
        return res.status(201).json({ message: "Manual user created", user: result });
      }

      return res.status(400).json({ message: "Invalid method" });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "User creation failed" });
    }
  });

  // Users - Login
  app.post("/login", async (req, res) => {
    const { email, password, method } = req.body;
    if (!email) return res.status(400).json({ message: "Email required" });

    try {
      const user = await usersCollection.findOne({ email });
      if (!user) return res.status(404).json({ message: "User not found" });

      if (method === "google") {
        return res.status(200).json({ message: "Google login successful", user });
      }

      if (method === "manual" && password) {
        const isValid = await bcrypt.compare(password, user.password || "");
        if (!isValid) return res.status(401).json({ message: "Invalid password" });
        return res.status(200).json({ message: "Manual login successful", user });
      }

      return res.status(400).json({ message: "Invalid login method or missing password" });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Login failed", error: error.message });
    }
  });

  // Artifacts Routes
  app.post("/artifacts", verifyJWT, async (req, res) => {
    const artifact = req.body;
    artifact.adderEmail = req.user.email;
    artifact.adderName = req.user.name || "Unknown";
    artifact.likes = 0;
    artifact.createdAt = new Date();

    try {
      const result = await artifactsCollection.insertOne(artifact);
      res.status(201).send(result);
    } catch (error) {
      console.error(error);
      res.status(500).send({ error: "Failed to add artifact" });
    }
  });

  app.get("/artifacts", async (req, res) => {
    try {
      const result = await artifactsCollection.find().toArray();
      res.send(result);
    } catch (error) {
      console.error(error);
      res.status(500).send({ error: "Failed to retrieve artifacts" });
    }
  });

  app.get("/artifacts/featured", async (req, res) => {
    try {
      const result = await artifactsCollection
        .find()
        .sort({ likes: -1, createdAt: -1 })
        .limit(6)
        .toArray();
      res.send(result);
    } catch (error) {
      console.error(error);
      res.status(500).send({ error: "Failed to retrieve featured artifacts" });
    }
  });

  app.get("/artifacts/:id", verifyJWT, async (req, res) => {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).send({ error: "Invalid ID" });

    try {
      const artifact = await artifactsCollection.findOne({ _id: new ObjectId(id) });
      artifact ? res.send(artifact) : res.status(404).send({ error: "Not found" });
    } catch (error) {
      console.error(error);
      res.status(500).send({ error: "Failed to fetch" });
    }
  });

  app.put("/artifacts/:id", verifyJWT, async (req, res) => {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).send({ error: "Invalid ID" });

    const updated = { ...req.body };
    delete updated.likes;
    delete updated.adderEmail;
    delete updated.adderName;
    delete updated.createdAt;

    try {
      const result = await artifactsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updated }
      );
      result.matchedCount === 0
        ? res.status(404).send({ error: "Not found or no change" })
        : res.send(result);
    } catch (error) {
      console.error(error);
      res.status(500).send({ error: "Update failed" });
    }
  });

  app.delete("/artifacts/:id", verifyJWT, async (req, res) => {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).send({ error: "Invalid ID" });

    try {
      const result = await artifactsCollection.deleteOne({ _id: new ObjectId(id) });
      result.deletedCount === 0
        ? res.status(404).send({ error: "Not found" })
        : res.send({ message: "Deleted" });
    } catch (error) {
      console.error(error);
      res.status(500).send({ error: "Delete failed" });
    }
  });

  app.post("/like/:id", verifyJWT, async (req, res) => {
    const { id } = req.params;
    const email = req.user.email;
    if (!ObjectId.isValid(id)) return res.status(400).send({ error: "Invalid ID" });

    try {
      const liked = await likedCollection.findOne({ artifactId: id, email });
      if (liked) {
        await likedCollection.deleteOne({ _id: liked._id });
        await artifactsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $inc: { likes: -1 } }
        );
        return res.send({ liked: false, message: "Unliked" });
      } else {
        await likedCollection.insertOne({
          artifactId: id,
          email,
          likedAt: new Date(),
        });
        await artifactsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $inc: { likes: 1 } }
        );
        return res.send({ liked: true, message: "Liked" });
      }
    } catch (error) {
      console.error(error);
      res.status(500).send({ error: "Failed to like/unlike" });
    }
  });

  app.get("/liked", verifyJWT, async (req, res) => {
    const email = req.user.email;
    try {
      const liked = await likedCollection.find({ email }).toArray();
      const ids = liked.map((doc) => new ObjectId(doc.artifactId));
      if (ids.length === 0) return res.send([]);
      const result = await artifactsCollection.find({ _id: { $in: ids } }).toArray();
      res.send(result);
    } catch (error) {
      console.error(error);
      res.status(500).send({ error: "Failed to fetch liked" });
    }
  });

  app.get("/my-artifacts", verifyJWT, async (req, res) => {
    const email = req.user.email;
    try {
      const result = await artifactsCollection.find({ adderEmail: email }).toArray();
      res.send(result);
    } catch (error) {
      console.error(error);
      res.status(500).send({ error: "Failed to fetch my artifacts" });
    }
  });

  app.get("/search", async (req, res) => {
    const name = req.query.name;
    if (!name) return res.status(400).send({ error: "Query param 'name' required" });

    try {
      const result = await artifactsCollection
        .find({ name: { $regex: name, $options: "i" } })
        .toArray();
      res.send(result);
    } catch (error) {
      console.error(error);
      res.status(500).send({ error: "Search error" });
    }
  });

  // --- REVIEWS POST ---
  app.post("/reviews/:id", verifyJWT, async (req, res) => {
    const artifactId = req.params.id;
    const userEmail = req.user.email;
    const userName = req.user.name || "Anonymous";
    const { review } = req.body;

    if (!ObjectId.isValid(artifactId)) {
      return res.status(400).json({ error: "Invalid artifact ID" });
    }
    if (!review || review.trim() === "") {
      return res.status(400).json({ error: "Review text is required" });
    }

    try {
      const artifact = await artifactsCollection.findOne({ _id: new ObjectId(artifactId) });
      if (!artifact) {
        return res.status(404).json({ error: "Artifact not found" });
      }

      const reviewDoc = {
        artifactId,
        userEmail,
        userName,
        review: review.trim(),
        createdAt: new Date(),
      };

      const result = await db.collection("reviews").insertOne(reviewDoc);

      return res.status(201).json({
        _id: result.insertedId,
        ...reviewDoc,
      });
    } catch (error) {
      console.error("Error posting review:", error);
      return res.status(500).json({ error: "Failed to post review" });
    }
  });

  // --- REVIEWS GET ---
  app.get("/reviews/:id", verifyJWT, async (req, res) => {
    const artifactId = req.params.id;

    if (!ObjectId.isValid(artifactId)) {
      return res.status(400).json({ error: "Invalid artifact ID" });
    }

    try {
      const reviews = await db
        .collection("reviews")
        .find({ artifactId })
        .sort({ createdAt: -1 })
        .toArray();

      return res.json(reviews);
    } catch (error) {
      console.error("Error fetching reviews:", error);
      return res.status(500).json({ error: "Failed to fetch reviews" });
    }
  });

  // 404 handler
  app.use((req, res) => {
    res.status(404).send("❌ 404 - Not Found");
  });

  // Global error handler
  app.use((err, req, res, next) => {
    console.error("Unhandled Error:", err.stack);
    res.status(500).json({ success: false, message: "Server Error" });
  });
}

// Start everything
startServer();
