// index.js
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import dotenv from "dotenv";
import admin from "firebase-admin";
import fs from "fs";
import bcrypt from "bcrypt";

// ✅ Step 1: Firebase config JSON file read
const serviceAccount = JSON.parse(
  fs.readFileSync("./firebase-service-Key.json", "utf-8")
);

// ✅ Step 2: Initialize Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Load environment variables
dotenv.config();

// Express App Setup
const app = express();
const port = process.env.PORT || 5000;

const corsOptions = {
  origin: ["http://localhost:5173", "https://your-deployed-site.netlify.app"],
  credentials: true,
};
app.use(cors(corsOptions));
app.use(express.json());

// MongoDB Setup
const uri = process.env.MONGODB_URI;
const jwtSecret = process.env.JWT_SECRET;

if (!uri || !jwtSecret) {
  console.error("❌ MONGODB_URI or JWT_SECRET missing in .env file.");
  process.exit(1);
}

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// JWT Verify Middleware (Firebase)
const verifyJWT = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .send({ error: "Unauthorized access: No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decodedUser = await admin.auth().verifyIdToken(token);
    req.user = decodedUser;
    next();
  } catch (error) {
    console.error("Firebase token verification failed:", error.message);
    return res
      .status(403)
      .send({ error: "Forbidden: Invalid or expired token" });
  }
};

async function run() {
  try {
    await client.connect();
    console.log("✅ MongoDB Connected");

    const db = client.db("historicalArtifactsDB");
    const artifactsCollection = db.collection("artifacts");
    const likedCollection = db.collection("likes");
    const usersCollection = db.collection("users");

    // Generate JWT Token
    app.post("/jwt", (req, res) => {
      const user = req.body;
      if (!user || !user.email) {
        return res.status(400).send({ error: "User email is required" });
      }
      const token = jwt.sign(user, jwtSecret, { expiresIn: "7d" });
      res.send({ token });
    });

    // Users - GET All Users
    app.get("/api/users", async (req, res) => {
      try {
        const users = await usersCollection.find().toArray();
        if (users.length === 0) {
          return res.status(404).json({ message: "No users found" });
        }
        res.status(200).json(users);
      } catch (error) {
        console.error("❌ Error fetching users:", error);
        res.status(500).json({ message: "Server error while fetching users" });
      }
    });

    // Users - Register (Manual/Google)
    app.post("/api/users", async (req, res) => {
      let { name, photoURL, email, password, method } = req.body;

      if (typeof email === "string") email = email.trim().toLowerCase();
      if (typeof photoURL === "string") photoURL = photoURL.trim();

      try {
        if (!email || !name || !photoURL || !method) {
          return res.status(400).json({ message: "Missing required fields" });
        }

        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.status(400).json({ message: "User already exists" });
        }

        if (method === "google") {
          const user = {
            name,
            photoURL,
            email,
            authType: "google",
          };
          const result = await usersCollection.insertOne(user);
          return res
            .status(201)
            .json({ message: "Google user created", user: result });
        }

        if (method === "manual") {
          if (!password)
            return res.status(400).json({ message: "Password is required" });
          if (
            password.length < 6 ||
            !/[A-Z]/.test(password) ||
            !/[a-z]/.test(password)
          ) {
            return res.status(400).json({
              message:
                "Password must be at least 6 chars and contain upper & lower case letters",
            });
          }
          const hashedPassword = await bcrypt.hash(password, 10);
          const user = {
            name,
            photoURL,
            email,
            password: hashedPassword,
            authType: "manual",
          };
          const result = await usersCollection.insertOne(user);
          return res
            .status(201)
            .json({ message: "Manual user created", user: result });
        }

        return res.status(400).json({ message: "Invalid method" });
      } catch (error) {
        console.error("Error registering user:", error);
        return res.status(500).json({ message: "User creation failed" });
      }
    });

    // Users - Login
    app.post("/login", async (req, res) => {
      const { email, password, method } = req.body;
      if (!email) return res.status(400).json({ message: "Email is required" });

      try {
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).json({ message: "User not found" });

        if (method === "google") {
          return res
            .status(200)
            .json({ message: "Google login successful", user });
        }

        if (method === "manual" && password) {
          const isPasswordValid = await bcrypt.compare(
            password,
            user.password || ""
          );
          if (!isPasswordValid)
            return res.status(401).json({ message: "Invalid password" });
          return res
            .status(200)
            .json({ message: "Manual login successful", user });
        }

        return res
          .status(400)
          .json({ message: "Invalid login method or missing password" });
      } catch (error) {
        console.error("Login failed:", error);
        res.status(500).json({ message: "Login failed", error: error.message });
      }
    });

    // Add Artifact
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
        console.error("Add artifact failed:", error);
        res.status(500).send({ error: "Failed to add artifact" });
      }
    });

    // Get All Artifacts
    app.get("/artifacts", async (req, res) => {
      try {
        const result = await artifactsCollection.find().toArray();
        res.send(result);
      } catch (error) {
        console.error("Fetch all artifacts failed:", error);
        res.status(500).send({ error: "Failed to retrieve artifacts" });
      }
    });

    // Get Top 6 Featured Artifacts
    app.get("/artifacts/featured", async (req, res) => {
      try {
        const result = await artifactsCollection
          .find()
          .sort({ likes: -1, createdAt: -1 })
          .limit(6)
          .toArray();
        res.send(result);
      } catch (error) {
        console.error("Featured fetch failed:", error);
        res
          .status(500)
          .send({ error: "Failed to retrieve featured artifacts" });
      }
    });

    // Get Single Artifact
    app.get("/artifacts/:id", verifyJWT, async (req, res) => {
      const { id } = req.params;
      if (!ObjectId.isValid(id))
        return res.status(400).send({ error: "Invalid ID" });

      try {
        const artifact = await artifactsCollection.findOne({
          _id: new ObjectId(id),
        });
        artifact
          ? res.send(artifact)
          : res.status(404).send({ error: "Not found" });
      } catch (error) {
        console.error("Single artifact fetch failed:", error);
        res.status(500).send({ error: "Failed to fetch" });
      }
    });

    // Update Artifacts
    app.put("/artifacts/:id", verifyJWT, async (req, res) => {
      const { id } = req.params;
      if (!ObjectId.isValid(id))
        return res.status(400).send({ error: "Invalid ID" });

      const updated = req.body;
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
        console.error("Update failed:", error);
        res.status(500).send({ error: "Update failed" });
      }
    });

    // Delete Artifact
    app.delete("/artifacts/:id", verifyJWT, async (req, res) => {
      const { id } = req.params;
      if (!ObjectId.isValid(id))
        return res.status(400).send({ error: "Invalid ID" });

      try {
        const result = await artifactsCollection.deleteOne({
          _id: new ObjectId(id),
        });
        result.deletedCount === 0
          ? res.status(404).send({ error: "Not found" })
          : res.send({ message: "Deleted" });
      } catch (error) {
        console.error("Delete failed:", error);
        res.status(500).send({ error: "Delete failed" });
      }
    });

    // Like/Unlike
    app.post("/like/:id", verifyJWT, async (req, res) => {
      const { id } = req.params;
      const email = req.user.email;
      if (!ObjectId.isValid(id))
        return res.status(400).send({ error: "Invalid ID" });

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
        console.error("Like/unlike failed:", error);
        res.status(500).send({ error: "Failed to like/unlike" });
      }
    });

    // Get Liked Artifacts
    app.get("/liked", verifyJWT, async (req, res) => {
      const email = req.user.email;
      try {
        const liked = await likedCollection.find({ email }).toArray();
        const ids = liked.map((doc) => new ObjectId(doc.artifactId));
        if (ids.length === 0) return res.send([]);
        const result = await artifactsCollection
          .find({ _id: { $in: ids } })
          .toArray();
        res.send(result);
      } catch (error) {
        console.error("Liked fetch failed:", error);
        res.status(500).send({ error: "Failed to fetch liked" });
      }
    });

    // Get My Artifacts
    app.get("/my-artifacts", verifyJWT, async (req, res) => {
      const email = req.user.email;
      try {
        const result = await artifactsCollection
          .find({ adderEmail: email })
          .toArray();
        res.send(result);
      } catch (error) {
        console.error("My artifacts fetch failed:", error);
        res.status(500).send({ error: "Failed to fetch my artifacts" });
      }
    });

    // Search
    app.get("/search", async (req, res) => {
      const name = req.query.name;
      if (!name)
        return res.status(400).send({ error: "Query param 'name' required" });

      try {
        const result = await artifactsCollection
          .find({ name: { $regex: name, $options: "i" } })
          .toArray();
        res.send(result);
      } catch (error) {
        console.error("Search failed:", error);
        res.status(500).send({ error: "Search error" });
      }
    });

    // Health Check
    app.get("/", (req, res) => {
      res.status(200).json({ message: "✅ Server running", version: "1.0.0" });
    });

    // 404 Page
    app.use((req, res) => {
      res.status(404).send("❌ 404 - Not Found");
    });

    // Global Error Handler
    app.use((err, req, res, next) => {
      console.error("Unhandled Error:", err.stack);
      res.status(500).json({ success: false, message: "Server Error" });
    });

    // Start server
    app.listen(port, () => {
      console.log(`🚀 Server running at http://localhost:${port}`);
    });
  } catch (error) {
    console.error("❌ Startup error:", error);
    process.exit(1);
  }
}

run();
