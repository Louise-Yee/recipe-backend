const functions = require("firebase-functions");
const admin = require("firebase-admin");
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
// const multer = require("multer");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const Busboy = require("busboy");
const os = require("os");
const fs = require("fs");

const corsOptions = {
  origin: true, // This will reflect the request origin
  credentials: true, // This is crucial for cookies
  methods: ["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "Accept",
    "Origin",
    "X-Requested-With",
    "Access-Control-Allow-Headers",
    "Access-Control-Request-Method",
    "Access-Control-Request-Headers",
  ],
  exposedHeaders: ["Content-Range", "X-Content-Range"],
  maxAge: 3600,
  preflightContinue: false,
  optionsSuccessStatus: 204,
};

// Initialize Firebase Admin
admin.initializeApp({
  credential: admin.credential.applicationDefault(),
  storageBucket: "cloud-recipe-coursework.firebasestorage.app",
});

// Initialize Firestore database
const db = admin.firestore();
// Initialize Storage bucket
const bucket = admin.storage().bucket();
// Initialize Express app
const app = express();

// Middleware setup - order is important
app.use(cors(corsOptions)); // CORS should be first
app.options("*", cors(corsOptions));

app.use(express.json());
app.use(cookieParser());

// Set up multer for handling file uploads
// const storage = multer.memoryStorage();
// const upload = multer({
//   storage: multer.memoryStorage(),
// }).single("image");

// Helper function to get token from request (cookie or header)
const getTokenFromRequest = (req) => {
  // First try to get token from cookie
  let token = req.cookies?.auth_token;

  // If no cookie, fall back to Bearer token
  if (!token) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split("Bearer ")[1];
    }
  }

  return token;
};

// ============= AUTH ROUTES =============

// Create session with HttpOnly cookie
app.post("/auth/session", async (req, res) => {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      return res.status(400).json({ error: "ID token is required" });
    }

    // Verify the Firebase token
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const userId = decodedToken.uid;

    // Get user data from Firestore
    const userDoc = await db.collection("users").doc(userId).get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: "User not found" });
    }

    res.header("Access-Control-Allow-Credentials", "true");
    res.header("Access-Control-Allow-Origin", req.headers.origin);

    // Set HttpOnly, Secure cookie with the token
    res.cookie("auth_token", idToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "none",
      maxAge: 3600000, // 1 hour
    });

    // Return user data
    res.status(200).json({
      success: true,
      user: {
        uid: userId,
        email: userDoc.data().email,
        displayName: userDoc.data().displayName || "",
        username: userDoc.data().username || userDoc.data().email.split("@")[0],
        profileImage: userDoc.data().profileImage || "",
        bio: userDoc.data().bio || "",
        followersCount: userDoc.data().followersCount || 0,
        followingCount: userDoc.data().followingCount || 0,
        recipesCount: userDoc.data().recipesCount || 0,
        firstName: userDoc.data().firstName || "",
        lastName: userDoc.data().lastName || "",
        createdAt: userDoc.data().createdAt,
      },
    });
  } catch (error) {
    console.error("Error creating session:", error);
    res.status(500).json({ error: error.message });
  }
});

// Logout endpoint to clear cookie
app.post("/auth/logout", (req, res) => {
  res.clearCookie("auth_token");
  res.status(200).json({ success: true, message: "Logged out successfully" });
});

// ============= USER ROUTES =============

// Create a new user
app.post("/users", async (req, res) => {
  try {
    // Get token from request
    const idToken = getTokenFromRequest(req);
    if (!idToken) {
      return res
        .status(401)
        .json({ error: "No authentication token provided" });
    }

    // Verify the Firebase ID token
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const uid = decodedToken.uid;

    // Get user data from request body
    const { email, username, firstName, lastName, displayName } = req.body;

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    // Update the user's display name in Firebase Auth (optional)
    const userDisplayName =
      displayName ||
      `${firstName || ""} ${lastName || ""}`.trim() ||
      email.split("@")[0];

    await admin.auth().updateUser(uid, {
      displayName: userDisplayName,
    });

    // Save additional user data in Firestore
    await db
      .collection("users")
      .doc(uid)
      .set({
        email,
        username,
        firstName: firstName || "",
        lastName: lastName || "",
        displayName: userDisplayName,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });

    res.status(201).json({
      success: true,
      userId: uid,
      message: "User profile created successfully",
    });
  } catch (error) {
    console.error("Error creating user profile:", error);
    res.status(500).json({
      error: error.message,
      code: error.code || "unknown",
    });
  }
});

// Get user profile
app.get("/users/:userId", async (req, res) => {
  try {
    const userId = req.params.userId;

    // Get token from request
    const idToken = getTokenFromRequest(req);
    if (!idToken) {
      return res
        .status(401)
        .json({ error: "Unauthorized - No token provided" });
    }

    // Verify the token
    const decodedToken = await admin.auth().verifyIdToken(idToken);

    // Check if user is requesting their own profile
    if (userId !== decodedToken.uid) {
      return res
        .status(403)
        .json({ error: "Forbidden - Can only access your own profile" });
    }

    const userDoc = await db.collection("users").doc(userId).get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json({
      success: true,
      userData: userDoc.data(),
    });
  } catch (error) {
    console.error("Error getting user:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/users/by-username", async (req, res) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({ error: "Username is required" });
    }

    // Query Firestore to find a user with this username
    const usersRef = db.collection("users");
    const snapshot = await usersRef
      .where("username", "==", username)
      .limit(1)
      .get();

    if (snapshot.empty) {
      return res.status(404).json({ error: "User not found" });
    }

    // Return only the email (not the whole user object for security)
    const userData = snapshot.docs[0].data();

    res.status(200).json({
      success: true,
      email: userData.email,
    });
  } catch (error) {
    console.error("Error finding user by username:", error);
    res.status(500).json({ error: error.message });
  }
});

// Update user profile
app.put("/users/profile", async (req, res) => {
  try {
    // Get token from request
    const idToken = getTokenFromRequest(req);
    if (!idToken) {
      return res
        .status(401)
        .json({ error: "Unauthorized - No token provided" });
    }

    // Verify the token
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const userId = decodedToken.uid;

    const { firstName, lastName, displayName } = req.body;

    // Update data object
    const updateData = {
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    // Only update fields that are provided
    if (firstName !== undefined) updateData.firstName = firstName;
    if (lastName !== undefined) updateData.lastName = lastName;

    // Calculate displayName if both firstName and lastName are provided
    if (firstName !== undefined && lastName !== undefined) {
      updateData.displayName = `${firstName} ${lastName}`.trim();
    } else if (displayName !== undefined) {
      updateData.displayName = displayName;
    }

    // Update in Firestore
    await db.collection("users").doc(userId).update(updateData);

    // If displayName was updated, also update in Firebase Auth
    if (updateData.displayName) {
      await admin.auth().updateUser(userId, {
        displayName: updateData.displayName,
      });
    }

    res.status(200).json({
      success: true,
      message: "Profile updated successfully",
    });
  } catch (error) {
    console.error("Error updating profile:", error);
    res.status(500).json({ error: error.message });
  }
});

// Login user
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    // Firebase Auth REST API doesn't support username/password login directly from server
    // Instead, we'll provide a consistent response for frontend authentication

    res.status(200).json({
      success: true,
      message:
        "Authentication should be handled on the client side using Firebase Auth SDK",
      note: "For security reasons, server-side password validation is not supported. Use the Firebase Auth client SDK for login.",
    });
  } catch (error) {
    console.error("Error in login endpoint:", error);
    res.status(500).json({ error: error.message });
  }
});

// Get current user information
app.get("/me", async (req, res) => {
  try {
    // Get token from request (cookie or header)
    const token = getTokenFromRequest(req);

    if (!token) {
      return res
        .status(401)
        .json({ error: "Unauthorized - Not authenticated" });
    }

    // Verify the token
    const decodedToken = await admin.auth().verifyIdToken(token);
    const userId = decodedToken.uid;

    // Get user data from Firestore
    const userDoc = await db.collection("users").doc(userId).get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json({
      success: true,
      user: {
        uid: userId,
        email: userDoc.data().email,
        firstName: userDoc.data().firstName || "",
        lastName: userDoc.data().lastName || "",
        displayName: userDoc.data().displayName || "",
        username: userDoc.data().username || userDoc.data().email.split("@")[0],
        profileImage: userDoc.data().profileImage || "",
        bio: userDoc.data().bio || "",
        followersCount: userDoc.data().followersCount || 0,
        followingCount: userDoc.data().followingCount || 0,
        recipesCount: userDoc.data().recipesCount || 0,
        createdAt: userDoc.data().createdAt,
      },
    });
  } catch (error) {
    console.error("Error getting user info:", error);
    res.status(500).json({ error: error.message });
  }
});

// ============= RECIPE ROUTES =============

// Upload image to Firebase Storage
app.post("/upload-image", (req, res) => {
  console.log("Direct upload request received");

  if (!req.headers["content-type"]) {
    return res.status(400).json({ error: "No content-type header provided" });
  }

  // Create a temporary directory to store the file
  const tmpdir = os.tmpdir();
  const fields = {};
  let fileWrites = [];
  let tmpFilePath = null;
  let fileData = null;

  // Create busboy instance
  const busboy = Busboy({ headers: req.headers });

  // Handle normal field values
  busboy.on("field", (fieldname, val) => {
    fields[fieldname] = val;
  });

  // Handle file upload
  busboy.on("file", (fieldname, file, { filename, encoding, mimeType }) => {
    console.log(`Processing file: ${filename}, type: ${mimeType}`);

    if (!filename) {
      console.log("No file provided");
      return;
    }

    // Only accept images
    if (!mimeType.startsWith("image/")) {
      console.log(`Invalid file type: ${mimeType}`);
      file.resume(); // Skip this file
      return;
    }

    // Create a unique temp file path
    const uniqueFilename = `${Date.now()}-${filename}`;
    tmpFilePath = path.join(tmpdir, uniqueFilename);

    fileData = {
      fieldname,
      originalname: filename,
      encoding,
      mimetype: mimeType,
      filepath: tmpFilePath,
    };

    console.log(`Saving to temp file: ${tmpFilePath}`);

    // Create write stream to temp file
    const writeStream = fs.createWriteStream(tmpFilePath);
    file.pipe(writeStream);

    // Add promise to track file write completion
    const promise = new Promise((resolve, reject) => {
      file.on("end", () => {
        writeStream.end();
      });

      writeStream.on("finish", () => {
        console.log(`File write completed: ${tmpFilePath}`);
        resolve();
      });

      writeStream.on("error", (error) => {
        console.error(`Error writing file: ${error}`);
        reject(error);
      });
    });

    fileWrites.push(promise);
  });

  // Handle completion
  busboy.on("finish", async () => {
    console.log("Busboy processing finished");

    try {
      // Wait for all file writes to complete
      await Promise.all(fileWrites);

      // If no file was provided
      if (!tmpFilePath || !fileData) {
        return res
          .status(400)
          .json({ error: "No valid image file was provided" });
      }

      // Get and verify authentication token
      const token = getTokenFromRequest(req);
      if (!token) {
        return res
          .status(401)
          .json({ error: "Unauthorized - No authentication token found" });
      }

      // Verify the token
      const decodedToken = await admin.auth().verifyIdToken(token);
      const userId = decodedToken.uid;

      // Create a unique filename
      const fileExtension = path.extname(fileData.originalname).toLowerCase();
      const uniqueFilename = `${uuidv4()}${fileExtension}`;
      const storageFilePath = `recipe-images/${userId}/${uniqueFilename}`;

      console.log(`Uploading to Firebase Storage: ${storageFilePath}`);

      // Upload directly to Firebase Storage using the file
      const [uploadedFile] = await bucket.upload(tmpFilePath, {
        destination: storageFilePath,
        metadata: {
          contentType: fileData.mimetype,
          metadata: {
            originalname: fileData.originalname,
            uploadedBy: userId,
            uploadedAt: new Date().toISOString(),
          },
        },
      });

      console.log("File successfully uploaded to Firebase Storage");

      // Make the file publicly accessible
      await uploadedFile.makePublic();

      // Get the public URL
      const publicUrl = `https://storage.googleapis.com/${bucket.name}/${storageFilePath}`;

      // Clean up - delete temp file
      try {
        fs.unlinkSync(tmpFilePath);
        console.log(`Temp file deleted: ${tmpFilePath}`);
      } catch (err) {
        console.error(`Error deleting temp file: ${err}`);
        // Continue even if cleanup fails
      }

      // Return success response
      return res.status(200).json({
        success: true,
        imageUrl: publicUrl,
        message: "Image uploaded successfully",
        fileInfo: {
          originalname: fileData.originalname,
          mimetype: fileData.mimetype,
          size: fs.statSync(tmpFilePath).size,
        },
      });
    } catch (error) {
      console.error("Error in upload process:", error);

      // Clean up temp file if it exists and there was an error
      if (tmpFilePath) {
        try {
          fs.unlinkSync(tmpFilePath);
          console.log(`Temp file deleted after error: ${tmpFilePath}`);
        } catch (cleanupErr) {
          console.error(`Error deleting temp file: ${cleanupErr}`);
        }
      }

      return res.status(500).json({
        error: "Server error during upload",
        message: error.message,
      });
    }
  });

  // Handle busboy errors
  busboy.on("error", (error) => {
    console.error("Busboy error:", error);
    return res.status(500).json({
      error: "Error processing upload",
      message: error.message,
    });
  });

  // Pipe request to busboy for processing
  req.pipe(busboy);
});

// Add this helper function to delete images
const deleteImageFromUrl = async (imageUrl) => {
  try {
    if (!imageUrl) return;

    const urlParts = imageUrl.split(
      `https://storage.googleapis.com/${bucket.name}/`
    );

    if (urlParts.length !== 2) return;

    const filePath = urlParts[1];
    const file = bucket.file(filePath);

    // Check if file exists before deleting
    const [exists] = await file.exists();
    if (exists) {
      await file.delete();
      console.log(`Successfully deleted image: ${filePath}`);
    }
  } catch (error) {
    console.error("Error deleting image:", error);
  }
};
// Create a new recipe
app.post("/recipes", async (req, res) => {
  try {
    // Get token from request
    const idToken = getTokenFromRequest(req);
    if (!idToken) {
      return res
        .status(401)
        .json({ error: "Unauthorized - No token provided" });
    }

    // Verify the token
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const userId = decodedToken.uid;

    const {
      title,
      description,
      ingredients,
      steps,
      cookTime,
      servings,
      imageUrl,
    } = req.body;

    // Validate required fields
    if (!title || !ingredients || !steps) {
      return res
        .status(400)
        .json({ error: "Title, ingredients, and steps are required" });
    }

    // Create the recipe document
    const recipeData = {
      title,
      description: description || "",
      ingredients,
      steps,
      cookTime: cookTime || 0,
      servings: servings || 1,
      imageUrl: imageUrl || null,
      authorId: userId,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    // Add to Firestore
    const recipeRef = await db.collection("recipes").add(recipeData);

    res.status(201).json({
      success: true,
      recipeId: recipeRef.id,
      message: "Recipe created successfully",
    });
  } catch (error) {
    console.error("Error creating recipe:", error);
    res.status(500).json({ error: error.message });
  }
});

// Get all recipes (public)
app.get("/recipes", async (req, res) => {
  try {
    const recipesSnapshot = await db
      .collection("recipes")
      .orderBy("createdAt", "desc")
      .get();

    const recipes = [];

    // Get all author IDs from recipes
    const authorIds = new Set();
    recipesSnapshot.forEach((doc) => {
      authorIds.add(doc.data().authorId);
    });

    // Fetch all authors' data in parallel
    const authorDocs = await Promise.all(
      Array.from(authorIds).map((authorId) =>
        db.collection("users").doc(authorId).get()
      )
    );

    // Create a map of author data for quick lookup
    const authorMap = {};
    authorDocs.forEach((doc) => {
      if (doc.exists) {
        authorMap[doc.id] = {
          uid: doc.id,
          displayName: doc.data().displayName || "Unknown",
          username:
            doc.data().username || doc.data().email?.split("@")[0] || "Unknown",
        };
      }
    });

    // Add recipes with author information
    recipesSnapshot.forEach((doc) => {
      const recipeData = doc.data();
      const author = authorMap[recipeData.authorId] || {
        uid: recipeData.authorId,
        displayName: "Unknown",
        username: "Unknown",
      };

      recipes.push({
        id: doc.id,
        ...recipeData,
        author,
      });
    });

    res.status(200).json({
      success: true,
      recipes,
    });
  } catch (error) {
    console.error("Error getting recipes:", error);
    res.status(500).json({ error: error.message });
  }
});

// Get a specific recipe (public)
app.get("/recipes/:recipeId", async (req, res) => {
  try {
    const recipeId = req.params.recipeId;
    const recipeDoc = await db.collection("recipes").doc(recipeId).get();

    if (!recipeDoc.exists) {
      return res.status(404).json({ error: "Recipe not found" });
    }

    // Get author information
    const authorId = recipeDoc.data().authorId;
    const authorDoc = await db.collection("users").doc(authorId).get();

    const recipeData = {
      id: recipeDoc.id,
      ...recipeDoc.data(),
      author: authorDoc.exists
        ? {
            id: authorDoc.id,
            displayName: authorDoc.data().displayName,
          }
        : { displayName: "Unknown" },
    };

    res.status(200).json({
      success: true,
      recipe: recipeData,
    });
  } catch (error) {
    console.error("Error getting recipe:", error);
    res.status(500).json({ error: error.message });
  }
});

// Update a recipe
app.put("/recipes/:recipeId", async (req, res) => {
  try {
    // Get token from request
    const idToken = getTokenFromRequest(req);
    if (!idToken) {
      return res
        .status(401)
        .json({ error: "Unauthorized - No token provided" });
    }

    // Verify the token
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const userId = decodedToken.uid;

    const recipeId = req.params.recipeId;
    const recipeDoc = await db.collection("recipes").doc(recipeId).get();

    if (!recipeDoc.exists) {
      return res.status(404).json({ error: "Recipe not found" });
    }

    // Check if user owns this recipe
    if (recipeDoc.data().authorId !== userId) {
      return res
        .status(403)
        .json({ error: "Forbidden - You can only update your own recipes" });
    }

    const {
      title,
      description,
      ingredients,
      steps,
      cookTime,
      servings,
      imageUrl,
    } = req.body;

    // Create update object
    const updateData = {
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    // Only update fields that are provided
    if (title) updateData.title = title;
    if (description !== undefined) updateData.description = description;
    if (ingredients) updateData.ingredients = ingredients;
    if (steps) updateData.steps = steps;
    if (cookTime !== undefined) updateData.cookTime = cookTime;
    if (servings !== undefined) updateData.servings = servings;

    // Handle image URL updates - delete the old image if there's a new one
    if (imageUrl !== undefined) {
      // If the image URL has changed and there was an old image
      if (imageUrl !== recipeDoc.data().imageUrl && recipeDoc.data().imageUrl) {
        await deleteImageFromUrl(recipeDoc.data().imageUrl);
      }
      updateData.imageUrl = imageUrl;
    }

    // Update the document
    await db.collection("recipes").doc(recipeId).update(updateData);

    res.status(200).json({
      success: true,
      message: "Recipe updated successfully",
    });
  } catch (error) {
    console.error("Error updating recipe:", error);
    res.status(500).json({ error: error.message });
  }
});

// Delete a recipe
app.delete("/recipes/:recipeId", async (req, res) => {
  try {
    // Get token from request
    const idToken = getTokenFromRequest(req);
    if (!idToken) {
      return res
        .status(401)
        .json({ error: "Unauthorized - No token provided" });
    }

    // Verify the token
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const userId = decodedToken.uid;

    const recipeId = req.params.recipeId;
    const recipeDoc = await db.collection("recipes").doc(recipeId).get();

    if (!recipeDoc.exists) {
      return res.status(404).json({ error: "Recipe not found" });
    }

    // Check if user owns this recipe
    if (recipeDoc.data().authorId !== userId) {
      return res
        .status(403)
        .json({ error: "Forbidden - You can only delete your own recipes" });
    }

    // Delete the associated image if it exists
    if (recipeDoc.data().imageUrl) {
      await deleteImageFromUrl(recipeDoc.data().imageUrl);
    }

    // Delete the document
    await db.collection("recipes").doc(recipeId).delete();

    res.status(200).json({
      success: true,
      message: "Recipe and associated image deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting recipe:", error);
    res.status(500).json({ error: error.message });
  }
});

// Get all recipes by a specific user
app.get("/users/:userId/recipes", async (req, res) => {
  try {
    const userId = req.params.userId;
    const recipesSnapshot = await db
      .collection("recipes")
      .where("authorId", "==", userId)
      .orderBy("createdAt", "desc")
      .get();

    const recipes = [];
    recipesSnapshot.forEach((doc) => {
      recipes.push({
        id: doc.id,
        ...doc.data(),
      });
    });

    res.status(200).json({
      success: true,
      recipes,
    });
  } catch (error) {
    console.error("Error getting user recipes:", error);
    res.status(500).json({ error: error.message });
  }
});

// Export the Express app as a Cloud Function
exports.api = functions.https.onRequest(app);
