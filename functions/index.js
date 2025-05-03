const functions = require("firebase-functions");
const admin = require("firebase-admin");
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { v4: uuidv4 } = require("uuid"); // Add this for generating unique filenames

// Initialize Firebase Admin
admin.initializeApp({
  credential: admin.credential.applicationDefault(),
  storageBucket: "cloud-recipe-coursework.firebasestorage.app",
});

// Initialize Firestore database
const db = admin.firestore();

// Initialize Firebase Storage with explicit bucket name
const storage = admin.storage();
const bucket = storage.bucket("cloud-recipe-coursework.firebasestorage.app");

// Initialize Express app
const app = express();

// Simple in-memory rate limiting (production would use Redis)
const rateLimit = {
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 100, // limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later",
  ipCache: new Map(),
};

// Rate limiting middleware
const rateLimiter = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();

  if (!rateLimit.ipCache.has(ip)) {
    rateLimit.ipCache.set(ip, {
      count: 1,
      resetTime: now + rateLimit.windowMs,
    });
    return next();
  }

  const client = rateLimit.ipCache.get(ip);

  // Reset if window expired
  if (now > client.resetTime) {
    client.count = 1;
    client.resetTime = now + rateLimit.windowMs;
    return next();
  }

  // Check count against limit
  if (client.count >= rateLimit.maxRequests) {
    return res.status(429).json({ error: rateLimit.message });
  }

  // Increment and continue
  client.count++;
  return next();
};

// Clean expired entries from cache periodically
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of rateLimit.ipCache.entries()) {
    if (now > data.resetTime) {
      rateLimit.ipCache.delete(ip);
    }
  }
}, 5 * 60 * 1000); // Run every 5 minutes

// CORS options
const corsOptions = {
  origin: ["https://cloud-recipe-coursework.web.app", "http://localhost:3000"], // Updated to include frontend domain
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

// Middleware
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());
app.use(rateLimiter);

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

// Helper function to generate upload URL for image upload
const generateUploadUrl = async (folderPath, fileName, contentType) => {
  try {
    // Generate a unique filename to avoid collisions
    const uniqueFileName = `${folderPath}/${Date.now()}_${uuidv4()}_${fileName}`;

    // Create a reference to the file in Firebase Storage
    const file = bucket.file(uniqueFileName);

    // Set metadata for the file
    const fileMetadata = {
      contentType: contentType,
      firebaseStorageDownloadTokens: uuidv4(),
    };

    // Apply the metadata to the file
    await file.setMetadata({
      contentType,
      metadata: fileMetadata,
    });

    // Create a signed URL for direct upload with proper configuration
    const [signedUrl] = await file.getSignedUrl({
      version: "v4",
      action: "write",
      expires: Date.now() + 15 * 60 * 1000, // 15 minutes
      contentType: contentType,
      // Ensure proper CORS headers for the upload
      headers: {
        "Content-Type": contentType,
        "Access-Control-Allow-Origin": "*",
      },
    });

    // Create a signed URL for reading to verify the upload later
    const [downloadSignedUrl] = await file.getSignedUrl({
      version: "v4",
      action: "read",
      expires: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
    });

    // For direct access after upload (public URL)
    const downloadUrl = `https://firebasestorage.googleapis.com/v0/b/${
      bucket.name
    }/o/${encodeURIComponent(uniqueFileName)}?alt=media`;

    // Return both URLs
    return {
      uploadUrl: signedUrl,
      fileUrl: downloadUrl,
      verificationUrl: downloadSignedUrl,
      fileName: uniqueFileName,
    };
  } catch (error) {
    console.error("Error generating upload URL:", error);
    throw error;
  }
};

// Helper function to validate file size and type
const validateImageFile = (contentType, fileSize) => {
  // Check if content type is valid image
  const validImageTypes = [
    "image/jpeg",
    "image/png",
    "image/jpg",
    "image/webp",
  ];
  if (!validImageTypes.includes(contentType)) {
    return {
      valid: false,
      error: "Invalid file type. Only JPEG, PNG, GIF, and WEBP are allowed.",
    };
  }

  // Check if file size is reasonable (limit to 5MB)
  const MAX_SIZE = 5 * 1024 * 1024; // 5MB
  if (fileSize > MAX_SIZE) {
    return { valid: false, error: "File too large. Maximum size is 5MB." };
  }

  return { valid: true };
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

// Refresh session and extend cookie lifetime
// Refresh session and extend cookie lifetime
app.post("/auth/refresh", async (req, res) => {
  try {
    const { idToken, requestCrossSiteCookies } = req.body;

    // If no token in body, try to get from cookie
    let token = idToken;
    if (!token) {
      token = getTokenFromRequest(req);
    }

    if (!token) {
      return res
        .status(401)
        .json({ error: "No authentication token provided" });
    }

    // Verify the token
    await admin.auth().verifyIdToken(token);

    // Cookie options
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production" || requestCrossSiteCookies,
      maxAge: 3600000, // 1 hour
    };

    // If cross-site cookies are requested, use SameSite=None (requires Secure)
    if (requestCrossSiteCookies) {
      cookieOptions.sameSite = "none";
    } else {
      cookieOptions.sameSite = "strict";
    }

    // Set a new cookie with the refreshed token
    res.cookie("auth_token", token, cookieOptions);

    res.status(200).json({
      success: true,
      message: "Session refreshed successfully",
    });
  } catch (error) {
    console.error("Error refreshing session:", error);
    // Clear the invalid cookie if there's an error
    res.clearCookie("auth_token");
    res.status(401).json({
      error: "Session expired or invalid",
      message: error.message,
    });
  }
});

// Logout endpoint to clear cookie
app.post("/auth/logout", (req, res) => {
  res.clearCookie("auth_token");
  res.status(200).json({ success: true, message: "Logged out successfully" });
});

// ============= USER ROUTES =============

// Get all users (only returns IDs)
app.get("/users", async (req, res) => {
  try {
    // Get token from request
    const idToken = getTokenFromRequest(req);
    if (!idToken) {
      return res
        .status(401)
        .json({ error: "Unauthorized - No token provided" });
    }

    // Verify the token
    await admin.auth().verifyIdToken(idToken);

    const usersSnapshot = await db.collection("users").get();

    const users = [];
    usersSnapshot.forEach((doc) => {
      users.push({
        id: doc.id,
        username: doc.data().username || "",
        displayName: doc.data().displayName || "",
      });
    });

    res.status(200).json({
      success: true,
      users,
      count: users.length,
    });
  } catch (error) {
    console.error("Error getting users:", error);
    res.status(500).json({ error: error.message });
  }
});

// Get public user profile - NEW ENDPOINT
app.get("/users/public/:userId", async (req, res) => {
  try {
    const userId = req.params.userId;

    // Get token from request (still require authentication)
    const idToken = getTokenFromRequest(req);
    if (!idToken) {
      return res
        .status(401)
        .json({ error: "Unauthorized - No token provided" });
    }

    // Verify the token (any authenticated user can access)
    await admin.auth().verifyIdToken(idToken);

    const userDoc = await db.collection("users").doc(userId).get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: "User not found" });
    }

    // Get user's recipes
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

    // Return only public user data
    const userData = {
      id: userId,
      username: userDoc.data().username || "",
      displayName: userDoc.data().displayName || "",
      profileImage: userDoc.data().profileImage || "",
      bio: userDoc.data().bio || "",
      recipesCount: recipes.length,
    };

    res.status(200).json({
      success: true,
      userData: userData,
      recipes: recipes,
    });
  } catch (error) {
    console.error("Error getting public user profile:", error);
    res.status(500).json({ error: error.message });
  }
});

// Search users by username or displayName
app.get("/users/search", async (req, res) => {
  try {
    const { query } = req.query;

    if (!query) {
      return res.status(400).json({ error: "Search query is required" });
    }

    // Get token from request
    const idToken = getTokenFromRequest(req);
    if (!idToken) {
      return res
        .status(401)
        .json({ error: "Unauthorized - No token provided" });
    }

    // Verify the token
    await admin.auth().verifyIdToken(idToken);

    const usersRef = db.collection("users");
    const searchValue = query.toLowerCase();

    // Get all users, we'll filter them on the server side
    const snapshot = await usersRef.orderBy("username").limit(100).get();

    // Combine and deduplicate results
    const userMap = new Map();

    snapshot.forEach((doc) => {
      const userData = doc.data();
      const username = (userData.username || "").toLowerCase();
      const displayName = (userData.displayName || "").toLowerCase();

      // Check if username or displayName contains the search query
      if (username.includes(searchValue) || displayName.includes(searchValue)) {
        userMap.set(doc.id, {
          id: doc.id,
          username: userData.username,
          displayName: userData.displayName || "",
          profileImage: userData.profileImage || "",
          bio: userData.bio || "",
        });
      }
    });

    const users = Array.from(userMap.values());

    res.status(200).json({
      success: true,
      users,
      count: users.length,
    });
  } catch (error) {
    console.error("Error searching users:", error);
    res.status(500).json({ error: error.message });
  }
});

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

    if (!username) {
      return res.status(400).json({ error: "Username is required" });
    }

    // Check if username already exists
    const usernameQuery = await db
      .collection("users")
      .where("username", "==", username)
      .get();

    if (!usernameQuery.empty) {
      return res.status(409).json({
        error: "Username already taken",
        code: "username-exists",
      });
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

    // Get user's recipes
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
      userData: userDoc.data(),
      recipes: recipes,
      recipesCount: recipes.length,
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

// ============= IMAGE UPLOAD ROUTES =============

// Generate upload URL for profile image
app.post("/users/profile-image-upload-url", async (req, res) => {
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

    const { fileName, contentType, fileSize } = req.body;

    if (!fileName || !contentType || !fileSize) {
      return res.status(400).json({
        error:
          "Missing required fields. Please provide fileName, contentType and fileSize",
      });
    }

    // Validate the image file
    const validation = validateImageFile(contentType, fileSize);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    // Generate the upload URL with the user ID in the path
    const folderPath = `profile-images/${userId}`;
    const uploadInfo = await generateUploadUrl(
      folderPath,
      fileName,
      contentType
    );

    // Store pending file info in the user's document
    await db
      .collection("users")
      .doc(userId)
      .update({
        pendingProfileImage: {
          fileName: uploadInfo.fileName,
          uploadUrl: uploadInfo.uploadUrl,
          fileUrl: uploadInfo.fileUrl,
          contentType: contentType,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        },
      });

    res.status(200).json({
      success: true,
      uploadInfo: {
        uploadUrl: uploadInfo.uploadUrl,
        fileUrl: uploadInfo.fileUrl,
        fileName: uploadInfo.fileName,
      },
    });
  } catch (error) {
    console.error("Error generating profile image upload URL:", error);
    res.status(500).json({ error: error.message });
  }
});

// Confirm profile image upload
app.post("/users/confirm-profile-image", async (req, res) => {
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

    const { fileName } = req.body;

    if (!fileName) {
      return res.status(400).json({ error: "fileName is required" });
    }

    // Get user data to check if the pending image exists
    const userDoc = await db.collection("users").doc(userId).get();

    if (
      !userDoc.exists ||
      !userDoc.data().pendingProfileImage ||
      userDoc.data().pendingProfileImage.fileName !== fileName
    ) {
      return res
        .status(400)
        .json({ error: "No matching pending profile image found" });
    }

    const pendingProfileImage = userDoc.data().pendingProfileImage;

    // Update the user's profile with the new image URL
    await db.collection("users").doc(userId).update({
      profileImage: pendingProfileImage.fileUrl,
      pendingProfileImage: admin.firestore.FieldValue.delete(), // Remove the pending image
    });

    res.status(200).json({
      success: true,
      profileImageUrl: pendingProfileImage.fileUrl,
      message: "Profile image updated successfully",
    });
  } catch (error) {
    console.error("Error confirming profile image upload:", error);
    res.status(500).json({ error: error.message });
  }
});

// Generate upload URL for recipe image
app.post("/recipes/image-upload-url", async (req, res) => {
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

    const { fileName, contentType, fileSize, recipeId } = req.body;

    if (!fileName || !contentType || !fileSize) {
      return res.status(400).json({
        error:
          "Missing required fields. Please provide fileName, contentType and fileSize",
      });
    }

    // Validate the image file
    const validation = validateImageFile(contentType, fileSize);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    // If recipeId is provided (for updating existing recipe), check ownership
    if (recipeId) {
      const recipeDoc = await db.collection("recipes").doc(recipeId).get();
      if (recipeDoc.exists && recipeDoc.data().authorId !== userId) {
        return res.status(403).json({
          error: "Forbidden - You can only upload images for your own recipes",
        });
      }
    }

    // Generate the upload URL
    const folderPath = `recipe-images/${userId}`;
    const uploadInfo = await generateUploadUrl(
      folderPath,
      fileName,
      contentType
    );

    res.status(200).json({
      success: true,
      uploadInfo: {
        uploadUrl: uploadInfo.uploadUrl,
        fileUrl: uploadInfo.fileUrl,
        fileName: uploadInfo.fileName,
      },
    });
  } catch (error) {
    console.error("Error generating recipe image upload URL:", error);
    res.status(500).json({ error: error.message });
  }
});

// ============= RECIPE ROUTES =============

// Search recipes by title
app.get("/recipes/search", async (req, res) => {
  try {
    const { query } = req.query;

    if (!query) {
      return res.status(400).json({ error: "Search query is required" });
    }

    const recipesRef = db.collection("recipes");
    const searchValue = query.toLowerCase();

    // First get all recipes, we'll filter them on the server side
    const snapshot = await recipesRef.orderBy("title").limit(100).get();

    const recipes = [];
    const userIds = new Set();

    // Filter recipes where the title contains the search term
    snapshot.forEach((doc) => {
      const recipeData = doc.data();
      // Check if the title contains the search query (case insensitive)
      if (
        recipeData.title &&
        recipeData.title.toLowerCase().includes(searchValue)
      ) {
        recipes.push({
          id: doc.id,
          ...recipeData,
        });

        if (recipeData.authorId) {
          userIds.add(recipeData.authorId);
        }
      }
    });

    // Get author information for all recipes in a single batch
    const authors = {};
    if (userIds.size > 0) {
      const userDocs = await Promise.all(
        Array.from(userIds).map((uid) => db.collection("users").doc(uid).get())
      );

      userDocs.forEach((userDoc) => {
        if (userDoc.exists) {
          authors[userDoc.id] = {
            id: userDoc.id,
            displayName: userDoc.data().displayName || "",
            username: userDoc.data().username || "",
          };
        }
      });
    }

    // Add author info to recipes
    const recipesWithAuthors = recipes.map((recipe) => ({
      ...recipe,
      author: authors[recipe.authorId] || { displayName: "Unknown" },
    }));

    res.status(200).json({
      success: true,
      recipes: recipesWithAuthors,
      count: recipesWithAuthors.length,
    });
  } catch (error) {
    console.error("Error searching recipes:", error);
    res.status(500).json({ error: error.message });
  }
});

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

    const { title, description, ingredients, steps, cookTime, servings } =
      req.body;

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

    // Get the recipe data to check for image URL
    const recipeData = recipeDoc.data();

    try {
      // First try to delete any associated image from Storage
      if (recipeData.imageUrl) {
        // Extract filename from the image URL
        // Format: https://firebasestorage.googleapis.com/v0/b/BUCKET/o/PATH%2FFILENAME?alt=media
        const urlPath = recipeData.imageUrl.split("?")[0];
        const decodedPath = decodeURIComponent(urlPath.split("/o/")[1]);

        if (decodedPath) {
          const imageFile = bucket.file(decodedPath);

          // Check if file exists before attempting deletion
          const [exists] = await imageFile.exists();
          if (exists) {
            await imageFile.delete();
            console.log(`Deleted image file: ${decodedPath}`);
          }
        }
      }

      // Then delete the recipe document
      await db.collection("recipes").doc(recipeId).delete();

      res.status(200).json({
        success: true,
        message: "Recipe and associated image deleted successfully",
      });
    } catch (storageError) {
      console.error("Error deleting recipe image:", storageError);

      // Even if image deletion fails, still delete the recipe document
      await db.collection("recipes").doc(recipeId).delete();

      res.status(200).json({
        success: true,
        message:
          "Recipe deleted successfully, but there was an issue removing the associated image",
      });
    }
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
