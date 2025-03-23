const functions = require("firebase-functions");
const admin = require("firebase-admin");
const express = require("express");
const cors = require("cors");

// Initialize Firebase Admin
admin.initializeApp();

// Initialize Firestore database
const db = admin.firestore();

// Initialize Express app
const app = express();

// Middleware
app.use(cors({ origin: true }));
app.use(express.json());

// ============= USER ROUTES =============

// Create a new user
app.post("/users", async (req, res) => {
  try {
    const { email, password, displayName, firstName, lastName } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    console.log(`Attempting to create user with email: ${email}`);

    // Create the user in Firebase Authentication
    try {
      const userRecord = await admin.auth().createUser({
        email,
        password,
        displayName:
          displayName ||
          `${firstName || ""} ${lastName || ""}`.trim() ||
          email.split("@")[0],
      });

      console.log(`User created with UID: ${userRecord.uid}`);

      // Save additional user data in Firestore
      await db
        .collection("users")
        .doc(userRecord.uid)
        .set({
          email,
          firstName: firstName || "",
          lastName: lastName || "",
          displayName:
            displayName ||
            `${firstName || ""} ${lastName || ""}`.trim() ||
            email.split("@")[0],
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });

      res.status(201).json({
        success: true,
        userId: userRecord.uid,
        message: "User created successfully",
      });
    } catch (authError) {
      console.error("Firebase Auth error:", authError);
      if (authError.code === "auth/configuration-not-found") {
        return res.status(500).json({
          error:
            "Authentication service misconfigured. Please check that Email/Password authentication is enabled in the Firebase Console.",
        });
      }

      throw authError;
    }
  } catch (error) {
    console.error("Error creating user:", error);
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

    // Verify the request has a valid Firebase ID token
    const idToken = req.headers.authorization?.split("Bearer ")[1];
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
    // Verify authentication
    const idToken = req.headers.authorization
      ? req.headers.authorization.split("Bearer ")[1]
      : null;
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
    // Verify authentication
    const idToken = req.headers.authorization
      ? req.headers.authorization.split("Bearer ")[1]
      : null;
    if (!idToken) {
      return res
        .status(401)
        .json({ error: "Unauthorized - No token provided" });
    }

    // Verify the token
    const decodedToken = await admin.auth().verifyIdToken(idToken);
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
        createdAt: userDoc.data().createdAt,
      },
    });
  } catch (error) {
    console.error("Error getting user info:", error);
    res.status(500).json({ error: error.message });
  }
});

// ============= RECIPE ROUTES =============

// Create a new recipe
app.post("/recipes", async (req, res) => {
  try {
    // Verify authentication
    const idToken = req.headers.authorization?.split("Bearer ")[1];
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
    // Verify authentication
    const idToken = req.headers.authorization?.split("Bearer ")[1];
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
    if (imageUrl !== undefined) updateData.imageUrl = imageUrl;

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
    // Verify authentication
    const idToken = req.headers.authorization?.split("Bearer ")[1];
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

    // Delete the document
    await db.collection("recipes").doc(recipeId).delete();

    res.status(200).json({
      success: true,
      message: "Recipe deleted successfully",
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
