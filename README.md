# Recipe Sharing Platform - Backend API

This repository contains the backend API code for a recipe sharing platform built with Firebase Cloud Functions, Express, and Firestore. The API provides endpoints for user authentication, user management, and recipe CRUD operations.

## Features

- User authentication with Firebase Auth
- Secure session management with HTTP-only cookies
- Username uniqueness validation
- RESTful API for recipe management
- User profile management
- Authorization middleware for protected routes

## Tech Stack

- [Firebase Cloud Functions](https://firebase.google.com/docs/functions) - Serverless backend
- [Express.js](https://expressjs.com/) - Web framework
- [Firebase Admin SDK](https://firebase.google.com/docs/admin/setup) - Server-side Firebase integration
- [Firestore](https://firebase.google.com/docs/firestore) - NoSQL database
- [Firebase Authentication](https://firebase.google.com/docs/auth) - User authentication

## Prerequisites

Before you begin, ensure you have the following installed:
- [Node.js](https://nodejs.org/) (v16 or higher recommended)
- [npm](https://www.npmjs.com/) (v8 or higher)
- [Firebase CLI](https://firebase.google.com/docs/cli) (`npm install -g firebase-tools`)
- [Firebase project](https://console.firebase.google.com/) created and configured

## Project Structure

```
functions/
├── index.js           # Main API entry point
├── package.json       # Dependencies and scripts
├── node_modules/      # Installed packages
└── ...
```

## Local Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Louise-Yee/recipe-backend.git
   cd recipe-backend
   ```

2. Install dependencies:
   ```bash
   cd functions
   npm install
   ```

3. Set up Firebase project and initialize:
   ```bash
   firebase login
   firebase use --add
   ```
   Select your Firebase project when prompted.

4. Set up environment variables (optional):
   ```bash
   firebase functions:config:set someservice.key="THE API KEY" someservice.id="THE CLIENT ID"
   ```

5. Start the local emulator:
   ```bash
   firebase emulators:start
   ```
   This will start the Firebase emulator suite, including Functions and Firestore.

## API Endpoints

### Authentication

- `POST /api/auth/session` - Create a session with HttpOnly cookie
- `POST /api/auth/logout` - Logout and clear cookie

### User Management

- `POST /api/users` - Create a new user profile
- `GET /api/users/:userId` - Get user profile
- `POST /api/users/by-username` - Find user by username
- `PUT /api/users/profile` - Update user profile
- `GET /api/me` - Get current user information

### Recipe Management

- `POST /api/recipes` - Create a new recipe
- `GET /api/recipes` - Get all recipes
- `GET /api/recipes/:recipeId` - Get a specific recipe
- `PUT /api/recipes/:recipeId` - Update a recipe
- `DELETE /api/recipes/:recipeId` - Delete a recipe
- `GET /api/users/:userId/recipes` - Get all recipes by a specific user

## Deployment

### Deploy to Firebase

1. Build the project:
   ```bash
   cd functions
   npm run build  # If you have a build step, otherwise skip
   ```

2. Deploy to Firebase:
   ```bash
   firebase deploy --only functions
   ```

### Automated Deployment with GitHub Actions

1. Set up secrets in your GitHub repository:
   - `FIREBASE_SERVICE_ACCOUNT_YOUR_PROJECT_ID`

2. Create a `.github/workflows/deploy.yml` file:
   ```yaml
   name: Deploy to Firebase Functions
   on:
     push:
       branches:
         - main
   jobs:
     deploy:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v3
         - uses: actions/setup-node@v3
           with:
             node-version: 16
         - run: cd functions && npm ci
         - uses: w9jds/firebase-action@master
           with:
             args: deploy --only functions
           env:
             FIREBASE_TOKEN: ${{ secrets.FIREBASE_TOKEN }}
   ```

3. Generate a Firebase token for CI:
   ```bash
   firebase login:ci
   ```
   Add the token to your GitHub repository as a secret named `FIREBASE_TOKEN`.

## Testing

To test the API locally:

1. Start the emulators:
   ```bash
   firebase emulators:start
   ```

2. Use a tool like [Postman](https://www.postman.com/) or [curl](https://curl.se/) to make requests to `http://localhost:5001/your-project-id/us-central1/api`

## Security Rules

Don't forget to set up appropriate Firestore security rules to protect your data. Here's an example:

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read: if request.auth != null && request.auth.uid == userId;
      allow create: if request.auth != null && request.auth.uid == userId;
      allow update: if request.auth != null && request.auth.uid == userId;
      allow delete: if request.auth != null && request.auth.uid == userId;
    }
    
    match /recipes/{recipeId} {
      allow read: if true;
      allow create: if request.auth != null;
      allow update, delete: if request.auth != null && resource.data.authorId == request.auth.uid;
    }
  }
}
```

## Troubleshooting

### CORS Issues

If you encounter CORS issues when calling your API from the frontend:

1. Check your CORS configuration in `index.js`:
   ```javascript
   app.use(cors({ origin: true, credentials: true }));
   ```

2. Ensure your frontend is making requests with the appropriate credentials setting:
   ```javascript
   fetch(url, { credentials: 'include' })
   ```

### Function Deployment Failures

If deployment fails:

1. Check for any syntax errors in your code
2. Verify that you have the correct permissions for your Firebase project
3. Check that your dependencies in `package.json` are compatible with Firebase Functions

## License

[MIT](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
