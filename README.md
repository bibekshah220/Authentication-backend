# Authentication System

A full-stack authentication system with Node.js, Express, MongoDB, Redis, and email-based OTP verification.

## Features
- User registration with email verification
- Login with OTP (One-Time Password) sent to email
- Password reset via email link
- JWT-based authentication (access & refresh tokens)
- User profile management
- Change password, update profile, delete account
- Admin endpoints for user management
- Rate limiting and Redis caching for performance

## Tech Stack
- **Backend:** Node.js, Express
- **Database:** MongoDB (Mongoose)
- **Cache/Rate Limit:** Redis
- **Validation:** Zod
- **Email:** Nodemailer
- **Authentication:** JWT

## Folder Structure
```
backend/
  controllers/      # Route controllers
  middlewares/      # Express middlewares
  models/           # Mongoose models
  routes/           # Express routes
  config/           # Config files (db, mail, zod, etc.)
  server.js         # App entry point
frontend/
  ...               # (Frontend not included in this repo)
```

## Setup Instructions
1. **Clone the repository:**
   ```sh
   git clone <your-repo-url>
   cd Authentication/backend
   ```
2. **Install dependencies:**
   ```sh
   npm install
   ```
3. **Configure environment variables:**
   - Copy `.env.example` to `.env` and fill in the required values (MongoDB URI, Redis URL, JWT secrets, email credentials, etc.)
4. **Start Redis server** (if not running):
   ```sh
   redis-server
   ```
5. **Run the backend server:**
   ```sh
   npm run dev
   ```

## API Endpoints
- `POST   /api/user/register`         Register new user
- `POST   /api/user/verify/:token`    Verify email
- `POST   /api/user/login`            Login (sends OTP)
- `POST   /api/user/request-otp`      Request OTP
- `POST   /api/user/verify-otp`       Verify OTP and login
- `POST   /api/user/forgot-password`  Request password reset
- `POST   /api/user/reset-password/:token`  Reset password
- `POST   /api/user/refresh-token`    Refresh JWT access token
- `POST   /api/user/logout`           Logout
- `GET    /api/user/profile`          Get user profile
- `POST   /api/user/update-profile`   Update profile
- `POST   /api/user/change-password`  Change password
- `POST   /api/user/delete-account`   Delete account
- **Admin:**
  - `GET    /api/user/admin/users`           List all users
  - `GET    /api/user/admin/user/:id`        Get user by ID
  - `PUT    /api/user/admin/update-user/:id` Update user
  - `DELETE /api/user/admin/delete-user/:id` Delete user

## License
MIT
