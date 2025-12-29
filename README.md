# Pro Assignment 1: Authentication System

## Learning Objectives

By completing this assignment, you will:

- Understand authentication and authorization concepts
- Learn to implement secure user registration and login
- Practice password hashing and security best practices
- Implement JWT tokens or session management
- Create protected routes and endpoints
- Understand middleware for authentication
- Gain experience with authentication libraries (bcrypt, jsonwebtoken, jne.)

---

## Prerequisites

- Completed at least Assignment 2 (E2E Hello World)
- Working server and client application
- Understanding of Node.js + Express basics
- Cursor AI installed and configured
- Basic understanding of HTTP requests and responses
- (Optional) Basic understanding of databases (for storing users)

---

## Overview

This is a **pro-level bonus assignment** worth **10 bonus points**. It's optional but highly recommended for students who want to learn security and user management.

**Goal:** Add user authentication to your application, enabling users to register, login, and access protected features.

**Features:**

- User registration (sign up)
- User login
- Session management
- Protected routes/endpoints
- Logout functionality
- Password security

---

## Instructions

### Step 1: Choose Your Authentication Approach

Select an authentication method:

- **JWT (JSON Web Tokens)** (recommended) - Stateless, scalable
- **Session cookies** - Traditional, stateful
- **Passport.js** - Authentication middleware

**Recommendation:** Start with **JWT** - it's the most common approach for modern web apps.

### Step 2: Install Authentication Dependencies

1. **Install authentication libraries:**

   **Node.js (JWT + bcrypt):**

   ```bash
   npm install jsonwebtoken bcrypt
   npm install --save-dev @types/jsonwebtoken @types/bcrypt
   ```

   **Node.js (Passport.js):**

   ```bash
   npm install passport passport-local passport-jwt
   ```

2. **Update package.json:**

   ```json
   {
     "dependencies": {
       "jsonwebtoken": "^9.0.2",
       "bcrypt": "^5.1.1"
     }
   }
   ```

### Step 3: Set Up User Storage

1. **Choose storage method:**

   - **In-memory** (for learning) - Simple, no database needed
   - **SQLite** (recommended) - File-based, easy setup
   - **PostgreSQL/MongoDB** - Production-ready

2. **Create user schema:**

   **SQLite (Node.js):**

   ```javascript
   // server/db.js
   const Database = require('better-sqlite3')
   const db = new Database('app.db')

   db.exec(`
     CREATE TABLE IF NOT EXISTS users (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       username TEXT UNIQUE NOT NULL,
       email TEXT UNIQUE NOT NULL,
       password_hash TEXT NOT NULL,
       created_at DATETIME DEFAULT CURRENT_TIMESTAMP
     )
   `)

   module.exports = db
   ```

### Step 4: Implement Password Hashing

1. **Hash passwords on registration:**

   **Node.js (bcrypt):**

   ```javascript
   // server/auth.js
   const bcrypt = require('bcrypt')

   async function hashPassword(password) {
     const saltRounds = 10
     return await bcrypt.hash(password, saltRounds)
   }

   async function comparePassword(password, hash) {
     return await bcrypt.compare(password, hash)
   }

   module.exports = { hashPassword, comparePassword }
   ```

### Step 5: Implement User Registration

1. **Create registration endpoint:**

   **Node.js:**

   ```javascript
   // server/index.js
   const express = require('express')
   const { hashPassword } = require('./auth')
   const db = require('./db')

   const app = express()
   app.use(express.json())

   app.post('/api/auth/register', async (req, res) => {
     try {
       const { username, email, password } = req.body

       // Validate input
       if (!username || !email || !password) {
         return res.status(400).json({ error: 'All fields required' })
       }

       if (password.length < 8) {
         return res.status(400).json({ error: 'Password must be at least 8 characters' })
       }

       // Check if user exists
       const existingUser = db.prepare('SELECT * FROM users WHERE email = ?').get(email)
       if (existingUser) {
         return res.status(400).json({ error: 'User already exists' })
       }

       // Hash password
       const passwordHash = await hashPassword(password)

       // Create user
       const stmt = db.prepare(
         'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'
       )
       const result = stmt.run(username, email, passwordHash)

       res.status(201).json({
         success: true,
         message: 'User registered successfully',
         userId: result.lastInsertRowid,
       })
     } catch (error) {
       console.error('Registration error:', error)
       res.status(500).json({ error: 'Registration failed' })
     }
   })
   ```

### Step 6: Implement User Login

1. **Create login endpoint:**

   **Node.js (JWT):**

   ```javascript
   // server/index.js
   const jwt = require('jsonwebtoken')
   const { comparePassword } = require('./auth')

   const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production'

   app.post('/api/auth/login', async (req, res) => {
     try {
       const { email, password } = req.body

       // Validate input
       if (!email || !password) {
         return res.status(400).json({ error: 'Email and password required' })
       }

       // Find user
       const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email)
       if (!user) {
         return res.status(401).json({ error: 'Invalid credentials' })
       }

       // Verify password
       const isValid = await comparePassword(password, user.password_hash)
       if (!isValid) {
         return res.status(401).json({ error: 'Invalid credentials' })
       }

       // Generate JWT token
       const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, {
         expiresIn: '24h',
       })

       res.json({
         success: true,
         token,
         user: {
           id: user.id,
           username: user.username,
           email: user.email,
         },
       })
     } catch (error) {
       console.error('Login error:', error)
       res.status(500).json({ error: 'Login failed' })
     }
   })
   ```

### Step 7: Create Authentication Middleware

1. **Protect routes with middleware:**

   **Node.js (JWT middleware):**

   ```javascript
   // server/middleware/auth.js
   const jwt = require('jsonwebtoken')

   const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production'

   function authenticateToken(req, res, next) {
     const authHeader = req.headers['authorization']
     const token = authHeader && authHeader.split(' ')[1] // Bearer TOKEN

     if (!token) {
       return res.status(401).json({ error: 'Access token required' })
     }

     jwt.verify(token, JWT_SECRET, (err, user) => {
       if (err) {
         return res.status(403).json({ error: 'Invalid or expired token' })
       }
       req.user = user
       next()
     })
   }

   module.exports = { authenticateToken }
   ```

   **Use middleware:**

   ```javascript
   // server/index.js
   const { authenticateToken } = require('./middleware/auth')

   // Protected route
   app.get('/api/profile', authenticateToken, (req, res) => {
     res.json({
       message: 'Protected route accessed',
       user: req.user,
     })
   })
   ```

### Step 8: Implement Logout

1. **Create logout endpoint:**

   **Node.js (JWT - client-side):**

   ```javascript
   // Client-side: Simply remove token
   function logout() {
     localStorage.removeItem('token')
     window.location.href = '/login'
   }
   ```

### Step 9: Update Client to Use Authentication

1. **Create login form:**

   ```html
   <!-- client/login.html -->
   <!DOCTYPE html>
   <html>
     <head>
       <title>Login</title>
     </head>
     <body>
       <h1>Login</h1>
       <form id="loginForm">
         <input type="email" id="email" placeholder="Email" required />
         <input type="password" id="password" placeholder="Password" required />
         <button type="submit">Login</button>
       </form>
       <div id="error"></div>

       <script>
         document.getElementById('loginForm').addEventListener('submit', async e => {
           e.preventDefault()

           const email = document.getElementById('email').value
           const password = document.getElementById('password').value

           try {
             const response = await fetch('/api/auth/login', {
               method: 'POST',
               headers: { 'Content-Type': 'application/json' },
               body: JSON.stringify({ email, password }),
             })

             const data = await response.json()

             if (response.ok) {
               // Store token
               localStorage.setItem('token', data.token)
               window.location.href = '/dashboard'
             } else {
               document.getElementById('error').textContent = data.error
             }
           } catch (error) {
             console.error('Login error:', error)
           }
         })
       </script>
     </body>
   </html>
   ```

2. **Add token to requests:**

   ```javascript
   // client/api.js
   function getAuthHeaders() {
     const token = localStorage.getItem('token')
     return {
       'Content-Type': 'application/json',
       Authorization: `Bearer ${token}`,
     }
   }

   async function fetchProfile() {
     const response = await fetch('/api/profile', {
       headers: getAuthHeaders(),
     })
     return await response.json()
   }
   ```

### Step 10: Document Your Authentication System

1. **Update README.md:**

   - Add "Authentication" section
   - Document registration and login endpoints
   - Explain JWT token usage
   - Include security considerations
   - Document protected routes

2. **Create authentication documentation:**

   ```markdown
   ## Authentication System

   ### Endpoints

   - `POST /api/auth/register` - Register new user
   - `POST /api/auth/login` - Login user
   - `POST /api/auth/logout` - Logout user
   - `GET /api/profile` - Get user profile (protected)

   ### Security

   - Passwords are hashed using bcrypt
   - JWT tokens expire after 24 hours
   - Protected routes require valid token
   ```

---

## Requirements

### Required

- [ ] User registration (sign up) working
- [ ] User login working
- [ ] Password hashing implemented (bcrypt)
- [ ] JWT tokens or session management working
- [ ] Authentication middleware created
- [ ] At least one protected route/endpoint
- [ ] Logout functionality
- [ ] Authentication documented in README.md

### Optional

- [ ] Email validation
- [ ] Password strength requirements
- [ ] Remember me functionality
- [ ] Password reset
- [ ] Email verification
- [ ] Rate limiting on auth endpoints
- [ ] Account lockout after failed attempts

---

## Acceptance Criteria

Your submission will be evaluated based on:

- [ ] User registration working
- [ ] User login working
- [ ] Passwords securely hashed
- [ ] JWT tokens or sessions working
- [ ] Protected routes require authentication
- [ ] Logout functionality working
- [ ] Authentication system documented
- [ ] Security considerations documented
- [ ] Changes committed and pushed to GitHub

---

## Submission Requirements

1. **Authentication code:** All auth code in server
2. **Database:** User storage set up (SQLite or in-memory)
3. **Documentation:** README.md updated with authentication section
4. **Security notes:** Security considerations documented
5. **Commit:** All changes committed and pushed to GitHub

**Commit message example:**

```bash
git commit -m "Pro Assignment 1: Authentication System"
```

---

## Grading Rubric

See [Grading Rubrics](https://repodin-education.github.io/vibe-coding-materials/grading-rubrics.html) for detailed criteria.

**Total Points:** 10 bonus points

- **Registration & Login:** 4 points
  - Registration working: 1 point
  - Login working: 1 point
  - Password hashing: 1 point
  - Input validation: 1 point
- **Authentication:** 3 points
  - JWT/session working: 1 point
  - Protected routes: 1 point
  - Middleware: 1 point
- **Security:** 2 points
  - Password security: 1 point
  - Token security: 1 point
- **Documentation:** 1 point
  - Authentication documented: 0.5 points
  - Security considerations: 0.5 points

---

## Security Best Practices

### Password Security

- ✅ **Always hash passwords** - Never store plain text passwords
- ✅ **Use bcrypt** - Industry standard for password hashing
- ✅ **Salt rounds** - Use at least 10 salt rounds
- ✅ **Password requirements** - Minimum 8 characters, complexity rules
- ❌ **Never log passwords** - Don't log password in any form
- ❌ **Never send passwords** - Don't send passwords in error messages

### Token Security

- ✅ **Use HTTPS** - Always use HTTPS in production
- ✅ **Token expiration** - Set reasonable expiration times (24h)
- ✅ **Secret key** - Use strong, random secret keys
- ✅ **Store securely** - Store tokens securely (httpOnly cookies or localStorage)
- ❌ **Don't expose secrets** - Never commit secret keys to Git

### General Security

- ✅ **Input validation** - Validate all user input
- ✅ **Rate limiting** - Limit login attempts
- ✅ **Error messages** - Don't reveal if user exists
- ✅ **CORS** - Configure CORS properly
- ✅ **SQL injection** - Use parameterized queries

---

## Tips for Success

- **Start with JWT:** Easiest to implement in Node.js
- **Use bcrypt:** Industry standard for password hashing
- **Test thoroughly:** Test registration, login, logout, protected routes
- **Handle errors:** Provide clear error messages
- **Use Cursor AI:** Ask Cursor to generate authentication code
- **Keep it simple:** Start with basic auth, add features later
- **Document as you go:** Write down what you learn

---

## Example Authentication Flow

```
1. User Registration:
   User → POST /api/auth/register → Hash password → Store user → Success

2. User Login:
   User → POST /api/auth/login → Verify password → Generate JWT → Return token

3. Access Protected Route:
   User → GET /api/profile (with token) → Verify token → Return data

4. User Logout:
   User → POST /api/auth/logout → Remove token → Success
```

---

## Common Authentication Issues

### Issue: Password not hashing

**Solutions:**

- Check bcrypt installation
- Verify async/await usage
- Check salt rounds

### Issue: Token not working

**Solutions:**

- Verify JWT_SECRET matches
- Check token expiration
- Verify token format (Bearer TOKEN)
- Check token in request headers

### Issue: Protected route not working

**Solutions:**

- Verify middleware is applied
- Check token is sent in request
- Verify token is valid
- Check middleware order

### Issue: User not found on login

**Solutions:**

- Check database connection
- Verify email exists
- Check password comparison
- Verify user was created

---

## Getting Help

- Ask questions in the help channel
- Review authentication documentation:
  - [JWT.io](https://jwt.io/) - JWT token debugger
  - [bcrypt Documentation](https://www.npmjs.com/package/bcrypt)
- Check [FAQ](https://repodin-education.github.io/vibe-coding-materials/faq.html)
- Review [Student Guide](https://repodin-education.github.io/vibe-coding-materials/student-guide.html)
- Contact your teacher if needed

---

## Resources

**Authentication Libraries:**

- [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken) - Node.js JWT library
- [bcrypt](https://www.npmjs.com/package/bcrypt) - Password hashing
- [Passport.js](http://www.passportjs.org/) - Node.js authentication middleware

**Learning Resources:**

- [JWT Authentication Tutorial](https://jwt.io/introduction)
- [Password Hashing Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Authentication vs Authorization](https://auth0.com/blog/authentication-vs-authorization/)

---

## Document History

| Version | Date       | Author                 | Changes         |
| ------- | ---------- | ---------------------- | --------------- |
| 1.0     | 2025-12-25 | RepodIn Education Team | Initial version |
| 1.1     | 2025-12-28 | RepodIn Education Team | Simplified to Node.js only |

---

**Next Review Date:** 2026-03-20

