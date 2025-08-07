# 🔐 Node.js Authentication API

> **🚧 Work in Progress** - This project is actively being developed as a learning exercise and portfolio piece.

A secure, production-ready Node.js authentication API built with Express, TypeScript, and PostgreSQL. This project demonstrates modern backend development practices, security best practices, and clean architecture patterns.

## ✨ Features

### Core Authentication
- ✅ **User Registration & Login** - Secure user account creation and authentication
- ✅ **JWT Token Management** - Access tokens with refresh token rotation
- ✅ **Password Security** - Bcrypt hashing with configurable rounds
- ✅ **Input Validation** - Zod schemas for request validation

### Advanced Security
- ✅ **Two-Factor Authentication (2FA)** - TOTP-based 2FA with QR codes
- ✅ **Rate Limiting** - Protection against brute force attacks
- ✅ **Encrypted Secrets** - Database encryption for sensitive 2FA data
- ✅ **Token Cleanup** - Automated cleanup of expired tokens
- ✅ **Account Management** - Secure account deletion with cascade cleanup

### Infrastructure & DevOps
- ✅ **Database Management** - PostgreSQL with Prisma ORM
- ✅ **TypeScript** - Full type safety across the application
- ✅ **Environment Configuration** - Secure configuration management
- ✅ **Scheduled Jobs** - Background cleanup tasks with node-cron
- ✅ **API Documentation** - Comprehensive endpoint documentation

## 🛠️ Tech Stack

### Backend
- **Runtime**: Node.js
- **Framework**: Express.js
- **Language**: TypeScript
- **Database**: PostgreSQL
- **ORM**: Prisma

### Security & Authentication
- **Password Hashing**: bcrypt
- **JWT Tokens**: jsonwebtoken
- **2FA**: speakeasy (TOTP)
- **QR Codes**: qrcode
- **Rate Limiting**: express-rate-limit

### Development Tools
- **Development Server**: ts-node-dev
- **Type Checking**: TypeScript compiler
- **Schema Validation**: Zod

## 🚀 Getting Started

### Prerequisites
- Node.js (v16+)
- PostgreSQL database
- npm or yarn

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/node-auth.git
   cd node-auth
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment Setup**
   ```bash
   cp .env.example .env
   # Configure your environment variables
   ```

   **⚠️ Required Environment Variables**
   
   The following environment variables are **mandatory** and must be configured:
   
   | Variable | Description | Example |
   |----------|-------------|---------|
   | `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@localhost:5432/db` |
   | `JWT_SECRET` | JWT signing key (min 32 chars) | Generate with: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` |
   | `ENCRYPTION_KEY_V1` | Encryption key for 2FA secrets (min 32 chars) | Generate with: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` |
   
   **📝 Optional Environment Variables** (with defaults)
   
   | Variable | Default | Description |
   |----------|---------|-------------|
   | `PORT` | `3000` | Server port |
   | `JWT_EXPIRES_IN` | `15m` | Access token expiration |
   | `JWT_REFRESH_EXPIRES_IN` | `7d` | Refresh token expiration |
   | `ENCRYPTION_VERSION_FOR_NEW_DATA` | `v1` | Encryption version |
   | Rate limiting vars | See `.env.example` | Request limits configuration |
   | `CLEANUP_SCHEDULE` | `0 2 * * *` | Token cleanup schedule |

4. **Database Setup**
   ```bash
   npx prisma migrate dev
   npx prisma generate
   ```

5. **Start Development Server**
   ```bash
   npm run dev
   ```

The API will be available at `http://localhost:3000`

## 📚 API Documentation

### Authentication Endpoints

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

#### Refresh Token
```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "your-refresh-token"
}
```

### Two-Factor Authentication

#### Generate 2FA Secret
```http
POST /api/auth/2fa/generate
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "password": "SecurePass123!"
}
```

#### Confirm 2FA Setup
```http
POST /api/auth/2fa/confirm
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "otp": "123456"
}
```

For complete API documentation, see [docs/API.md](docs/API.md)

## 🔒 Security Features

### Industry-Standard Practices
- **Password Hashing**: Bcrypt with configurable salt rounds
- **JWT Security**: Short-lived access tokens with refresh token rotation
- **Rate Limiting**: Configurable limits for different endpoint categories
- **Input Validation**: Comprehensive request validation with Zod
- **Database Security**: Encrypted storage of sensitive 2FA secrets

### Two-Factor Authentication
- **TOTP-based**: Compatible with Google Authenticator, Authy, etc.
- **QR Code Generation**: Easy setup with authenticator apps
- **Backup Codes**: Recovery options for lost devices (planned)
- **Password Protection**: All 2FA operations require password verification

## 📁 Project Structure

```
src/
├── controllers/          # Request handlers and business logic
│   ├── authController.ts # Authentication endpoints
│   └── helloController.ts # Demo endpoints
├── middleware/           # Express middleware
│   ├── authMiddleware.ts # JWT verification
│   └── rateLimitMiddleware.ts # Rate limiting
├── routes/               # API route definitions
│   ├── authRoutes.ts     # Authentication routes
│   └── helloRoutes.ts    # Demo routes
├── schemas/              # Zod validation schemas
│   └── authSchemas.ts    # Auth request validation
├── services/             # Business logic services
│   └── cleanupService.ts # Token cleanup utilities
├── utils/                # Utility functions
│   └── encryption.ts     # Encryption helpers
├── jobs/                 # Scheduled background jobs
│   └── scheduler.ts      # Token cleanup scheduler
├── constants.ts          # Application configuration
└── index.ts             # Application entry point
```

## 🔧 Development

### Available Scripts
- `npm run dev` - Start development server with hot reload
- `npm run build` - Build the TypeScript project
- `npm start` - Run the built application

### Database Management
- `npx prisma migrate dev` - Create and apply migrations
- `npx prisma generate` - Generate Prisma client
- `npx prisma studio` - Open database browser

## 👨‍💻 About

This project was built as a learning exercise to demonstrate:
- **Modern Node.js Development** - TypeScript, Express, modern tooling
- **Security Best Practices** - Authentication, encryption, input validation
- **Database Design** - Relational modeling with Prisma
- **Clean Architecture** - Separation of concerns, maintainable code
- **Production Readiness** - Error handling, logging, configuration management

**Background**: Built by a .NET developer learning Node.js ecosystem and modern JavaScript/TypeScript development patterns. This project serves as both a learning tool and a foundation for future Node.js projects.

## 📝 License

This project is licensed under the ISC License. See [LICENSE](LICENSE) file for details.

---

**⭐ If this project helps you learn Node.js authentication patterns, please consider giving it a star!**