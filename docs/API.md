# Node.js Auth API Documentation

## Authentication Endpoints

### Register User
- **POST** `/api/auth/register`
- **Body**: `{ "email": "user@example.com", "password": "SecurePass123!" }`

### Login User
- **POST** `/api/auth/login`
- **Body**: `{ "email": "user@example.com", "password": "SecurePass123!" }`
- **Response**: Returns access token and refresh token (or temp token if 2FA is enabled)

### Login with 2FA
- **POST** `/api/auth/login/2fa`
- **Body**: `{ "otp": "123456", "tempToken": "jwt_token" }`

### Refresh Token
- **POST** `/api/auth/refresh`
- **Body**: `{ "refreshToken": "uuid_token" }`

## 2FA Management Endpoints

### Generate 2FA Secret
- **POST** `/api/auth/2fa/generate`
- **Headers**: `Authorization: Bearer <access_token>`
- **Body**: `{ "password": "SecurePass123!" }`
- **Security**: Always requires password verification
- **Behavior**: 
  - If 2FA is not enabled: Generates new secret and QR code
  - If 2FA is already enabled: Returns existing secret and QR code
- **Response**: `{ "otpauthUrl": "...", "qrCodeDataURL": "...", "message": "..." }`

### Confirm 2FA Setup
- **POST** `/api/auth/2fa/confirm`
- **Headers**: `Authorization: Bearer <access_token>`
- **Body**: `{ "otp": "123456" }`
- **Response**: `{ "message": "2FA enabled successfully", "twoFactorEnabled": true }`

### Reset 2FA (Requires Password)
- **POST** `/api/auth/2fa/reset`
- **Headers**: `Authorization: Bearer <access_token>`
- **Body**: `{ "password": "SecurePass123!" }`
- **Security**: Requires current password verification
- **Response**: `{ "message": "2FA reset successfully", "otpauthUrl": "...", "qrCodeDataURL": "..." }`

### Disable 2FA (Requires Password)
- **POST** `/api/auth/2fa/disable`
- **Headers**: `Authorization: Bearer <access_token>`
- **Body**: `{ "password": "SecurePass123!" }`
- **Security**: Requires current password verification
- **Response**: `{ "message": "2FA disabled successfully", "twoFactorEnabled": false }`

## 2FA Security Features

### Industry-Standard Behavior
- **Single Secret**: One active 2FA secret per user (like Google, GitHub, AWS)
- **Password Protection**: All 2FA operations require password verification
- **Account Protection**: Prevents malicious 2FA setup that could lock out users
- **Graceful Handling**: Existing 2FA setup is preserved when calling generate
- **Secure Reset**: New secrets require password verification and re-confirmation

### Security Benefits
- Prevents accidental 2FA secret regeneration
- Requires password verification for sensitive operations
- Follows industry best practices for 2FA management
- Maintains user's existing authenticator setup

## Example Usage Flow

### Initial 2FA Setup
1. `POST /api/auth/2fa/generate` - Provide password to get QR code
2. Scan QR code with authenticator app
3. `POST /api/auth/2fa/confirm` - Confirm with OTP code

### Viewing Existing 2FA Setup
1. `POST /api/auth/2fa/generate` - Provide password to view existing QR code and secret

### Resetting 2FA (if device lost)
1. `POST /api/auth/2fa/reset` - Provide password to get new QR code
2. Scan new QR code with authenticator app
3. `POST /api/auth/2fa/confirm` - Confirm with new OTP code

### Disabling 2FA
1. `POST /api/auth/2fa/disable` - Provide password to disable 2FA