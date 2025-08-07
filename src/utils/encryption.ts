import crypto from 'crypto';
import dotenv from 'dotenv';
import { APP_CONFIG } from '../constants';

interface EncryptedData {
  encrypted: string;
  iv: string;
  tag: string;
  salt: string; // Unique salt used for key derivation
}

/**
 * Derives a 32-byte key from the provided password/key string using PBKDF2 with a unique salt
 * @param keyString - The key string from environment variables
 * @param salt - Unique salt for key derivation (must be provided for security)
 * @returns 32-byte key for AES-256
 */
function deriveKey(keyString: string, salt: Buffer): Buffer {
  return crypto.pbkdf2Sync(keyString, salt, APP_CONFIG.ENCRYPTION.PBKDF2_ITERATIONS, APP_CONFIG.ENCRYPTION.KEY_LENGTH, 'sha256');
}

/**
 * Async version of key derivation for better performance in high-concurrency scenarios
 * @param keyString - The key string from environment variables
 * @param salt - Unique salt for key derivation (must be provided for security)
 * @returns Promise resolving to 32-byte key for AES-256
 */
async function deriveKeyAsync(keyString: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(keyString, salt, APP_CONFIG.ENCRYPTION.PBKDF2_ITERATIONS, APP_CONFIG.ENCRYPTION.KEY_LENGTH, 'sha256', (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

/**
 * Gets the encryption key for a specific version from environment variables
 * @param version - The key version ('v1' or 'v2')
 * @param salt - Unique salt for key derivation
 * @returns The derived encryption key
 * @throws Error if the key is not found or invalid
 */
function getEncryptionKey(version: string, salt: Buffer): Buffer {
  const keyEnvVar = version === 'v1' ? 'ENCRYPTION_KEY_V1' : 'ENCRYPTION_KEY_V2';
  const keyString = process.env[keyEnvVar];
  
  if (!keyString) {
    throw new Error(`Encryption key ${keyEnvVar} not found in environment variables`);
  }
  
  if (keyString.length < 32) {
    throw new Error(`Encryption key ${keyEnvVar} must be at least 32 characters long`);
  }
  
  return deriveKey(keyString, salt);
}

/**
 * Gets the current encryption version for new data from environment variables
 * @returns The encryption version to use for new data ('v1' or 'v2')
 */
export function getCurrentEncryptionVersion(): string {
  const version = process.env.ENCRYPTION_VERSION_FOR_NEW_DATA || 'v1';
  
  if (version !== 'v1' && version !== 'v2') {
    throw new Error('ENCRYPTION_VERSION_FOR_NEW_DATA must be either "v1" or "v2"');
  }
  
  return version;
}

/**
 * Encrypts a string using AES-256-GCM with the specified key version
 * @param text - The text to encrypt
 * @param version - The encryption key version to use ('v1' or 'v2')
 * @returns Object containing encrypted data, IV, authentication tag, and unique salt
 * @throws Error if encryption fails
 */
export function encryptSecret(text: string, version: string): EncryptedData {
  try {
    // Generate unique salt for this encryption operation
    const salt = crypto.randomBytes(APP_CONFIG.ENCRYPTION.SALT_LENGTH);
    const key = getEncryptionKey(version, salt);
    const iv = crypto.randomBytes(APP_CONFIG.ENCRYPTION.IV_LENGTH);
    const cipher = crypto.createCipheriv(APP_CONFIG.ENCRYPTION.ALGORITHM, key, iv);
    cipher.setAAD(Buffer.from(version)); // Use version as additional authenticated data
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      tag: tag.toString('hex'),
      salt: salt.toString('hex')
    };
  } catch (error) {
    throw new Error(`Failed to encrypt secret with version ${version}: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Decrypts a string using AES-256-GCM with the specified key version
 * @param encryptedData - Object containing encrypted data, IV, authentication tag, and salt
 * @param version - The encryption key version that was used ('v1' or 'v2')
 * @returns The decrypted text
 * @throws Error if decryption fails or authentication fails
 */
export function decryptSecret(encryptedData: EncryptedData, version: string): string {
  try {
    // Use the same salt that was used during encryption
    const salt = Buffer.from(encryptedData.salt, 'hex');
    const key = getEncryptionKey(version, salt);
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const decipher = crypto.createDecipheriv(APP_CONFIG.ENCRYPTION.ALGORITHM, key, iv);
    
    decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));
    decipher.setAAD(Buffer.from(version)); // Use same version as AAD
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    throw new Error(`Failed to decrypt secret with version ${version}: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Encrypts a 2FA secret using the current encryption version
 * @param secret - The base32 2FA secret to encrypt
 * @returns Object containing encrypted data and version used
 */
export function encrypt2FASecret(secret: string): { encryptedData: EncryptedData; version: string } {
  const version = getCurrentEncryptionVersion();
  const encryptedData = encryptSecret(secret, version);
  
  return {
    encryptedData,
    version
  };
}

/**
 * Decrypts a 2FA secret using the specified version
 * @param encryptedData - The encrypted data object
 * @param version - The encryption version that was used
 * @returns The decrypted base32 2FA secret
 */
export function decrypt2FASecret(encryptedData: EncryptedData, version: string): string {
  return decryptSecret(encryptedData, version);
}

/**
 * Serializes encrypted data to a string for database storage
 * @param encryptedData - The encrypted data object
 * @returns Base64-encoded JSON string
 */
export function serializeEncryptedData(encryptedData: EncryptedData): string {
  return Buffer.from(JSON.stringify(encryptedData)).toString('base64');
}

/**
 * Deserializes encrypted data from database storage
 * @param serializedData - Base64-encoded JSON string
 * @returns The encrypted data object
 * @throws Error if data is invalid
 */
export function deserializeEncryptedData(serializedData: string): EncryptedData {
  try {
    const jsonString = Buffer.from(serializedData, 'base64').toString('utf8');
    const data = JSON.parse(jsonString);
    
    if (!data.encrypted || !data.iv || !data.tag) {
      throw new Error('Invalid encrypted data format - missing required fields (encrypted, iv, tag)');
    }
    
    // Check for salt field - required for security
    if (!data.salt) {
      throw new Error('Invalid encrypted data format - missing salt field. This data was encrypted with an insecure version and must be re-encrypted.');
    }
    
    return data as EncryptedData;
  } catch (error) {
    throw new Error(`Failed to deserialize encrypted data: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Async version of encryptSecret for high-concurrency scenarios
 * @param text - The text to encrypt
 * @param version - The encryption key version to use ('v1' or 'v2')
 * @returns Promise resolving to object containing encrypted data, IV, authentication tag, and unique salt
 * @throws Error if encryption fails
 */
export async function encryptSecretAsync(text: string, version: string): Promise<EncryptedData> {
  try {
    // Generate unique salt for this encryption operation
    const salt = crypto.randomBytes(APP_CONFIG.ENCRYPTION.SALT_LENGTH);
    const key = await deriveKeyAsync(getKeyString(version), salt);
    const iv = crypto.randomBytes(APP_CONFIG.ENCRYPTION.IV_LENGTH);
    const cipher = crypto.createCipheriv(APP_CONFIG.ENCRYPTION.ALGORITHM, key, iv);
    cipher.setAAD(Buffer.from(version)); // Use version as additional authenticated data
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      tag: tag.toString('hex'),
      salt: salt.toString('hex')
    };
  } catch (error) {
    throw new Error(`Failed to encrypt secret with version ${version}: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Async version of decryptSecret for high-concurrency scenarios
 * @param encryptedData - Object containing encrypted data, IV, authentication tag, and salt
 * @param version - The encryption key version that was used ('v1' or 'v2')
 * @returns Promise resolving to the decrypted text
 * @throws Error if decryption fails or authentication fails
 */
export async function decryptSecretAsync(encryptedData: EncryptedData, version: string): Promise<string> {
  try {
    // Use the same salt that was used during encryption
    const salt = Buffer.from(encryptedData.salt, 'hex');
    const key = await deriveKeyAsync(getKeyString(version), salt);
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const decipher = crypto.createDecipheriv(APP_CONFIG.ENCRYPTION.ALGORITHM, key, iv);
    
    decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));
    decipher.setAAD(Buffer.from(version)); // Use same version as AAD
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    throw new Error(`Failed to decrypt secret with version ${version}: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Helper function to get the key string for a version (used by async functions)
 * @param version - The key version ('v1' or 'v2')
 * @returns The key string from environment variables
 * @throws Error if key not found
 */
function getKeyString(version: string): string {
  const keyEnvVar = version === 'v1' ? 'ENCRYPTION_KEY_V1' : 'ENCRYPTION_KEY_V2';
  const keyString = process.env[keyEnvVar];
  
  if (!keyString) {
    throw new Error(`Encryption key ${keyEnvVar} not found in environment variables`);
  }
  
  if (keyString.length < 32) {
    throw new Error(`Encryption key ${keyEnvVar} must be at least 32 characters long`);
  }
  
  return keyString;
}