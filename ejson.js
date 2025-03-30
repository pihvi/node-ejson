import nacl from './lib/nacl-fast.js';
import * as fs from 'node:fs/promises';
import * as path from 'node:path'; // Import path module

// --- Constants ---
const EJSON_REGEX = /^EJ\[(\d):([A-Za-z0-9+=/]{44}):([A-Za-z0-9+=/]{32}):(.+)]$/;
const BASE64 = 'base64';
const HEX = 'hex';
const UTF8 = 'utf8';
const DEFAULT_KEYS_DIR = '/opt/ejson/keys/';

// --- Helper Functions ---

/**
 * Parses an EJSON encrypted string into its components.
 * @param {string} value - The EJSON encrypted string (e.g., "EJ[...]").
 * @returns {{schemaVersion: number, encrypterPublic: string, nonce: string, box: string}} Parsed components.
 * @throws {Error} If the value is not a valid EJSON string.
 */
export const parseEncryptedValue = (value) => {
    const parts = value.match(EJSON_REGEX);
    if (!parts || parts.length !== 5) {
        throw new Error(`Invalid EJSON format: String does not match expected pattern.`);
    }

    // Destructure for clarity, skipping the full match (index 0)
    const [, schemaVersionStr, encrypterPublic, nonce, box] = parts;

    return {
        schemaVersion: parseInt(schemaVersionStr, 10), // Explicit radix
        encrypterPublic,
        nonce,
        box,
    };
};

/**
 * Prepares Buffers for cryptographic operations from string inputs.
 * @param {string} nonce - Base64 encoded nonce.
 * @param {string} theirPublicKey - Base64 encoded public key.
 * @param {string} mySecretKey - Hex encoded secret key.
 * @returns {{nonceBuff: Buffer, theirPubBuff: Buffer, privBuff: Buffer}} Object containing Buffers.
 * @throws {Error} If inputs are not valid base64/hex strings.
 */
const _prepareCryptoArgs = (nonce, theirPublicKey, mySecretKey) => {
    try {
        const nonceBuff = Buffer.from(nonce, BASE64);
        const theirPubBuff = Buffer.from(theirPublicKey, BASE64);
        const privBuff = Buffer.from(mySecretKey, HEX);

        // Basic length checks (optional but good practice for NaCl keys/nonces)
        if (nonceBuff.length !== nacl.box.nonceLength) {
            console.warn(`Warning: Nonce length (${nonceBuff.length}) does not match expected NaCl nonce length (${nacl.box.nonceLength}).`);
        }
        if (theirPubBuff.length !== nacl.box.publicKeyLength) {
            console.warn(`Warning: Public key length (${theirPubBuff.length}) does not match expected NaCl public key length (${nacl.box.publicKeyLength}).`);
        }
        if (privBuff.length !== nacl.box.secretKeyLength) {
            console.warn(`Warning: Secret key length (${privBuff.length}) does not match expected NaCl secret key length (${nacl.box.secretKeyLength}).`);
        }


        return {nonceBuff, theirPubBuff, privBuff};
    } catch (error) {
        // Catch potential Buffer.from errors for invalid encoding
        throw new Error(`Failed to create Buffers for crypto args: ${error.message}`);
    }
};

// --- Core Crypto Functions ---

/**
 * Encrypts a message using NaCl box (public-key authenticated encryption).
 * @param {string} message - The plaintext message (UTF-8 encoded).
 * @param {string} nonce - Base64 encoded nonce.
 * @param {string} theirPublicKey - Recipient's public key (Base64 encoded).
 * @param {string} mySecretKey - Sender's secret key (Hex encoded).
 * @returns {string} Base64 encoded encrypted message (ciphertext).
 */
export const encrypt = (message, nonce, theirPublicKey, mySecretKey) => {
    const msgBuff = Buffer.from(message, UTF8);
    const {nonceBuff, theirPubBuff, privBuff} = _prepareCryptoArgs(nonce, theirPublicKey, mySecretKey);
    const encryptedData = nacl.box(msgBuff, nonceBuff, theirPubBuff, privBuff);
    return Buffer.from(encryptedData).toString(BASE64);
};

/**
 * Decrypts a message using NaCl box (public-key authenticated encryption).
 * @param {string} encryptedMessageBase64 - The Base64 encoded ciphertext.
 * @param {string} nonce - Base64 encoded nonce used for encryption.
 * @param {string} theirPublicKey - Sender's public key (Base64 encoded).
 * @param {string} mySecretKey - Recipient's secret key (Hex encoded).
 * @returns {string | null} Decrypted plaintext message (UTF-8 encoded), or null if decryption fails.
 */
export const decrypt = (encryptedMessageBase64, nonce, theirPublicKey, mySecretKey) => {
    const msgBuff = Buffer.from(encryptedMessageBase64, BASE64);
    const {nonceBuff, theirPubBuff, privBuff} = _prepareCryptoArgs(nonce, theirPublicKey, mySecretKey);
    const decryptedData = nacl.box.open(msgBuff, nonceBuff, theirPubBuff, privBuff);

    if (!decryptedData) {
        // Decryption failed (e.g., wrong key, corrupted message)
        console.error("Decryption failed: nacl.box.open returned null. Check keys, nonce, and ciphertext integrity.");
        return null; // Or throw an error if preferred: throw new Error("Decryption failed");
    }

    return Buffer.from(decryptedData).toString(UTF8);
};


// --- Configuration ---

/**
 * Default configuration settings.
 */
export const defaultConfig = {
    /** Path to the EJSON file. Overrides other envFile settings if set. */
    envFilePath: process.env.NODE_EJSON_FILE_PATH ?? undefined,
    /** Directory containing the EJSON file (used if envFilePath is not set). */
    envFileDir: process.env.NODE_EJSON_DIR ?? '.',
    /** Filename prefix (e.g., environment name) (used if envFilePath is not set). */
    envFilePrefix: process.env.NODE_ENV ?? 'development', // Default to 'development' if NODE_ENV unset
    /** Filename suffix (used if envFilePath is not set). */
    envFileSuffix: '.ejson',
    /** Directory containing private key files. */
    keysDir: process.env.NODE_EJSON_KEYS_DIR ?? DEFAULT_KEYS_DIR,
    /**
     * Asynchronously retrieves the private key corresponding to a public key.
     * Checks NODE_EJSON_PRIVATE_KEY environment variable first, then looks for a file
     * named <publicKey> in the keysDir.
     * @param {string} publicKey - The public key whose corresponding private key is needed.
     * @param {object} conf - The active configuration object.
     * @returns {Promise<string>} The private key (Hex encoded).
     * @throws {Error} If the private key cannot be found or read.
     */
    getPrivateKey: async (publicKey, conf) => {
        if (process.env.NODE_EJSON_PRIVATE_KEY) {
            return process.env.NODE_EJSON_PRIVATE_KEY;
        }
        if (!publicKey || typeof publicKey !== 'string' || publicKey.length === 0) {
            throw new Error("Cannot fetch private key: Invalid or missing public key provided.");
        }

        // Basic check to prevent path traversal - ensure publicKey is just the key string
        if (publicKey.includes('/') || publicKey.includes('..')) {
            throw new Error(`Invalid public key format for filename: "${publicKey}"`);
        }

        const keyFilePath = path.join(conf.keysDir, publicKey);
        try {
            // Read file, trim whitespace (keys often have trailing newlines)
            const key = await fs.readFile(keyFilePath, UTF8);
            return key.trim();
        } catch (error) {
            if (error.code === 'ENOENT') {
                throw new Error(`Private key file not found at ${keyFilePath}. Ensure NODE_EJSON_PRIVATE_KEY is set or the file exists.`);
            }
            throw new Error(`Failed to read private key file at ${keyFilePath}: ${error.message}`);
        }
    },
};

/**
 * Merges user-provided configuration with defaults.
 * @param {Partial<typeof defaultConfig>} [userConfig] - User configuration overrides.
 * @returns {typeof defaultConfig} The merged configuration object.
 */
const mergeConfigs = (userConfig) => ({...defaultConfig, ...userConfig});

// --- EJSON Processing ---

/**
 * Recursively processes an object, decrypting EJSON strings in place.
 * Handles `_` prefixed keys according to EJSON conventions.
 * MUTATES the input object.
 * @param {object} obj - The object to process.
 * @param {string} privateKey - The private key (Hex encoded) for decryption.
 * @throws {Error} If decryption fails for any value.
 */
const processObjectFields = (obj, privateKey) => {
    for (const key in obj) {
        if (!Object.hasOwnProperty.call(obj, key)) {
            continue; // Skip properties from prototype chain
        }

        const value = obj[key];

        if (key.startsWith('_')) {
            // EJSON convention: _key defines a default if key doesn't exist
            const keyName = key.slice(1);
            if (!(keyName in obj)) {
                obj[keyName] = value;
            }
            // Often, we want to remove the _key after processing, uncomment if needed:
            // delete obj[key];
        } else if (typeof value === 'string' && value.startsWith('EJ[')) {
            try {
                const parsed = parseEncryptedValue(value);
                const decryptedValue = decrypt(parsed.box, parsed.nonce, parsed.encrypterPublic, privateKey);

                if (decryptedValue === null) {
                    // Handle decryption failure as per 'decrypt' function's return
                    throw new Error(`Decryption failed for key "${key}". Check keys/ciphertext.`);
                }
                obj[key] = decryptedValue;

            } catch (error) {
                // Add context to errors from parseEncryptedValue or decrypt
                throw new Error(`Error processing key "${key}": ${error.message}`);
            }
        } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
            // Recurse into nested plain objects
            processObjectFields(value, privateKey);
        }
        // Note: Arrays containing EJSON strings are not typically processed by standard ejson tools.
        // If you need to handle arrays, add specific logic here.
    }
    // No return value needed as the object is mutated directly.
};


/**
 * Reads an EJSON file, decrypts its values, and returns the resulting object.
 * @param {Partial<typeof defaultConfig>} [userConfig] - Optional configuration overrides.
 * @returns {Promise<object>} A promise that resolves to the decrypted configuration object.
 * @throws {Error} If the file cannot be read, parsed, or decrypted.
 */
export const processEjson = async (userConfig) => {
    const conf = mergeConfigs(userConfig);
    const filePath = conf.envFilePath ?? path.join(conf.envFileDir, `${conf.envFilePrefix}${conf.envFileSuffix}`);

    let rawConfJson;
    try {
        rawConfJson = await fs.readFile(filePath, UTF8);
    } catch (error) {
        throw new Error(`Failed to read EJSON file at "${filePath}": ${error.message}`);
    }

    let rawConf;
    try {
        rawConf = JSON.parse(rawConfJson);
    } catch (error) {
        throw new Error(`Failed to parse JSON from EJSON file at "${filePath}": ${error.message}`);
    }

    const publicKey = rawConf['_public_key'];
    if (!publicKey) {
        throw new Error(`EJSON file at "${filePath}" is missing the required '_public_key' field.`);
    }

    let privateKey;
    try {
        privateKey = await conf.getPrivateKey(publicKey, conf);
    } catch (error) {
        // Add context to errors from getPrivateKey
        throw new Error(`Failed to retrieve private key for public key "${publicKey}": ${error.message}`);
    }

    try {
        // Process the object in place
        processObjectFields(rawConf, privateKey);
    } catch (error) {
        // Add context to errors from processObjectFields
        throw new Error(`Failed during EJSON decryption process for file "${filePath}": ${error.message}`);
    }


    // Optionally remove _public_key after processing
    // delete rawConf['_public_key'];

    return rawConf;
};

// Default export remains the main function
export default processEjson;
