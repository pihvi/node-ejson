# node-ejson

Node.js native decrypter for EJSON (Encrypted JSON)

## Description

node-ejson is a lightweight Node.js library for working with EJSON (Encrypted JSON). It provides functionality to decrypt EJSON-encrypted values, making it easy to manage sensitive configuration data in your Node.js applications. This library allows you to pass EJSON content directly as a string and provide your own logic for private key retrieval.

## Installation

```
npm install node-ejson
```

## Usage

The primary function `processEjson` now expects the EJSON content as its first argument and a configuration object as its second. The configuration object must include an asynchronous function `getPrivateKey` which takes a public key string and should return the corresponding private key.

```javascript
import processEjson from 'node-ejson';
import fs from 'node:fs/promises'; // Or any other method to get your EJSON content and key

// Example: Reading EJSON content from a file (user-managed)
const ejsonFileContent = await fs.readFile('path/to/your/env.ejson', 'utf8');

// Example: Providing the private key (user-managed)
// This could be from an environment variable, a file, or a secrets manager
const myPrivateKey = process.env.MY_EJSON_PRIVATE_KEY || await fs.readFile('path/to/your/privatekeyfile', 'utf8');

async function main() {
  try {
    const config = await processEjson(ejsonFileContent, {
      getPrivateKey: async (publicKeyIdentifier) => {
        // publicKeyIdentifier is the string after _public_key in your EJSON file.
        // Implement your logic to fetch the correct private key.
        // For example, if you have only one key or a map:
        if (publicKeyIdentifier === "your_public_key_string_from_ejson") {
          return myPrivateKey;
        }
        throw new Error(`Private key not found for public key: ${publicKeyIdentifier}`);
      }
    });

    console.log('Decrypted secret:', config.some_secret_key);
    // Example: Accessing a nested secret
    // console.log('Nested secret:', config.database.password);
  } catch (error) {
    console.error('Error processing EJSON:', error);
  }
}

main();
```

## Features

- Decrypt EJSON-encrypted values
- Flexible: You control how EJSON content and private keys are loaded
- Support for custom configuration options for `getPrivateKey` logic
- Environment variable support (managed by your `getPrivateKey` implementation)
- Nested object decryption

## Configuration

The `processEjson` function takes two arguments:
1.  `ejsonContent (String)`: The full EJSON content as a string.
2.  `config (Object)`: A configuration object. The most important part of this object is `getPrivateKey`.

### `config.getPrivateKey(publicKey, conf)`

-   **Required**: This asynchronous function is responsible for retrieving the private key.
-   `publicKey (String)`: The public key string found in the `_public_key` field of your EJSON data.
-   `conf (Object)`: The rest of the configuration object passed to `processEjson` is also passed here, allowing you to include other settings your `getPrivateKey` function might need (e.g., paths, flags).

**Default Behavior of `getPrivateKey` if not overridden by user (as of previous versions):**
Previously, the library had a default `getPrivateKey` that would:
1. Check `process.env.NODE_EJSON_PRIVATE_KEY`.
2. If not found, try to read a file named `publicKey` from a `keysDir` (defaulting to `/opt/ejson/keys/`).

**Current Approach:** You **must** provide your own `getPrivateKey` function. You can replicate the old default behavior if desired:

```javascript
// Example of replicating old default getPrivateKey logic
import fs from 'node:fs/promises';

// ... (inside your main logic or a helper module)
const customConfig = {
  keysDir: process.env.MY_KEYS_DIR || '/opt/ejson/keys/', // Example custom option
  getPrivateKey: async (publicKey, conf) => {
    if (process.env.NODE_EJSON_PRIVATE_KEY) {
      return process.env.NODE_EJSON_PRIVATE_KEY;
    } else {
      // conf.keysDir would be this customConfig.keysDir
      return await fs.readFile(conf.keysDir + publicKey, 'utf8');
    }
  }
  // ... other custom config options you might need for getPrivateKey
};

// const processed = await processEjson(ejsonString, customConfig);
```

Other fields in the `defaultConfig` related to file paths (`envFilePath`, `envFileDir`, `envFilePrefix`, `envFileSuffix`) are no longer directly used by `processEjson` for loading the EJSON *content*, as this is now passed as an argument. However, you can include similar fields in your custom config if your `getPrivateKey` logic needs them.

## Environment Variables

How environment variables are used is now largely up to your custom `getPrivateKey` implementation.
If you choose to replicate or adapt the library's previous default behavior for key loading, you might use:

-   `NODE_EJSON_PRIVATE_KEY`: To directly provide the private key.
-   Variables to specify paths if your `getPrivateKey` reads keys from files (e.g., `MY_KEYS_DIR` in the example above).

The library itself no longer directly reads `NODE_EJSON_FILE_PATH` or uses `NODE_ENV` to construct file paths for the EJSON content.

## Testing

Run the test suite with:

```
npm test
```

## License

MIT

## TODO

- Include common configs (examples of `getPrivateKey` for various scenarios)
- Allow local overrides (patterns for managing configurations)
