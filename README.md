# node-ejson

Node.js native decrypter for EJSON (Encrypted JSON)

## Description

node-ejson is a lightweight Node.js library for working with EJSON (Encrypted JSON) files. It provides functionality to decrypt EJSON-encrypted values, making it easy to manage sensitive configuration data in your Node.js applications.

## Installation

```
npm install node-ejson
```

## Usage

```javascript
import processEjson from 'node-ejson';

const config = await processEjson();
console.log(config.decrypted_secret);
```

## Features

- Decrypt EJSON-encrypted values
- Support for custom configuration options
- Environment variable support
- Nested object decryption

## Configuration

node-ejson uses the following default configuration:

```javascript
{
  envFilePath: process.env.NODE_EJSON_FILE_PATH ?? undefined,
  envFileDir: '.',
  envFilePrefix: process.env.NODE_ENV ?? 'env',
  envFileSuffix: '.ejson',
  keysDir: '/opt/ejson/keys/',
  getPrivateKey: async (publicKey, conf) => {
    if (process.env.NODE_EJSON_PRIVATE_KEY) {
      return process.env.NODE_EJSON_PRIVATE_KEY;
    } else {
      return await fs.readFile(conf.keysDir + publicKey, 'utf8');
    }
  }
}
```

You can override these settings by passing a configuration object to `processEjson()`.

## Environment Variables

- `NODE_EJSON_FILE_PATH`: Custom path to the EJSON file
- `NODE_ENV`: Used as the prefix for the EJSON file name (default: 'env')
- `NODE_EJSON_PRIVATE_KEY`: Private key for decryption (optional)

## Testing

Run the test suite with:

```
npm test
```

## License

MIT

## TODO

- Include common configs
- Allow local overrides
