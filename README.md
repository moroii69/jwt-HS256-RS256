# custom JWT library

a minimal, production-minded JSON Web Token (JWT) implementation in node.js supporting **HS256** and **RS256** algorithms.  
built with the native `crypto` module, no external dependencies.

learn more about HS256 & RS256 algorithms here - https://auth0.com/blog/rs256-vs-hs256-whats-the-difference/


## features
- sign and verify tokens using HMAC (HS256) or RSA (RS256)
- constant-time signature comparison
- standard claims validation (`exp`, `nbf`, `iat`, `iss`, `aud`, `sub`)
- configurable clock tolerance and required claims
- typed errors for fine-grained error handling

## usage

### HS256 example
```
const { sign, verify } = require("./jwt");

const secret = "supersecret";
const payload = { userId: 123 };

const token = sign(payload, secret, { algorithm: "HS256", expiresIn: 60 });
console.log("Token:", token);

const decoded = verify(token, secret, { algorithms: ["HS256"] });
console.log("Decoded:", decoded);
```

### RS256 example
```
const fs = require("fs");
const { sign, verify } = require("./jwt");

const privateKey = fs.readFileSync("./test/private.pem");
const publicKey = fs.readFileSync("./test/public.pem");

const payload = { userId: 456 };

const token = sign(payload, { privateKey }, { algorithm: "RS256", expiresIn: 60 });
console.log("Token:", token);

const decoded = verify(token, { publicKey }, { algorithms: ["RS256"] });
console.log("Decoded:", decoded);
```

## running tests
`
npm test
`
Includes coverage for:
- Valid HS256 and RS256 signing/verification
- Rejection of tampered signatures
- Expired token rejection


## security note
- **DO NOT** use the `test/private.pem` and `test/public.pem` keys in production.
- always keep real private keys secure and out of source
