# Custom JWT Library

A minimal, production-minded JSON Web Token (JWT) implementation in Node.js supporting **HS256** and **RS256** algorithms.  
Built with the native `crypto` module, no external dependencies.

## Features
- Sign and verify tokens using HMAC (HS256) or RSA (RS256)
- Constant-time signature comparison
- Standard claims validation (`exp`, `nbf`, `iat`, `iss`, `aud`, `sub`)
- Configurable clock tolerance and required claims
- Typed errors for fine-grained error handling