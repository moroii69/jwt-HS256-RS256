// jwt.js
// Minimal production-minded JWT implementation supporting HS256 and RS256.
// Node.js built-in 'crypto' only (v12+). Not a drop-in replacement for libraries,
// but demonstrates secure, careful implementation details.

const crypto = require("crypto");

const DEFAULTS = {
  alg: "HS256",
  clockToleranceSec: 5, // seconds of allowed clock skew
};

class JWTError extends Error {}
class TokenExpiredError extends JWTError {}
class TokenNotActiveError extends JWTError {}
class InvalidTokenError extends JWTError {}
class SignatureVerificationError extends JWTError {}
class AlgorithmError extends JWTError {}

// --- Utilities ---
function base64urlEncode(input) {
  // input: Buffer or string
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input));
  return buf.toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function base64urlDecodeToBuffer(b64u) {
  if (typeof b64u !== "string") throw new TypeError("base64url input must be a string");
  // Convert from base64url to base64
  let b64 = b64u.replace(/-/g, "+").replace(/_/g, "/");
  // Pad
  const padLen = (4 - (b64.length % 4)) % 4;
  b64 += "=".repeat(padLen);
  return Buffer.from(b64, "base64");
}

function safeJsonParse(str) {
  try {
    return JSON.parse(str);
  } catch (e) {
    throw new InvalidTokenError("Invalid JSON in token");
  }
}

function isObject(o) {
  return typeof o === "object" && o !== null && !Array.isArray(o);
}

// constant-time compare of two Buffers
function constantTimeEqual(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    a = Buffer.from(a);
    b = Buffer.from(b);
  }
  if (a.length !== b.length) {
    // Use compare on equal-length buffers only; to avoid leaking length via timing,
    // compare with a buffer of the same length created deterministically.
    const fake = Buffer.alloc(a.length);
    return !crypto.timingSafeEqual(Buffer.concat([a, fake]).slice(0, a.length), b);
  }
  return crypto.timingSafeEqual(a, b);
}

// time helpers (all in seconds since epoch)
function nowSec() {
  return Math.floor(Date.now() / 1000);
}

// --- Signing / verifying primitives ---
function hmacSign(data, secret, algorithm = "HS256") {
  const algo = algorithm.toLowerCase();
  if (!algo.startsWith("hs")) throw new AlgorithmError("Unsupported HMAC algorithm: " + algorithm);
  const nodeAlgo = algo === "hs256" ? "sha256" : algo === "hs384" ? "sha384" : algo === "hs512" ? "sha512" : null;
  if (!nodeAlgo) throw new AlgorithmError("Unsupported HMAC algorithm: " + algorithm);
  return crypto.createHmac(nodeAlgo, secret).update(data).digest();
}

function rsaSign(data, privateKeyPem, algorithm = "RS256") {
  const algo = algorithm.toLowerCase();
  const nodeAlgo = algo === "rs256" ? "RSA-SHA256" : algo === "rs384" ? "RSA-SHA384" : algo === "rs512" ? "RSA-SHA512" : null;
  if (!nodeAlgo) throw new AlgorithmError("Unsupported RSA algorithm: " + algorithm);
  return crypto.createSign(nodeAlgo).update(data).end().sign(privateKeyPem);
}

function rsaVerify(data, signatureBuf, publicKeyPem, algorithm = "RS256") {
  const algo = algorithm.toLowerCase();
  const nodeAlgo = algo === "rs256" ? "RSA-SHA256" : algo === "rs384" ? "RSA-SHA384" : algo === "rs512" ? "RSA-SHA512" : null;
  if (!nodeAlgo) throw new AlgorithmError("Unsupported RSA algorithm: " + algorithm);
  return crypto.createVerify(nodeAlgo).update(data).end().verify(publicKeyPem, signatureBuf);
}

// --- Public API ---

/**
 * sign(payload, key, options)
 * - payload: object (claims)
 * - key: secret (for HS*) or { privateKey } PEM string for RS*
 * - options:
 *   - algorithm: "HS256" or "RS256" (default HS256)
 *   - header: additional header fields (kid, typ default "JWT")
 *   - expiresIn: seconds from now (Number) or Date (absolute) or omit
 *   - notBefore: seconds from now (Number) or Date (absolute)
 *   - issuer, subject, audience, jwtid (optional)
 */
function sign(payload = {}, key, options = {}) {
  if (!isObject(payload)) throw new TypeError("payload must be an object");
  const opts = Object.assign({}, DEFAULTS, options);
  const alg = opts.algorithm || DEFAULTS.alg;
  if (alg === "none") throw new AlgorithmError("alg 'none' not allowed");

  // prepare header
  const header = Object.assign({ alg, typ: "JWT" }, opts.header || {});
  const now = nowSec();

  // copy payload and apply standard claims if provided
  const pl = Object.assign({}, payload);
  if (opts.expiresIn !== undefined) {
    const exp = typeof opts.expiresIn === "number" ? now + Math.floor(opts.expiresIn) : Math.floor(new Date(opts.expiresIn).getTime() / 1000);
    pl.exp = exp;
  }
  if (opts.notBefore !== undefined) {
    const nbf = typeof opts.notBefore === "number" ? now + Math.floor(opts.notBefore) : Math.floor(new Date(opts.notBefore).getTime() / 1000);
    pl.nbf = nbf;
  }
  if (opts.issuer) pl.iss = opts.issuer;
  if (opts.subject) pl.sub = opts.subject;
  if (opts.audience) pl.aud = opts.audience;
  if (opts.jwtid) pl.jti = opts.jwtid;
  if (!pl.iat) pl.iat = now;

  const encodedHeader = base64urlEncode(JSON.stringify(header));
  const encodedPayload = base64urlEncode(JSON.stringify(pl));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  let signatureBuf;
  if (alg.startsWith("HS")) {
    if (!key) throw new TypeError("Secret key required for HMAC signing");
    signatureBuf = hmacSign(signingInput, key, alg);
  } else if (alg.startsWith("RS")) {
    if (!key || !key.privateKey) throw new TypeError("Private key PEM required for RSA signing; pass { privateKey: '-----BEGIN...' }");
    signatureBuf = rsaSign(signingInput, key.privateKey, alg);
  } else {
    throw new AlgorithmError("Unsupported algorithm: " + alg);
  }

  const signature = base64urlEncode(signatureBuf);
  return `${signingInput}.${signature}`;
}

/**
 * verify(token, keyOrKeys, options)
 * - token: JWT string
 * - keyOrKeys:
 *     - for HS*: a secret string
 *     - for RS*: an object { publicKey: 'PEM' } or an async resolver function (kid -> key)
 * - options:
 *   - algorithms: array of allowed algs, e.g. ['HS256','RS256'] (required)
 *   - issuer, audience, subject (optional) - required match if provided
 *   - clockToleranceSec: allowed clock skew
 *   - maxAgeSec: optional maximum age from iat
 *   - requiredClaims: array of claims that must be present
 */
function verify(token, keyOrKeys, options = {}) {
  if (typeof token !== "string") throw new TypeError("token must be a string");
  const opts = Object.assign({}, DEFAULTS, options);
  const parts = token.split(".");
  if (parts.length !== 3) throw new InvalidTokenError("Token must consist of header.payload.signature");
  const [h64, p64, s64] = parts;

  // decode header & payload
  const headerBuf = base64urlDecodeToBuffer(h64);
  const payloadBuf = base64urlDecodeToBuffer(p64);
  const signatureBuf = base64urlDecodeToBuffer(s64);

  const header = safeJsonParse(headerBuf.toString("utf8"));
  const payload = safeJsonParse(payloadBuf.toString("utf8"));

  // header validation
  if (!isObject(header) || typeof header.alg !== "string") throw new InvalidTokenError("Invalid header");
  if (header.alg === "none") throw new AlgorithmError("alg 'none' is not allowed");

  const alg = header.alg;
  if (opts.algorithms && !opts.algorithms.includes(alg)) {
    throw new AlgorithmError(`Algorithm ${alg} not allowed`);
  }

  const signingInput = `${h64}.${p64}`;

  // obtain key for verification
  // For RS* we accept keyOrKeys.publicKey or a resolver function (kid -> key)
  let keyForVerification;
  if (alg.startsWith("HS")) {
    // Expect a plain secret string
    if (typeof keyOrKeys !== "string") throw new TypeError("HS algorithms require a secret string as key");
    const expectedSigBuf = hmacSign(signingInput, keyOrKeys, alg);
    // constant-time compare
    if (!constantTimeEqual(expectedSigBuf, signatureBuf)) throw new SignatureVerificationError("Invalid signature");
  } else if (alg.startsWith("RS")) {
    // Accept either { publicKey } or function(kid) -> publicKey string
    if (typeof keyOrKeys === "function") {
      // allow user to resolve by kid (header.kid)
      const keyResolved = keyOrKeys(header.kid);
      if (!keyResolved || !keyResolved.publicKey) throw new TypeError("Resolver must return { publicKey }");
      keyForVerification = keyResolved.publicKey;
    } else if (isObject(keyOrKeys) && keyOrKeys.publicKey) {
      keyForVerification = keyOrKeys.publicKey;
    } else {
      throw new TypeError("RS algorithms require { publicKey } or resolver function");
    }
    const ok = rsaVerify(signingInput, signatureBuf, keyForVerification, alg);
    if (!ok) throw new SignatureVerificationError("Invalid signature (RSA verify failed)");
  } else {
    throw new AlgorithmError("Unsupported algorithm: " + alg);
  }

  // Claim checks
  const now = nowSec();
  const tolerance = opts.clockToleranceSec || DEFAULTS.clockToleranceSec;

  if (opts.requiredClaims && Array.isArray(opts.requiredClaims)) {
    for (const rc of opts.requiredClaims) {
      if (!(rc in payload)) throw new InvalidTokenError(`Missing required claim: ${rc}`);
    }
  }

  if (payload.exp !== undefined) {
    if (typeof payload.exp !== "number") throw new InvalidTokenError("exp claim must be number");
    if (now > payload.exp + tolerance) throw new TokenExpiredError("Token expired");
  }
  if (payload.nbf !== undefined) {
    if (typeof payload.nbf !== "number") throw new InvalidTokenError("nbf claim must be number");
    if (now + tolerance < payload.nbf) throw new TokenNotActiveError("Token not yet active (nbf)");
  }
  if (payload.iat !== undefined) {
    if (typeof payload.iat !== "number") throw new InvalidTokenError("iat claim must be number");
    // optional maxAge check will be performed below
  }

  if (opts.issuer && payload.iss !== opts.issuer) throw new InvalidTokenError("Issuer (iss) mismatch");
  if (opts.subject && payload.sub !== opts.subject) throw new InvalidTokenError("Subject (sub) mismatch");
  if (opts.audience) {
    // allow opts.audience to be string or array
    const aud = payload.aud;
    if (aud === undefined) throw new InvalidTokenError("Token missing audience (aud)");
    const audiences = Array.isArray(aud) ? aud : [aud];
    const required = Array.isArray(opts.audience) ? opts.audience : [opts.audience];
    const match = required.some(r => audiences.includes(r));
    if (!match) throw new InvalidTokenError("Audience (aud) mismatch");
  }

  if (opts.maxAgeSec !== undefined) {
    if (payload.iat === undefined) throw new InvalidTokenError("iat required for maxAge check");
    const age = now - payload.iat;
    if (age - tolerance > Number(opts.maxAgeSec)) throw new TokenExpiredError("Token exceeds maxAge");
  }

  // all checks passed
  return payload;
}

module.exports = {
  sign,
  verify,
  // errors for consumer to check
  JWTError,
  TokenExpiredError,
  TokenNotActiveError,
  InvalidTokenError,
  SignatureVerificationError,
  AlgorithmError,
};
