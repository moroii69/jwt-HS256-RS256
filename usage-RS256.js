const { generateKeyPairSync } = require("crypto");
const { sign, verify } = require("./jwt");

// generate ephemeral key pair for demo 
const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const token = sign({ sub: "user123" }, { privateKey }, { algorithm: "RS256", expiresIn: 120 });
console.log("rs token:", token);

const payload = verify(token, { publicKey }, { algorithms: ["RS256"] });
console.log("verified payload:", payload);
