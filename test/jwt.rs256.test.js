const fs = require("fs");
const path = require("path");
const { sign, verify } = require("../jwt");

describe("JWT RS256", () => {
  const privateKey = fs.readFileSync(path.join(__dirname, "private.pem"));
  const publicKey = fs.readFileSync(path.join(__dirname, "public.pem"));
  const payload = { userId: 456 };

  it("should create and verify a valid token", () => {
    const token = sign(payload, { privateKey }, { algorithm: "RS256", expiresIn: 60 });
    const decoded = verify(token, { publicKey }, { algorithms: ["RS256"] });
    expect(decoded.userId).toBe(456);
  });

  it("should reject an invalid signature", () => {
    const token = sign(payload, { privateKey }, { algorithm: "RS256", expiresIn: 60 });

    // corrupt the signature (last segment)
    const tampered = token.replace(/\.[^.]+$/, ".invalidsig");

    expect(() => verify(tampered, { publicKey }, { algorithms: ["RS256"] }))
      .toThrow(/invalid signature/i);
  });

  it("should reject an expired token", () => {
    const token = sign(payload, { privateKey }, { algorithm: "RS256", expiresIn: -10 });
    expect(() => verify(token, { publicKey }, { algorithms: ["RS256"] }))
      .toThrow(/token expired/i);
  });
});
