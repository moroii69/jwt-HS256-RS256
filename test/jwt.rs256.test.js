const { generateKeyPairSync } = require("crypto");
const { sign, verify } = require("../jwt");

describe("JWT RS256", () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const payload = { sub: "user456", iat: Math.floor(Date.now() / 1000) };

  it("should create and verify a valid RS256 token", () => {
    const token = sign(
      payload,
      { privateKey },
      { algorithm: "RS256", expiresIn: 60 }
    );
    const decoded = verify(token, { publicKey }, { algorithms: ["RS256"] });
    expect(decoded.sub).toBe(payload.sub);
  });

  it("should reject an invalid signature", () => {
    const token = sign(
      payload,
      { privateKey },
      { algorithm: "RS256", expiresIn: 60 }
    );
    const tampered = token.replace(/\.$/, ".tampered");
    expect(() =>
      verify(tampered, { publicKey }, { algorithms: ["RS256"] })
    ).toThrow(/invalid signature/i);
  });

  it("should reject an expired token", () => {
    const token = sign(
      payload,
      { privateKey },
      { algorithm: "RS256", expiresIn: -10 }
    );
    expect(() =>
      verify(token, { publicKey }, { algorithms: ["RS256"] })
    ).toThrow(/expired/i);
  });
});
