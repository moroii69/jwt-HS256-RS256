const { sign, verify } = require("../jwt");

describe("JWT HS256", () => {
  const secret = "supersecret";
  const payload = { userId: 123 };

  it("should create and verify a valid token", () => {
    const token = sign(payload, secret, { algorithm: "HS256", expiresIn: 60 });
    const decoded = verify(token, secret, { algorithms: ["HS256"] });
    expect(decoded.userId).toBe(123);
  });

  it("should reject an invalid signature", () => {
    const token = sign(payload, secret, { algorithm: "HS256", expiresIn: 60 });

    // corrupt the signature (last segment)
    const tampered = token.replace(/\.[^.]+$/, ".invalidsig");

    expect(() => verify(tampered, secret, { algorithms: ["HS256"] }))
      .toThrow(/invalid signature/i);
  });

  it("should reject an expired token", () => {
    const token = sign(payload, secret, { algorithm: "HS256", expiresIn: -10 });
    expect(() => verify(token, secret, { algorithms: ["HS256"] }))
      .toThrow(/token expired/i);
  });
});
