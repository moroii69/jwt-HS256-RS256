const { sign, verify } = require("../jwt");

describe("JWT HS256", () => {
  const secret = "supersecret";
  const payload = { sub: "user123", iat: Math.floor(Date.now() / 1000) };

  it("should create and verify a valid HS256 token", () => {
    const token = sign(payload, secret, { algorithm: "HS256", expiresIn: 60 });
    const decoded = verify(token, secret, { algorithms: ["HS256"] });
    expect(decoded.sub).toBe(payload.sub);
  });

  it("should reject an invalid signature", () => {
    const token = sign(payload, secret, { algorithm: "HS256", expiresIn: 60 });
    const tampered = token.replace(/\.$/, ".tampered");
    expect(() => verify(tampered, secret, { algorithms: ["HS256"] })).toThrow(
      /invalid signature/i
    );
  });

  it("should reject an expired token", () => {
    const token = sign(payload, secret, { algorithm: "HS256", expiresIn: -10 });
    expect(() => verify(token, secret, { algorithms: ["HS256"] })).toThrow(
      /expired/i
    );
  });
});
