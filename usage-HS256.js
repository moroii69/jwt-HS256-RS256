const { sign, verify, TokenExpiredError } = require("./jwt");

const secret = "keysupersecret";
const token = sign({ sub: "user123", role: "admin" }, secret, {
  algorithm: "HS256",
  expiresIn: 60, // 60 secss
  issuer: "my-app",
});

console.log("token:", token);

try {
  const payload = verify(token, secret, {
    algorithms: ["HS256"],
    issuer: "my-app",
    clockToleranceSec: 5,
  });
  console.log("payload:", payload);
} catch (err) {
  if (err instanceof TokenExpiredError) {
    console.error("token expired");
  } else {
    console.error("verify failed:", err.message);
  }
}
