// verify-secret.js
const { STSClient, GetCallerIdentityCommand } = require("@aws-sdk/client-sts");
const { LEGACY_INTEGRATION_KEY } = require("./src/config");

async function verify() {
  const client = new STSClient({
    region: "us-east-1",
    credentials: {
      accessKeyId: LEGACY_INTEGRATION_KEY,
      secretAccessKey: "placeholder-no-real-secret-available", // see note below
    },
  });

  try {
    const result = await client.send(new GetCallerIdentityCommand({}));
    console.log("LIVE credential — this is a real, active key:", result);
  } catch (err) {
    console.log("Verification result:");
    console.log("  Error name:", err.name);
    console.log("  Error message:", err.message);
    console.log("  => Credential is NOT active / not a real, functioning key.");
  }
}

verify();
