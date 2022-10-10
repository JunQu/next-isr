import { createHmac, timingSafeEqual } from "node:crypto";

const secretKey = process.env.GITHUB_WEBHOOK_SECRET;

function compareSignatures(signature, rawBody) {
  const computedSignature = createHmac("sha256", secretKey)
    .update(rawBody)
    .digest("hex");
  const hexSignature = signature.slice("sha256=".length);

  const sig = Buffer.from(hexSignature, "utf8");
  const digest = Buffer.from(computedSignature);

  return sig.length === digest.length && timingSafeEqual(digest, sig);
};

 async function handleWebhook(req, res) {
  // verify the webhook signature request against the
  // unmodified, unparsed body
  if (!req.body) {
    res.status(400).send("Bad request (no body)");
    return;
  }

  // compute our signature from the raw body
  const signature = req.headers["x-hub-signature-256"];
  const rawBody = JSON.stringify(req.body);

  if (compareSignatures(signature, rawBody)) {
    const issueNumber = req.body.issue?.number;

    // issue opened or edited
    // comment created or edited
    console.log("[Next.js] Revalidating /");
    await res.revalidate("/");
    if (issueNumber) {
      console.log(`[Next.js] Revalidating /${issueNumber}`);
      await res.revalidate(`/${issueNumber}`);
    }

    return res.status(200).send("Success!");
  } else {
    return res.status(403).send("Forbidden");
  }
}
