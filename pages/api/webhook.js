import { createHmac, timingSafeEqual } from "crypto";

function compareSignatures(signature, rawBody,secretKey) {
  const computedSignature = createHmac("sha256", secretKey)
    .update(rawBody)
    .digest("hex");
  const hexSignature = signature.slice("sha256=".length);

  const sig = Buffer.from(hexSignature, "utf8");
  const digest = Buffer.from(computedSignature, 'utf8');

  return sig.length === digest.length && timingSafeEqual(digest, sig);
};

export default async function handleWebhook(req, res) {
  // verify the webhook signature request against the
  // unmodified, unparsed body
  const body = await getRawBody(req);
  if (!body) {
    res.status(400).send('Bad request (no body)');
    return;
  }

  const jsonBody = JSON.parse(body);

  // compute our signature from the raw body
  const secretKey = process.env.GITHUB_WEBHOOK_SECRET;
  const signature = req.headers['x-hub-signature-256'];

  if (compareSignatures(signature,body,secretKey)) {
    const issueNumber = jsonBody.issue?.number;

    // issue opened or edited
    // comment created or edited
    console.log('[Next.js] Revalidating /');
    await res.revalidate('/');
    if (issueNumber) {
      console.log(`[Next.js] Revalidating /${issueNumber}`);
      await res.revalidate(`/${issueNumber}`);
    }

    return res.status(200).send('Success!');
  } else {
    return res.status(403).send('Forbidden');
  }
}

function getRawBody(req) {
  return new Promise((resolve) => {
    let bodyChunks = [];
    req.on('end', () => {
      const rawBody = Buffer.concat(bodyChunks).toString('utf8');
      resolve(rawBody);
    });
    req.on('data', (chunk) => bodyChunks.push(chunk));
  });
}
