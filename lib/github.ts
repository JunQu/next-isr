import { sign } from "jsonwebtoken";

let accessToken;

const AppID = process.env.GITHUB_APP_ID;
const PEM = process.env.GITHUB_APP_PK_PEM;

const getAccessToken = async (installationId: number, token: string) => {
  const path = `/app/installations/${installationId}/access_tokens`;
  const data = await fetchGitHub(path, token, { method: "POST" });

  return data.token;
};

const getGitHubJWT = async () => {
  const algorithm = "RS256";
  // Registered Claim Names https://www.rfc-editor.org/rfc/rfc7519#section-4.1
  // Jose is more good for this
  const config = {
    iss: AppID,
    iat: Math.floor(Date.now() / 1000) - 60,
    exp: Math.floor(Date.now() / 1000) + 60 * 2, // 2 minutes is the max
  };
    console.log('------test error-----')
    console.log(PEM)
    console.log(AppID)
    console.log('-----end-------')

  return sign(config, PEM, { algorithm });
};

const getInstallation = async (token: string) => {
  const installations = await fetchGitHub("/app/installations", token);
  return installations.find((i: any) => i.account.login === "JunQu");
};

const createGitHubRequest = (path: string, token: string, opts: any = {}) => {
  const githubPath = `https://api.github.com${path}`;
  const headers = {
    ...opts.headers,
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    Accept: "application/vnd.github.v3+json",
  };

  return fetch(githubPath, { ...opts, headers });
};

export async function fetchGitHub(path: string, token: string, opts: any = {}) {
  let req = await createGitHubRequest(path, token, opts);
  // expired
  if (req.status === 401) {
    // JWT has expired, cache a new token
    await setAccessToken();
    // Retry request with new cached access token
    req = await createGitHubRequest(path, accessToken, opts);
  }

  return req.json();
}

export const readAccessToken = async () => {
  // check if exists
  if (!accessToken) {
    await setAccessToken();
  }

  return accessToken;
};

export const setAccessToken = async () => {
  const jwt = await getGitHubJWT();
  const installation = await getInstallation(jwt);
  accessToken = await getAccessToken(installation.id, jwt);

  return accessToken;
};
