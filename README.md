## CFWorker

Helper module for dealing with JWT's on cloudflare workers. Primarilty used for Auth0 authentication

Example:
Note, this assumes you have a login action setup with Auth0 that adds `event.user` data to the payload with the key `"https://<REDACTED>.com/user"`.

```ts
import { Auth0JWTClient } from "./Auth0JWTClient";

// env.Auth0KV is a worker KVNamespace
const jwtClient = new Auth0JWTClient(env.Auth0KV, "https://<REDACTED>.au.auth0.com/.well-known/jwks.json", "https://<REDACTED>.com/user");

const handleRequest = async (req: Request) => {
	if (req.headers.has("Authorization")) {
		try {
			const authJwt = await jwtClient.verifyAndDecode(req);
			return new Reponse(`UID: ${result.user_id_hashed}, Name: ${result.payload["https://<REDACTED>.com/user"].name}`);
		} catch (err) {
			return new Response("Not Authorized", { status: 401 });
		}
	}
	return new Response("Not Authorized", { status: 401 });
};
```
