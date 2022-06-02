const sleep = (timeout: number) => new Promise((res) => setTimeout(res, timeout));

type Jwk = {
	alg: "RS256";
	kty: "RSA";
	use: "sig";
	n: string;
	e: "AQAB";
	kid: string;
	x5t: string;
	x5c: string[];
};

// Json Web Key Cache
export class JWKSCache {
	private kv: KVNamespace;
	private JWKSUrl: string;

	private jwks: Record<Jwk["kid"], Jwk>;
	private keys: Record<Jwk["kid"], CryptoKey>;
	private nextAllowedFetch: number;

	private cacheLoaded: boolean;
	private loadingCache: boolean;

	constructor(JWKSKeyVault: KVNamespace, wellKnownJWKSUrl: string) {
		this.kv = JWKSKeyVault;
		this.JWKSUrl = wellKnownJWKSUrl;
		this.jwks = {};
		this.keys = {};
		this.nextAllowedFetch = 0;

		this.cacheLoaded = false;
		this.loadingCache = false;
	}

	public updateCache = async (): Promise<void> => {
		if (this.nextAllowedFetch > Date.now()) return;
		// Limit each fetch call to only occour at most every 120 seconds.
		// technically speaking this may never actually occour since workers usually wont live this long
		this.nextAllowedFetch = Date.now() + 1000 * 120;
		const jwks: Jwk[] = (await fetch(this.JWKSUrl).then((res) => res.json<{ keys: Jwk[] }>())).keys;
		if (jwks === undefined) throw new Error("Undefined jwks returned from Auth0");

		// Update the jwks
		this.jwks = {};
		for (const jwk of jwks) {
			this.jwks[jwk.kid] = jwk;
			this.keys[jwk.kid] = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
		}
		await this.kv.put("Auth0", JSON.stringify(this.jwks));
	};

	private loadCache = async (): Promise<void> => {
		const jwks = await this.kv.get("Auth0");
		// If the keyvault cache is empty then update the cache
		// this populates both the local cache and kv cache
		if (jwks === null) await this.updateCache();
		else this.jwks = JSON.parse(jwks);
		for (const kid in this.jwks) {
			this.keys[kid] = await crypto.subtle.importKey("jwk", this.jwks[kid], { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
		}
	};

	public get = async (kid: string): Promise<CryptoKey> => {
		if (this.cacheLoaded === false) {
			while (this.loadingCache) await sleep(5);
			this.loadingCache = true;
			try {
				// If the cache has been loaded while aquiring the mutex then dont load it.
				if (this.cacheLoaded === false) await this.loadCache();
				this.cacheLoaded = true;
			} catch (err) {
				// Make sure to always release
				this.loadingCache = false;
				throw err;
			}
			// Make sure to always release
			this.loadingCache = false;
		}
		// If it exists in the local cache just return it
		if (this.jwks[kid] !== undefined) return this.keys[kid];
		// Otherwise update JWKS incase the cache is out of date.
		await this.updateCache();
		// If it still does not exist then throw an error
		if (this.jwks[kid] === undefined) throw new Error("Invalid token kid");

		// Return the jwk
		return this.keys[kid];
	};
}
