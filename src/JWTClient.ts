import type { Jwt, JwtHeader, JwtPayload } from "jsonwebtoken";

import { JWKSCache } from "./JWKSCache";

export type RawJwt<PayloadExtras = {}> = {
	header: JwtHeader;
	payload: JwtPayload & PayloadExtras;
	signature: string;
	raw: { header: string; payload: string; signature: string };
};

export class JWTClient {
	private jwks: JWKSCache;

	constructor(JWKSKeyVault: KVNamespace, wellKnownJWKSUrl: string) {
		this.jwks = new JWKSCache(JWKSKeyVault, wellKnownJWKSUrl);
	}

	/**
	 * Parse the JWT and validate it.
	 *
	 * We are just checking that the signature is valid, but you can do more that.
	 * For example, check that the payload has the expected entries or if the signature is expired..
	 */
	async verifyAndDecode(request: Request): Promise<RawJwt> {
		const authHeader = request.headers.get("Authorization");
		if (!authHeader || authHeader.substring(0, 7) !== "Bearer ") throw new Error("Invalid authorization header");
		const encodedToken = authHeader.substring(7).trim();

		const token = this.decodeJwt(encodedToken);

		// Is the token expired?
		if (token.payload.exp === undefined) throw new Error("Token expiryDate undefined");
		const expiryDate = new Date(token.payload.exp * 1000);
		const currentDate = new Date(Date.now());
		if (expiryDate <= currentDate) throw new Error("Expired token");

		if (!(await this.isValidJwtSignature(token))) throw new Error("Invalid token signature");

		return token;
	}

	/**
	 * Parse and decode a JWT.
	 * A JWT is three, base64 encoded, strings concatenated with ‘.’:
	 *   a header, a payload, and the signature.
	 * The signature is “URL safe”, in that ‘/+’ characters have been replaced by ‘_-’
	 *
	 * Steps:
	 * 1. Split the token at the ‘.’ character
	 * 2. Base64 decode the individual parts
	 * 3. Retain the raw Bas64 encoded strings to verify the signature
	 */
	decodeJwt = (token: string): RawJwt => {
		const parts = token.split(".");
		const header = JSON.parse(atob(parts[0]));
		const payload = JSON.parse(atob(parts[1]));
		const signature = atob(parts[2].replace(/_/g, "/").replace(/-/g, "+"));
		return {
			header: header,
			payload: payload,
			signature: signature,
			raw: { header: parts[0], payload: parts[1], signature: parts[2] },
		};
	};

	/**
	 * Validate the JWT.
	 *
	 * Steps:
	 * Reconstruct the signed message from the Base64 encoded strings.
	 * Load the RSA public key into the crypto library.
	 * Verify the signature with the message and the key.
	 */
	isValidJwtSignature = async (token: RawJwt) => {
		const encoder = new TextEncoder();
		const data = encoder.encode([token.raw.header, token.raw.payload].join("."));
		const signature = new Uint8Array(Array.from<string>(token.signature).map((c) => c.charCodeAt(0)));

		if (token.header.kid === undefined) throw new Error("Token kid is undefined");

		const key = await this.jwks.get(token.header.kid);
		return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, data);
	};
}
