import { JWTClient, RawJwt } from "./JWTClient";

import { hash } from "./hash";

type UserMetadata = {
	app_metadata?: Record<string, unknown>;
	created_at?: string;
	email?: string;
	email_verified?: boolean;
	family_name?: string;
	given_name?: string;
	identities?: {
		connection?: string;
		isSocial?: boolean;
		provider?: string;
		userId?: string;
	}[];
	multifactor?: unknown[];
	name?: string;
	nickname?: string;
	picture?: string;
	updated_at?: string;
	user_id?: string;
	user_metadata?: unknown;
};

type Auth0PayloadExtras<UserMetadataKey extends string> = {
	[P in UserMetadataKey]?: UserMetadata;
} & {
	permissions?: string[];
};

export type Auth0Jwt<UserMetadataKey extends string> = RawJwt<Auth0PayloadExtras<UserMetadataKey>> & {
	user_id_hashed: () => Promise<string>;
};

export class Auth0JWTClient<UMK extends string> extends JWTClient {
	userMetadataKey: UMK;

	constructor(JWKSKeyVault: KVNamespace, wellKnownJWKSUrl: string, userMetadataKey: UMK) {
		super(JWKSKeyVault, wellKnownJWKSUrl);
		this.userMetadataKey = userMetadataKey;
	}

	private isWellFormedToken = (jwt: RawJwt): jwt is Auth0Jwt<UMK> => {
		return jwt.payload[this.userMetadataKey]?.email !== undefined && jwt.payload.permissions !== undefined;
	};

	verifyAndDecode = async (request: Request): Promise<Auth0Jwt<UMK>> => {
		const token = await super.verifyAndDecode(request);

		if (!this.isWellFormedToken(token)) throw new Error("Token is malformed");

		// Add hashed user id to the token
		if (token.payload[this.userMetadataKey]?.user_id === undefined) throw new Error("Token payload user_id is undefined");
		token.user_id_hashed = async () => await hash(token.payload[this.userMetadataKey].user_id);

		return token;
	};
}
