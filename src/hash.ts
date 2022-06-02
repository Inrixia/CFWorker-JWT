export const hash = async (str: string): Promise<string> => {
	// encode as (utf-8) Uint8Array & hash the message
	const hashBuffer = await crypto.subtle.digest("MD5", new TextEncoder().encode(str));
	// convert buffer to byte array
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	// convert bytes to hex string
	return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
};
