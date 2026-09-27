/** Public download URLs only; credentials must never be placed in the URL.
 * @param {unknown} value
 */
export function validKeepaliveUrl(value) {
	if (typeof value !== "string" || !/^https?:\/\//.test(value) || new TextEncoder().encode(value).length > 256 ||
		/[\s\\#"]/.test(value) || [...value].some((ch) => ch.charCodeAt(0) < 32 || ch.charCodeAt(0) === 127)) return false;
	try {
		const url = new URL(value);
		const authority = value.slice(value.indexOf("://") + 3).split(/[/?#]/)[0];
		return !authority.includes("@") && [...authority].every((ch) => ch.charCodeAt(0) <= 126) && Boolean(url.hostname) && !url.username && !url.password && url.port !== "0";
	} catch { return false; }
}
