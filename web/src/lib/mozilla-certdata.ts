export const MOZILLA_CERTDATA_URL = "https://hg-edge.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt";
const MAX_CERTDATA_BYTES = 2 * 1024 * 1024;
const MAX_CANDIDATES = 8;

type ParsedObject = Map<string, string | Uint8Array>;

export type MozillaRootCandidate = {
	label: string;
	derBase64: string;
};

function decodeOctal(lines: string[]) {
	const bytes: number[] = [];
	for (const line of lines) {
		const compact = line.trim();
		if (!compact || !/^(?:\\[0-7]{3})+$/.test(compact)) throw new Error("Invalid Mozilla octal value.");
		for (let offset = 0; offset < compact.length; offset += 4) bytes.push(Number.parseInt(compact.slice(offset + 1, offset + 4), 8));
	}
	return Uint8Array.from(bytes);
}

function parseObjects(text: string) {
	if (text.includes("\0")) throw new Error("Invalid Mozilla certdata text.");
	const lines = text.replaceAll("\r\n", "\n").split("\n");
	const objects: ParsedObject[] = [];
	let current: ParsedObject | undefined;
	for (let index = 0; index < lines.length; index += 1) {
		const line = lines[index].trim();
		if (line.startsWith("CKA_CLASS ")) {
			if (current) objects.push(current);
			current = new Map();
		}
		if (!current || !line.startsWith("CKA_")) continue;
		const [name, kind, ...valueParts] = line.split(/\s+/);
		if (current.has(name)) throw new Error("Duplicate Mozilla certdata attribute.");
		if (kind === "MULTILINE_OCTAL") {
			const valueLines: string[] = [];
			for (index += 1; index < lines.length && lines[index].trim() !== "END"; index += 1) valueLines.push(lines[index]);
			if (index >= lines.length) throw new Error("Truncated Mozilla certdata object.");
			current.set(name, decodeOctal(valueLines));
		} else {
			current.set(name, valueParts.join(" "));
		}
	}
	if (current) objects.push(current);
	return objects;
}

function bytesEqual(left: Uint8Array, right: Uint8Array) {
	return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function bytesKey(value: Uint8Array) {
	let binary = "";
	for (const byte of value) binary += String.fromCharCode(byte);
	return btoa(binary);
}

function sha1(value: Uint8Array) {
	const bitLength = value.length * 8;
	const paddedLength = Math.ceil((value.length + 9) / 64) * 64;
	const bytes = new Uint8Array(paddedLength);
	bytes.set(value);
	bytes[value.length] = 0x80;
	const view = new DataView(bytes.buffer);
	view.setUint32(paddedLength - 4, bitLength >>> 0);
	view.setUint32(paddedLength - 8, Math.floor(bitLength / 0x100000000));
	let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
	const words = new Uint32Array(80);
	for (let chunk = 0; chunk < bytes.length; chunk += 64) {
		for (let index = 0; index < 16; index += 1) words[index] = view.getUint32(chunk + index * 4);
		for (let index = 16; index < 80; index += 1) words[index] = ((words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16]) << 1) |
			((words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16]) >>> 31);
		let a = h0, b = h1, c = h2, d = h3, e = h4;
		for (let index = 0; index < 80; index += 1) {
			const f = index < 20 ? (b & c) | (~b & d) : index < 40 ? b ^ c ^ d : index < 60 ? (b & c) | (b & d) | (c & d) : b ^ c ^ d;
			const k = index < 20 ? 0x5a827999 : index < 40 ? 0x6ed9eba1 : index < 60 ? 0x8f1bbcdc : 0xca62c1d6;
			const next = ((((a << 5) | (a >>> 27)) + f + e + k + words[index]) >>> 0);
			e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = next;
		}
		h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
	}
	const result = new Uint8Array(20);
	const resultView = new DataView(result.buffer);
	[h0, h1, h2, h3, h4].forEach((word, index) => resultView.setUint32(index * 4, word));
	return result;
}

function quoted(value: string | Uint8Array | undefined) {
	if (typeof value !== "string" || value.length < 2 || !value.startsWith('"') || !value.endsWith('"')) return undefined;
	return value.slice(1, -1);
}

export function selectMozillaRootCandidates(text: string, leafFirstIssuerDer: readonly Uint8Array[]) {
	const issuers = leafFirstIssuerDer.filter((issuer) => issuer.length > 0);
	const objects = parseObjects(text);
	const trusted = new Set<string>();
	for (const object of objects) {
		if (object.get("CKA_CLASS") !== "CKO_NSS_TRUST" ||
			object.get("CKA_TRUST_SERVER_AUTH") !== "CKT_NSS_TRUSTED_DELEGATOR") continue;
		const issuer = object.get("CKA_ISSUER");
		const serial = object.get("CKA_SERIAL_NUMBER");
		const hash = object.get("CKA_CERT_SHA1_HASH");
		if (issuer instanceof Uint8Array && serial instanceof Uint8Array && hash instanceof Uint8Array && hash.length === 20) {
			trusted.add(`${bytesKey(issuer)}:${bytesKey(serial)}:${bytesKey(hash)}`);
		}
	}
	const candidates: MozillaRootCandidate[] = [];
	const seen = new Set<string>();
	for (const wantedIssuer of issuers) {
		for (const object of objects) {
			if (object.get("CKA_CLASS") !== "CKO_CERTIFICATE" || object.get("CKA_NSS_MOZILLA_CA_POLICY") !== "CK_TRUE") continue;
			const subject = object.get("CKA_SUBJECT");
			const issuer = object.get("CKA_ISSUER");
			const serial = object.get("CKA_SERIAL_NUMBER");
			const value = object.get("CKA_VALUE");
			const label = quoted(object.get("CKA_LABEL"));
			if (!(subject instanceof Uint8Array) || !(issuer instanceof Uint8Array) || !(serial instanceof Uint8Array) ||
				!(value instanceof Uint8Array) || !label || !bytesEqual(wantedIssuer, subject) ||
				!trusted.has(`${bytesKey(issuer)}:${bytesKey(serial)}:${bytesKey(sha1(value))}`)) continue;
			const derBase64 = bytesKey(value);
			if (seen.has(derBase64)) continue;
			seen.add(derBase64);
			candidates.push({ label, derBase64 });
			if (candidates.length > MAX_CANDIDATES) throw new Error("Mozilla issuer matched more than 8 root candidates.");
		}
	}
	return candidates;
}

export async function fetchMozillaCertData(fetcher: typeof fetch = fetch, timeoutMs = 15000) {
	const controller = new AbortController();
	const deadline = Date.now() + Math.max(1, timeoutMs);
	const timer = globalThis.setTimeout(() => controller.abort(), Math.max(1, timeoutMs));
	try {
		const response = await fetcher(MOZILLA_CERTDATA_URL, {
			credentials: "omit",
			redirect: "error",
			referrerPolicy: "no-referrer",
			signal: controller.signal
		});
		if (!response.ok || !response.body) throw new Error(`Mozilla certdata HTTP ${response.status}.`);
		const declared = Number(response.headers.get("content-length"));
		if (Number.isFinite(declared) && declared > MAX_CERTDATA_BYTES) throw new Error("Mozilla certdata exceeds 2 MiB.");
		const reader = response.body.getReader();
		const chunks: Uint8Array[] = [];
		let total = 0;
		try {
			for (;;) {
				if (Date.now() >= deadline) controller.abort();
				const { done, value } = await reader.read();
				if (done) break;
				total += value.length;
				if (total > MAX_CERTDATA_BYTES) throw new Error("Mozilla certdata exceeds 2 MiB.");
				chunks.push(value);
			}
		} catch (error) {
			await reader.cancel().catch(() => undefined);
			throw error;
		}
		const bytes = new Uint8Array(total);
		let offset = 0;
		for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
		return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
	} catch (error) {
		if (controller.signal.aborted) throw new Error("Mozilla certdata download timed out.", { cause: error });
		throw error;
	} finally {
		globalThis.clearTimeout(timer);
	}
}
