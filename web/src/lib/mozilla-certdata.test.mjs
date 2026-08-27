import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
	MOZILLA_CERTDATA_URL,
	fetchMozillaCertData,
	selectMozillaRootCandidates
} from "./mozilla-certdata.ts";

const octal = (bytes) => [...bytes].map((byte) => `\\${byte.toString(8).padStart(3, "0")}`).join("");

function certificate(label, subject, value, policy = true) {
	return `CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
CKA_LABEL UTF8 "${label}"
CKA_SUBJECT MULTILINE_OCTAL
${octal(subject)}
END
CKA_ISSUER MULTILINE_OCTAL
\\001
END
CKA_SERIAL_NUMBER MULTILINE_OCTAL
\\002
END
CKA_VALUE MULTILINE_OCTAL
${octal(value)}
END
CKA_NSS_MOZILLA_CA_POLICY CK_BBOOL CK_${policy ? "TRUE" : "FALSE"}
`;
}

function trust(label, value, serverAuth = "CKT_NSS_TRUSTED_DELEGATOR") {
	const hash = createHash("sha1").update(value).digest();
	return `CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST
CKA_LABEL UTF8 "${label}"
CKA_ISSUER MULTILINE_OCTAL
\\001
END
CKA_SERIAL_NUMBER MULTILINE_OCTAL
\\002
END
CKA_CERT_SHA1_HASH MULTILINE_OCTAL
${octal(hash)}
END
CKA_TRUST_SERVER_AUTH CK_TRUST ${serverAuth}
`;
}

test("selects only complete Mozilla-policy server-auth roots matching a leaf-first issuer", () => {
	const issuer = Uint8Array.of(0x30, 0x03, 0x01);
	const accepted = Uint8Array.of(0x30, 0x01);
	const wrongSubject = Uint8Array.of(0x30, 0x02);
	const notPolicy = Uint8Array.of(0x30, 0x03);
	const notServerAuth = Uint8Array.of(0x30, 0x04);
	const text = [
		certificate("accepted", issuer, accepted), trust("accepted", accepted),
		certificate("wrong subject", Uint8Array.of(0x30, 0x02), wrongSubject), trust("wrong subject", wrongSubject),
		certificate("not policy", issuer, notPolicy, false), trust("not policy", notPolicy),
		certificate("not server auth", issuer, notServerAuth), trust("not server auth", notServerAuth, "CKT_NSS_NOT_TRUSTED")
	].join("\n");
	const candidates = selectMozillaRootCandidates(text, [issuer]);
	assert.deepEqual(candidates, [{ label: "accepted", derBase64: "MAE=" }]);
	assert.throws(() => selectMozillaRootCandidates(`${text}\nCKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_VALUE MULTILINE_OCTAL\n\\060`, [issuer]), /Truncated/);
});

test("rejects an ambiguous issuer instead of silently dropping candidates above the device bound", () => {
	const issuer = Uint8Array.of(0x30);
	const objects = Array.from({ length: 9 }, (_, index) => [
		certificate(`root-${index}`, issuer, Uint8Array.of(0x30, index)), trust(`root-${index}`, Uint8Array.of(0x30, index))
	]).flat().join("\n");
	assert.throws(() => selectMozillaRootCandidates(objects, [issuer]), /more than 8/);
});

test("downloads only the fixed CORS source with strict request options and a 2 MiB stream bound", async () => {
	let seen;
	const goodFetch = async (url, init) => {
		seen = { url, init };
		return new Response("certdata", { status: 200 });
	};
	assert.equal(await fetchMozillaCertData(goodFetch, 500), "certdata");
	assert.equal(seen.url, MOZILLA_CERTDATA_URL);
	assert.deepEqual({
		credentials: seen.init.credentials,
		redirect: seen.init.redirect,
		referrerPolicy: seen.init.referrerPolicy
	}, { credentials: "omit", redirect: "error", referrerPolicy: "no-referrer" });
	const tooLarge = async () => new Response(new Uint8Array(2 * 1024 * 1024 + 1));
	await assert.rejects(fetchMozillaCertData(tooLarge, 500), /2 MiB/);
});
