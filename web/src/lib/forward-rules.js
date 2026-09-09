export const CSV_PREFIX = "#!forward-rules-csv-v1\n";
/** @typedef {{type: string, pattern: string, action: string, enabled: string, line?: number}} Rule */
/** @param {string} value */
const trim = (value) => value.replace(/^[ \t\r\n\f\v]+|[ \t\r\n\f\v]+$/g, "");

/** Parse the stored format. CSV errors refer to the visible CSV line, without its storage marker.
 * @param {string} text */
export function parseRules(text) {
	const csv = text.startsWith(CSV_PREFIX);
	const rows = [];
	let pos = csv ? CSV_PREFIX.length : 0, line = 1;
	let semanticError = "", semanticLine = 0;
	/** @param {number} at @param {string} error */
	const fail = (at, error) => ({ rows: [], csv, error: semanticError || error, line: semanticError ? semanticLine : at });
	while (pos < text.length) {
		const start = line;
		if (!csv) {
			let end = text.indexOf("\n", pos);
			if (end < 0) end = text.length;
			const raw = trim(text.slice(pos, end)); pos = end + 1; line++;
			const a = raw.indexOf("\t"), b = a < 0 ? -1 : raw.indexOf("\t", a + 1);
			if (b < 0) continue;
			const c = raw.indexOf("\t", b + 1);
			rows.push({ type: raw.slice(0, a), pattern: raw.slice(a + 1, b), action: raw.slice(b + 1, c < 0 ? undefined : c), enabled: c < 0 ? "1" : trim(raw.slice(c + 1)), line: start });
			continue;
		}
		if (text[pos] === "\n") { pos++; line++; continue; }
		if (text.slice(pos, pos + 2) === "\r\n") { pos += 2; line++; continue; }
		const fields = [];
		let more = true;
		while (more) {
			let value = "";
			if (text[pos] === '"') {
				pos++; let closed = false;
				while (pos < text.length) {
					const ch = text[pos++];
					if (ch === '"') {
						if (text[pos] === '"') { value += '"'; pos++; }
						else { closed = true; break; }
					} else { value += ch; if (ch === "\n") line++; }
				}
				if (!closed) return fail(start, "quotes");
			} else {
				while (pos < text.length && !",\r\n".includes(text[pos])) {
					if (text[pos] === '"') return fail(start, "quotes");
					value += text[pos++];
				}
			}
			fields.push(value);
			if (fields.length > 4) return fail(start, "columns");
			if (pos === text.length) more = false;
			else if (text[pos] === ",") pos++;
			else if (text[pos] === "\n") { pos++; line++; more = false; }
			else if (text.slice(pos, pos + 2) === "\r\n") { pos += 2; line++; more = false; }
			else return fail(start, "quotes");
		}
		if (fields.length < 3) return fail(start, "columns");
		const enabled = fields[3] || "1";
		const problem = !["kw", "from", "re"].includes(fields[0]) ? "type" : !["0", "1"].includes(enabled) ? "enabled" :
			fields[2] && !fields[2].split(",").every((token) => ["drop", "email", "1", "2", "3", "4", "5"].includes(trim(token))) ? "action" : "";
		if (problem && !semanticError) { semanticError = problem; semanticLine = start; }
		rows.push({ type: fields[0], pattern: fields[1], action: fields[2], enabled, line: start });
	}
	return { rows, csv, error: semanticError, line: semanticLine };
}

/** @param {Rule[]} rows */
export function serializeRules(rows) {
	/** @param {string} value */
	const quote = (value) => /[,"\r\n]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value;
	return CSV_PREFIX + rows.map((row) => [row.type, row.pattern, row.action, row.enabled].map(quote).join(",")).join("\n");
}

/** Only convert well-formed legacy rows. Never discard ignored text or normalize unknown actions silently.
 * @param {string} text */
export function migrateRules(text) {
	const parsed = parseRules(text);
	if (parsed.csv) return text;
	if (text.split("\n").filter((line) => trim(line)).length !== parsed.rows.length) return null;
	const candidate = serializeRules(parsed.rows.map((row) => ({ ...row, enabled: row.enabled === "0" ? "0" : "1" })));
	return parseRules(candidate).error ? null : candidate;
}

// Mock/demo only. The device preview uses the production POSIX engine, not this browser approximation.
/** @param {string} text @param {string} sender @param {string} body */
export function previewMockRules(text, sender = "", body = "") {
	const parsed = parseRules(text);
	if (parsed.error) return { success: false, code: "ACTION_CONFIG_INVALID", data: {}, detail: `${parsed.line}:${parsed.error}` };
	for (const row of parsed.rows) {
		if (row.enabled === "0" || !row.pattern || !["from", "re"].includes(row.type)) continue;
		try {
			if (/(^|[^\\])(?:\\\\)*\(\?/.test(row.pattern)) throw new Error("unsupported");
			new RegExp(row.pattern, "i");
		} catch { return { success: false, code: "ACTION_CONFIG_INVALID", data: {}, detail: `${row.line}:regex` }; }
	}
	const row = parsed.rows.find((row) => row.enabled !== "0" && row.pattern &&
		(row.type === "kw" ? body.includes(row.pattern) : ["re", "from"].includes(row.type) && new RegExp(row.pattern, "i").test(row.type === "from" ? sender : body)));
	const actions = row?.action.split(",").map(trim) ?? [];
	return { success: true, code: "ACTION_QUERY_OK", detail: "", data: {
		matched: Boolean(row), line: row?.line ?? 0, drop: actions.includes("drop"), email: actions.includes("email"),
		channelMask: actions.reduce((mask, value) => /^0*[1-5]$/.test(value) ? mask | (1 << (Number(value) - 1)) : mask, 0)
	} };
}
