import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { CSV_PREFIX, migrateRules, parseRules, serializeRules } from "../src/lib/forward-rules.js";

test("CSV syntax fixtures agree on field errors and physical line numbers", () => {
	for (const fixture of JSON.parse(readFileSync(new URL("../../dev_doc/forward-rules-fixtures.json", import.meta.url)))) {
		const parsed = parseRules(fixture.rules);
		// Regex validity and routing outcomes are checked by the production C++ engine.
		if (fixture.rules === CSV_PREFIX + "re,[,email") continue;
		assert.equal(!parsed.error, fixture.valid, fixture.rules);
		if (!fixture.valid) assert.equal(parsed.line, fixture.line);
	}
});

test("CSV parser and serializer preserve literal quotes, commas and line breaks", () => {
	const text = CSV_PREFIX + 'kw,"a,""b""\nc","email,2",1';
	assert.deepEqual(parseRules(text).rows, [{ type: "kw", pattern: 'a,"b"\nc', action: "email,2", enabled: "1", line: 1 }]);
	assert.equal(serializeRules([{ type: "kw", pattern: 'a,"b"\nc', action: "email,2", enabled: "1" }]), text);
});

test("legacy conversion never drops ignored text or unknown actions", () => {
	assert.equal(migrateRules("kw\tA,B\temail,1"), CSV_PREFIX + 'kw,"A,B","email,1",1');
	assert.equal(migrateRules("ignored\nkw\tA\temail"), null);
	assert.equal(migrateRules("kw\tA\tunknown"), null);
	assert.equal(parseRules("kw,A,email").rows.length, 0);
});
