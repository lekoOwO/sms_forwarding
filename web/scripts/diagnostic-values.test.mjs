import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { diagnosticValue } from "../src/lib/diagnostic-values.js";

test("registration distinguishes roaming, limited service and unknown without claiming delivery", () => {
	assert.deepEqual(diagnosticValue("registration", 5), { key: "diagnosticRegistrationRoaming" });
	assert.deepEqual(diagnosticValue("registration", 1), { key: "diagnosticRegistrationHome" });
	assert.deepEqual(diagnosticValue("registration", 11), { key: "diagnosticRegistrationRestricted" });
	assert.deepEqual(diagnosticValue("registration", 6), { key: "diagnosticRegistrationReserved" });
	assert.deepEqual(diagnosticValue("registration", 42), { key: "diagnosticUnknown" });
	assert.deepEqual(diagnosticValue("registration", null), { key: "diagnosticUnknown" });
});

test("CSQ saturation and unknown codes never become precise or impossible power readings", () => {
	assert.deepEqual(diagnosticValue("rssi", 0), { key: "diagnosticSignalValue", value: "≤ −113 dBm" });
	assert.deepEqual(diagnosticValue("rssi", 20), { key: "diagnosticSignalValue", value: "−73 dBm" });
	assert.deepEqual(diagnosticValue("rssi", 31), { key: "diagnosticSignalValue", value: "≥ −51 dBm" });
	for (const value of [99, -1, 32, "20", null]) assert.deepEqual(diagnosticValue("rssi", value), { key: "diagnosticUnknown" });
	for (const [field, value] of [["signalDbm", -999], ["rsrpDbm", 999], ["rsrqDb", 999], ["ber", 99]]) {
		assert.deepEqual(diagnosticValue(field, value), { key: "diagnosticUnknown" });
	}
	assert.deepEqual(diagnosticValue("ber", 3), { key: "diagnosticErrorLevel", value: "3" });
});

test("cached signal summaries and IP presence are not presented as raw CESQ or live PDP checks", () => {
	assert.deepEqual(diagnosticValue("cesq", "-70,-11,31"), { key: "diagnosticLegacySignal" });
	assert.deepEqual(diagnosticValue("cesq", "99,99,255,255,20,80"), { key: "diagnosticUnknown" });
	assert.deepEqual(diagnosticValue("pdpActive", true), { key: "diagnosticCellIpPresent" });
	assert.deepEqual(diagnosticValue("pdpActive", false), { key: "diagnosticCellIpAbsent" });
	assert.deepEqual(diagnosticValue("operator", ""), { key: "diagnosticOperatorUnavailable" });
	assert.equal(diagnosticValue("operator", "00101"), null);
});

test("diagnostic descriptions resolve in all three user languages", () => {
	for (const [locale, expected] of [["en", "Registered on a roaming network"], ["zh-TW", "已註冊至漫遊網路"], ["zh-CN", "已注册至漫游网络"]]) {
		const messages = JSON.parse(readFileSync(new URL(`../src/lib/locales/${locale}.json`, import.meta.url), "utf8"));
		assert.equal(messages[diagnosticValue("registration", 5).key], expected);
		for (const [field, values] of [["registration", [0, 1, 2, 3, 4, 5, 6, 8, 11, 42]], ["mode", [0, 1, 4, 42]], ["wifiStatus", [3, 6, 42]], ["rsrpDbm", [-70, 999]], ["cesq", ["-70,-11,31"]]]) {
			for (const value of values) assert.equal(typeof messages[diagnosticValue(field, value).key], "string", `${locale}: ${field}=${value}`);
		}
	}
});
