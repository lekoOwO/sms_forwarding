import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { diagnosticValue, formatOperatorName } from "../src/lib/diagnostic-values.js";
import { OPERATOR_NAMES } from "../src/lib/operator-names.generated.js";
import { buildOperatorNames } from "./operator-names-generator.mjs";

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
	assert.equal(diagnosticValue("operator", "12345"), null);
});

test("operator formatter resolves worldwide MCC/MNC names without normalizing unknown input", () => {
	assert.equal(Object.keys(OPERATOR_NAMES).length, 3036);
	assert.ok(Object.keys(OPERATOR_NAMES).every((code) => /^\d{3}\d{2,3}$/.test(code)));
	for (const code of ["26202", "23430", "310260", "44010", "46697", "72405"]) assert.ok(OPERATOR_NAMES[code], `missing global operator code ${code}`);
	assert.equal(formatOperatorName("46697", "en"), "Taiwan Mobile");
	assert.equal(formatOperatorName("46697", "zh-TW"), "台灣大哥大");
	assert.equal(formatOperatorName("46697", "zh-CN"), "台湾大哥大");
	assert.equal(formatOperatorName("00101", "en"), "TEST");
	assert.equal(formatOperatorName("310260", "en"), "T-Mobile");
	assert.deepEqual(diagnosticValue("operator", "46697", "en"), { key: "diagnosticOperatorKnown", value: "Taiwan Mobile" });
	assert.deepEqual(diagnosticValue("operator", "46697", "zh-TW"), { key: "diagnosticOperatorKnown", value: "台灣大哥大" });
	for (const value of ["12345", "4669", "466970", "466 97", "Taiwan Mobile", 46697, null]) {
		assert.equal(formatOperatorName(value, "en"), value);
	}
});

test("operator table generator validates MCC and MNC fields separately", () => {
	const names = buildOperatorNames([
		{ mcc: "46", mnc: "697", brand: "Malformed split" },
		{ mcc: "466", mnc: "97", brand: "Taiwan Mobile" },
		{ mcc: "466", mnc: "097", brand: "Taiwan Mobile 3-digit" },
		{ mcc: "466", mnc: "9", brand: "Short MNC" }
	]);
	assert.equal(names["46697"], "Taiwan Mobile");
	assert.equal(names["466697"], undefined);
	assert.equal(names["466097"], "Taiwan Mobile 3-digit");
	assert.equal(names["4669"], undefined);
});

test("diagnostic descriptions resolve in all three user languages", () => {
	for (const [locale, expected] of [["en", "Registered on a roaming network"], ["zh-TW", "已註冊至漫遊網路"], ["zh-CN", "已注册至漫游网络"]]) {
		const messages = JSON.parse(readFileSync(new URL(`../src/lib/locales/${locale}.json`, import.meta.url), "utf8"));
		assert.equal(messages[diagnosticValue("registration", 5).key], expected);
		const operator = diagnosticValue("operator", "46697", locale);
		assert.equal(messages[operator.key].replace("{value}", operator.value), locale === "en" ? "Taiwan Mobile" : locale === "zh-TW" ? "台灣大哥大" : "台湾大哥大");
		for (const [field, values] of [["registration", [0, 1, 2, 3, 4, 5, 6, 8, 11, 42]], ["mode", [0, 1, 4, 42]], ["wifiStatus", [3, 6, 42]], ["rsrpDbm", [-70, 999]], ["cesq", ["-70,-11,31"]]]) {
			for (const value of values) assert.equal(typeof messages[diagnosticValue(field, value).key], "string", `${locale}: ${field}=${value}`);
		}
	}
});
