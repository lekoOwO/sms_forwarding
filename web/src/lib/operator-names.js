import { OPERATOR_NAMES } from "./operator-names.generated.js";

const localizedNames = Object.freeze({
	"46697": Object.freeze({
		en: "Taiwan Mobile",
		"zh-TW": "台灣大哥大",
		"zh-CN": "台湾大哥大"
	})
});
const operatorNames = /** @type {Record<string, string>} */ (OPERATOR_NAMES);
const localizedOperatorNames = /** @type {Record<string, Record<string, string>>} */ (localizedNames);

/**
 * Return a display name only for an exact MCC/MNC string known to the bundled
 * table. Unknown, malformed, and already named values remain unchanged.
 *
 * @param {unknown} value
 * @param {string} [locale="en"]
 * @returns {unknown}
 */
export function formatOperatorName(value, locale = "en") {
	if (typeof value !== "string" || !/^\d{5,6}$/.test(value)) return value;
	const name = operatorNames[value];
	if (!name) return value;
	return localizedOperatorNames[value]?.[locale] ?? name;
}
