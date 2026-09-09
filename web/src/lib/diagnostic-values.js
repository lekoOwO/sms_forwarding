// 3GPP TS 27.007 §8.5 / §10.1.22；只解讀有來源定義的碼值。
// https://www.etsi.org/deliver/etsi_ts/127000_127099/127007/17.06.00_60/ts_127007v170600p.pdf
/**
 * @param {string} field
 * @param {unknown} value
 * @returns {{key: string, value?: string} | null}
 */
export function diagnosticValue(field, value) {
	const unknown = { key: "diagnosticUnknown" };
	if (field === "registration") {
		const keys = ["Idle", "Home", "Searching", "Denied", "Unknown", "Roaming", "Reserved", "Reserved", "Emergency", "Reserved", "Reserved", "Restricted"];
		return typeof value === "number" && Number.isInteger(value) && value >= 0 && value < keys.length
			? { key: `diagnosticRegistration${keys[value]}` } : unknown;
	}
	if (field === "rssi") {
		if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 31) return unknown;
		const bound = value === 0 ? "≤ " : value === 31 ? "≥ " : "";
		return { key: "diagnosticSignalValue", value: `${bound}−${113 - value * 2} dBm` };
	}
	if (field === "ber") {
		return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 7
			? { key: "diagnosticErrorLevel", value: String(value) } : unknown;
	}
	if (["rsrpDbm", "rsrqDb", "signalDbm"].includes(field)) {
		if (typeof value !== "number" || !Number.isFinite(value) || value === 999 || value === -999) return unknown;
		return { key: "diagnosticSignalEstimate", value: `${value} ${field === "rsrqDb" ? "dB" : "dBm"}` };
	}
	if (field === "cesq") {
		// 舊 API 的三欄是已換算的 RSRP、RSRQ、CSQ，不是六欄 AT+CESQ 回覆。
		return typeof value === "string" && /^-?\d+,-?\d+,-?\d+$/.test(value)
			? { key: "diagnosticLegacySignal" } : unknown;
	}
	if (field === "pdpActive") return typeof value === "boolean"
		? { key: value ? "diagnosticCellIpPresent" : "diagnosticCellIpAbsent" } : unknown;
	if (field === "operator" && (value === null || value === "")) return { key: "diagnosticOperatorUnavailable" };
	if (field === "wifiStatus") return { key: value === 3 ? "diagnosticWifiConnected" : value === 6 ? "diagnosticWifiDisconnected" : "diagnosticUnknown" };
	if (field === "mode") return { key: value === 0 ? "diagnosticModeMinimum" : value === 1 ? "diagnosticModeFull" : value === 4 ? "diagnosticModeRadioOff" : "diagnosticUnknown" };
	return null;
}
