/** @typedef {"overview" | "notifications" | "messaging" | "cellular" | "device" | "security"} MainTab */
/** @typedef {"connection" | "diagnostics" | "maintenance" | "advanced"} DeviceSubpage */

export const DEVICE_SUBPAGES = Object.freeze([
	{ value: "connection", label: "deviceSubpageConnection", description: "deviceSubpageConnectionDescription" },
	{ value: "diagnostics", label: "deviceSubpageDiagnostics", description: "deviceSubpageDiagnosticsDescription" },
	{ value: "maintenance", label: "deviceSubpageMaintenance", description: "deviceSubpageMaintenanceDescription" },
	{ value: "advanced", label: "deviceSubpageAdvanced", description: "deviceSubpageAdvancedDescription" }
]);

export const DEVICE_TOOL_INVENTORY = Object.freeze({
	connection: ["identity-save", "wifi-profile-save", "network-mode-save", "keepalive-disable"],
	diagnostics: ["diagnostics-modem-info", "diagnostics-signal", "diagnostics-sim-info", "diagnostics-modem-signal", "diagnostics-operator", "diagnostics-imei", "diagnostics-network", "diagnostics-wifi", "diagnostics-flight", "diagnostics-logs-refresh", "diagnostics-logs-load-more"],
	maintenance: ["maintenance-backup", "maintenance-restore", "maintenance-ota"],
	advanced: ["advanced-wifi-restart", "advanced-flight-toggle", "advanced-modem-restart", "advanced-modem-hard-reset", "advanced-at-terminal"]
});

const validMainTabs = new Set(["overview", "notifications", "messaging", "cellular", "device", "security"]);
const validDeviceSubpages = new Set(DEVICE_SUBPAGES.map(({ value }) => value));

/** @param {string} hash */
export function parseDeviceHash(hash) {
	const raw = hash.replace(/^#/, "").replace(/^\/+|\/+$/g, "");
	const [tab, subpage] = raw.split("/", 2);
	if (tab === "device") {
		const deviceSubpage = validDeviceSubpages.has(subpage) ? subpage : "connection";
		return { mainTab: "device", deviceSubpage, canonicalHash: `#device/${deviceSubpage}` };
	}
	const mainTab = validMainTabs.has(tab) ? tab : "overview";
	return { mainTab, deviceSubpage: "connection", canonicalHash: `#${mainTab}` };
}

/** @param {MainTab} tab */
export function routeForMainTab(tab) {
	return tab === "device" ? "#device/connection" : `#${tab}`;
}
