import { createHash, timingSafeEqual } from "node:crypto";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import express from "express";

const defaultWebRoot = process.env.WEB_ROOT ?? "/web";
const defaultOpenApiPath = process.env.OPENAPI_PATH ?? "/spec/openapi.json";

function secureEqual(left, right) {
	return timingSafeEqual(
		createHash("sha256").update(left).digest(),
		createHash("sha256").update(right).digest()
	);
}

function initialState() {
	return {
		startedAt: Date.now(),
		flightMode: false,
		logs: ["Mock device started", "WiFi connected: MockNetwork"],
		config: {
			webAccounts: Array.from({ length: 10 }, (_, index) => ({
				username: index === 0 ? "admin" : "",
				password: index === 0 ? "admin123" : ""
			})),
			smtpServer: "",
			smtpPort: 465,
			smtpUser: "",
			smtpPass: "",
			smtpSendTo: "",
			adminPhone: "",
			numberBlackList: "",
			pushChannels: Array.from({ length: 5 }, (_, index) => ({
				enabled: false,
				type: 1,
				name: `通道${index + 1}`,
				url: "",
				key1: "",
				key2: "",
				customBody: ""
			}))
		}
	};
}

const actionCodes = new Set([
	"ACTION_CONFIG_SAVED",
	"ACTION_SMS_PHONE_REQUIRED",
	"ACTION_SMS_CONTENT_REQUIRED",
	"ACTION_SMS_SENT",
	"ACTION_SMS_FAILED",
	"ACTION_PING_OK",
	"ACTION_PING_MODEM_ERROR",
	"ACTION_PING_UNREACHABLE",
	"ACTION_PING_TIMEOUT",
	"ACTION_QUERY_OK",
	"ACTION_QUERY_FAILED",
	"ACTION_QUERY_UNKNOWN",
	"ACTION_FLIGHT_STATUS_NORMAL",
	"ACTION_FLIGHT_STATUS_OFF",
	"ACTION_FLIGHT_STATUS_ON",
	"ACTION_FLIGHT_STATUS_UNKNOWN",
	"ACTION_FLIGHT_ENABLED",
	"ACTION_FLIGHT_DISABLED",
	"ACTION_FLIGHT_FAILED",
	"ACTION_UNKNOWN",
	"ACTION_AT_REQUIRED",
	"ACTION_AT_OK",
	"ACTION_AT_TIMEOUT",
	"ACTION_MODEM_BUSY",
	"ACTION_MODEM_RESTARTING",
	"ACTION_MODEM_HARD_RESTARTING",
	"ACTION_MODEM_OK",
	"ACTION_MODEM_FAILED",
	"ACTION_WIFI_BUSY",
	"ACTION_WIFI_RESTARTING"
]);

function result(success, code, data = {}, detail = "") {
	if (!actionCodes.has(code)) throw new Error(`Undocumented action code: ${code}`);
	return { success, code, data, detail };
}

export function createApp({ webRoot = defaultWebRoot, openApiPath = defaultOpenApiPath, authRequired = true } = {}) {
	const app = express();
	const state = initialState();
	const indexPath = path.join(webRoot, "index.html");

	if (authRequired) app.use((request, response, next) => {
		const encoded = request.headers.authorization?.match(/^Basic (.+)$/i)?.[1];
		let username = "";
		let password = "";
		if (encoded) {
			const decoded = Buffer.from(encoded, "base64").toString("utf8");
			const separator = decoded.indexOf(":");
			username = separator >= 0 ? decoded.slice(0, separator) : decoded;
			password = separator >= 0 ? decoded.slice(separator + 1) : "";
		}
		const authenticated = state.config.webAccounts.some((account) => account.username && account.password &&
			secureEqual(username, account.username) && secureEqual(password, account.password));
		if (!authenticated) {
			response.set("WWW-Authenticate", 'Basic realm="SMS Forwarding"');
			response.status(401).end();
			return;
		}
		next();
	});

	app.use(express.urlencoded({ extended: false }));

	for (const route of ["/", "/tools", "/sms"]) {
		app.get(route, (_request, response) => {
			if (!existsSync(indexPath)) {
				response.status(503).type("text/plain").send("Web bundle missing. Run scripts/dev.sh build frontend.");
				return;
			}
			response.set("Cache-Control", "no-store");
			response.sendFile(indexPath);
		});
	}

	app.get("/api/config", (_request, response) => {
		const config = state.config;
		response.json({
			status: {
				ip: "192.168.1.50",
				wifiSsid: "MockNetwork",
				freeHeapKb: 247,
				uptimeSeconds: Math.floor((Date.now() - state.startedAt) / 1000),
				modemReady: true,
				emailConfigured: Boolean(config.smtpServer && config.smtpUser && config.smtpPass && config.smtpSendTo),
				enabledPushChannels: config.pushChannels.filter((channel) => channel.enabled).length
			},
			config: {
				...config,
				webAccounts: config.webAccounts.map((account) => ({ username: account.username, password: "" })),
				smtpPass: "",
				pushChannels: config.pushChannels.map((channel) => ({ ...channel }))
			}
		});
	});

	app.post("/save", (request, response) => {
		const body = request.body;
		const config = state.config;
		for (let index = 0; index < 10; index += 1) {
			const account = config.webAccounts[index];
			const userKey = `account${index}user`;
			const passKey = `account${index}pass`;
			if (Object.hasOwn(body, userKey)) {
				account.username = body[userKey].trim();
				if (!account.username) account.password = "";
			}
			if (Object.hasOwn(body, passKey) && body[passKey]) account.password = body[passKey];
			if (!account.password) account.username = "";
		}
		if (!config.webAccounts.some((account) => account.username && account.password)) {
			config.webAccounts[0] = { username: "admin", password: "admin123" };
		}
		if (Object.hasOwn(body, "smtpServer")) config.smtpServer = body.smtpServer;
		if (Object.hasOwn(body, "smtpPort")) config.smtpPort = Number.parseInt(body.smtpPort, 10) || 465;
		if (Object.hasOwn(body, "smtpUser")) config.smtpUser = body.smtpUser;
		if (Object.hasOwn(body, "smtpPass")) config.smtpPass = body.smtpPass;
		if (Object.hasOwn(body, "smtpSendTo")) config.smtpSendTo = body.smtpSendTo;
		if (Object.hasOwn(body, "adminPhone")) config.adminPhone = body.adminPhone;
		if (Object.hasOwn(body, "numberBlackList")) config.numberBlackList = body.numberBlackList;

		for (let index = 0; index < 5; index += 1) {
			const prefix = `push${index}`;
			const suffixes = ["en", "type", "url", "name", "key1", "key2", "body"];
			if (!suffixes.some((suffix) => Object.hasOwn(body, `${prefix}${suffix}`))) continue;
			const channel = config.pushChannels[index];
			channel.enabled = body[`${prefix}en`] === "on";
			channel.type = Number.parseInt(body[`${prefix}type`], 10) || 0;
			channel.url = body[`${prefix}url`] ?? "";
			channel.name = body[`${prefix}name`] || `通道${index + 1}`;
			channel.key1 = body[`${prefix}key1`] ?? "";
			channel.key2 = body[`${prefix}key2`] ?? "";
			channel.customBody = body[`${prefix}body`] ?? "";
		}

		state.logs.push("Configuration saved");
		response.json(result(true, "ACTION_CONFIG_SAVED"));
	});

	app.post("/sendsms", (request, response) => {
		const phone = request.body.phone?.trim() ?? "";
		const content = request.body.content?.trim() ?? "";
		if (!phone) return response.json(result(false, "ACTION_SMS_PHONE_REQUIRED"));
		if (!content) return response.json(result(false, "ACTION_SMS_CONTENT_REQUIRED"));
		state.logs.push(`SMS sent to ${phone}`);
		return response.json(result(true, "ACTION_SMS_SENT"));
	});

	app.post("/ping", (_request, response) => {
		state.logs.push("Ping completed");
		response.json(result(true, "ACTION_PING_OK", { ip: "8.8.8.8", latencyMs: 24, ttl: 117 }));
	});

	app.get("/query", (request, response) => {
		const dataByType = {
			ati: { manufacturer: "Mock Telecom", model: "Mock LTE-C3", revision: "1.0.0" },
			signal: { rsrpDbm: -82, rsrqDb: -9.5, cesq: "99,99,255,255,20,58" },
			siminfo: { imsi: "001010123456789", iccid: "8986000000000000000", msisdn: null },
			network: { registration: 1, operator: "Mock Mobile", pdpActive: true, apn: "internet" },
			wifi: {
				wifiStatus: 3, ssid: "MockNetwork", rssiDbm: -54, ip: "192.168.1.50",
				gateway: "192.168.1.1", netmask: "255.255.255.0", dns: "192.168.1.1",
				mac: "02:00:00:00:00:01", bssid: "02:00:00:00:00:02", channel: 6
			}
		};
		const type = String(request.query.type ?? "");
		const data = Object.hasOwn(dataByType, type) ? dataByType[type] : undefined;
		response.json(data ? result(true, "ACTION_QUERY_OK", data) : result(false, "ACTION_QUERY_UNKNOWN"));
	});

	app.get("/flight", (request, response) => {
		if (request.query.action === "query") {
			response.json(result(true, state.flightMode ? "ACTION_FLIGHT_STATUS_ON" : "ACTION_FLIGHT_STATUS_NORMAL", { mode: state.flightMode ? 4 : 1 }));
			return;
		}
		if (["toggle", "on", "off"].includes(request.query.action)) {
			state.flightMode = request.query.action === "toggle" ? !state.flightMode : request.query.action === "on";
			state.logs.push(`Flight mode ${state.flightMode ? "enabled" : "disabled"}`);
			response.json(result(true, state.flightMode ? "ACTION_FLIGHT_ENABLED" : "ACTION_FLIGHT_DISABLED"));
			return;
		}
		response.json(result(false, "ACTION_UNKNOWN"));
	});

	app.get("/at", (request, response) => {
		const command = request.query.cmd?.trim() ?? "";
		if (!command) return response.json(result(false, "ACTION_AT_REQUIRED"));
		state.logs.push(`AT command: ${command}`);
		return response.json(result(true, "ACTION_AT_OK", { raw: `${command}\r\nOK` }));
	});

	app.get("/log", (_request, response) => response.json(state.logs.slice(-120)));

	app.get("/modem", (request, response) => {
		const results = {
			restart: result(true, "ACTION_MODEM_RESTARTING"),
			hardreset: result(true, "ACTION_MODEM_HARD_RESTARTING"),
			signal: result(true, "ACTION_MODEM_OK", { signalDbm: -82, rssi: 16, ber: 0 }),
			operator: result(true, "ACTION_MODEM_OK", { operator: "Mock Mobile" }),
			imei: result(true, "ACTION_MODEM_OK", { imei: "860000000000001" })
		};
		const action = String(request.query.action ?? "");
		const actionResult = Object.hasOwn(results, action) ? results[action] : undefined;
		if (actionResult) state.logs.push(`Modem action: ${request.query.action}`);
		response.json(actionResult ?? result(false, "ACTION_UNKNOWN", {}, action));
	});

	app.get("/wifi", (request, response) => {
		if (request.query.action !== "restart") return response.json(result(false, "ACTION_UNKNOWN"));
		state.logs.push("WiFi restart requested");
		return response.json(result(true, "ACTION_WIFI_RESTARTING"));
	});

	app.get("/openapi.json", (_request, response) => response.sendFile(openApiPath));

	return app;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
	const port = Number.parseInt(process.env.PORT ?? "3000", 10);
	const authRequired = process.env.AUTH_REQUIRED !== "false";
	createApp({ authRequired }).listen(port, "0.0.0.0", () => console.log(`Mock server: http://0.0.0.0:${port}`));
}
