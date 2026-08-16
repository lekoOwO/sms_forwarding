import { createCipheriv, createDecipheriv, createHash, pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import express from "express";

const defaultWebRoot = process.env.WEB_ROOT ?? "/web";
const defaultOpenApiPath = process.env.OPENAPI_PATH ?? "/spec/openapi.json";
const byteLength = (value) => Buffer.byteLength(String(value ?? ""), "utf8");
const configMagic = Buffer.from("SMSCFG01");

function encryptConfig(bytes, passphrase) {
	const salt = randomBytes(16);
	const iv = randomBytes(12);
	const header = Buffer.alloc(44);
	configMagic.copy(header);
	header.writeUInt16LE(1, 8);
	header[10] = 1;
	header[11] = 1;
	header.writeUInt32LE(210000, 12);
	salt.copy(header, 16);
	iv.copy(header, 32);
	const cipher = createCipheriv("aes-256-gcm", pbkdf2Sync(passphrase, salt, 210000, 32, "sha256"), iv);
	cipher.setAAD(header);
	const encrypted = Buffer.concat([cipher.update(bytes), cipher.final(), cipher.getAuthTag()]);
	return Buffer.concat([header, encrypted]);
}

function decryptConfig(bytes, passphrase) {
	if (bytes.length < 60 || !bytes.subarray(0, 8).equals(configMagic) || bytes.readUInt16LE(8) !== 1 || bytes[10] !== 1 || bytes[11] !== 1 || bytes.readUInt32LE(12) !== 210000) throw new Error("format");
	const salt = bytes.subarray(16, 32);
	const iv = bytes.subarray(32, 44);
	const payload = bytes.subarray(44);
	const decipher = createDecipheriv("aes-256-gcm", pbkdf2Sync(passphrase, salt, 210000, 32, "sha256"), iv);
	decipher.setAAD(bytes.subarray(0, 44));
	decipher.setAuthTag(payload.subarray(-16));
	return Buffer.concat([decipher.update(payload.subarray(0, -16)), decipher.final()]);
}

function crc32(bytes) {
	let crc = 0xffffffff;
	for (const byte of bytes) {
		crc ^= byte;
		for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
	}
	return (crc ^ 0xffffffff) >>> 0;
}

function portableConfig(config) {
	const parts = [];
	const u32 = (value) => { const bytes = Buffer.alloc(4); bytes.writeUInt32LE(value); parts.push(bytes); };
	const string = (value) => { const bytes = Buffer.from(value); const length = Buffer.alloc(2); length.writeUInt16LE(bytes.length); parts.push(length, bytes); };
	u32(config.smtpPort);
	for (const value of ["Portable backup", "portable-backup", config.notificationLocale, config.smtpServer, config.smtpUser, config.smtpPass, config.smtpSendTo, config.adminPhone, config.numberBlackList]) string(value);
	for (let index = 0; index < 10; index += 1) { string(""); string(""); }
	for (const channel of config.pushChannels) {
		parts.push(Buffer.from([channel.enabled ? 1 : 0, channel.type]));
		for (const value of [channel.name, channel.url, channel.key1, channel.key2, channel.titleTemplate, channel.bodyTemplate, channel.customBody]) string(value);
	}
	const payload = Buffer.concat(parts);
	const header = Buffer.alloc(20);
	header.write("CFG2"); header.writeUInt16LE(3, 4); header.writeUInt32LE(payload.length, 12); header.writeUInt32LE(crc32(payload), 16);
	return Buffer.concat([header, payload]);
}

function decodePortableConfig(bytes, target) {
	const schemaVersion = bytes.length >= 6 ? bytes.readUInt16LE(4) : 0;
	if (bytes.length < 20 || bytes.subarray(0, 4).toString() !== "CFG2" || ![2, 3].includes(schemaVersion) ||
		bytes.readUInt16LE(6) !== 0 || bytes.readUInt32LE(8) !== 0 || bytes.readUInt32LE(12) !== bytes.length - 20 ||
		bytes.readUInt32LE(16) !== crc32(bytes.subarray(20))) throw new Error("portable");
	let offset = 20;
	const u32 = () => {
		if (offset + 4 > bytes.length) throw new Error("portable");
		const value = bytes.readUInt32LE(offset); offset += 4; return value;
	};
	const string = () => {
		if (offset + 2 > bytes.length) throw new Error("portable");
		const length = bytes.readUInt16LE(offset); offset += 2;
		if (offset + length > bytes.length) throw new Error("portable");
		let value;
		try {
			value = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(offset, offset + length));
		} catch {
			throw new Error("portable");
		}
		offset += length;
		if (value.includes("\0")) throw new Error("portable");
		return value;
	};
	const decoded = { smtpPort: u32() };
	[decoded.deviceName, decoded.hostname, decoded.notificationLocale, decoded.smtpServer, decoded.smtpUser,
		decoded.smtpPass, decoded.smtpSendTo, decoded.adminPhone, decoded.numberBlackList] = Array.from({ length: 9 }, string);
	decoded.webAccounts = Array.from({ length: 10 }, () => ({ username: string(), password: string() }));
	decoded.pushChannels = Array.from({ length: 5 }, () => {
		if (offset + 2 > bytes.length) throw new Error("portable");
		const enabledByte = bytes[offset++];
		if (enabledByte > 1) throw new Error("portable");
		const enabled = enabledByte === 1;
		const type = bytes[offset++];
		const [name, url, key1, key2, titleTemplate, bodyTemplate, customBody] = Array.from({ length: 7 }, string);
		return { enabled, type, name, url, key1, key2, titleTemplate, bodyTemplate, customBody };
	});
	if (offset !== bytes.length || decoded.deviceName !== "Portable backup" || decoded.hostname !== "portable-backup" ||
		decoded.webAccounts.some((account) => account.username || account.password) ||
		(schemaVersion === 2 && decoded.pushChannels.some((channel) => channel.type > 10))) throw new Error("portable");
	decoded.deviceName = target.deviceName;
	decoded.hostname = target.hostname;
	decoded.webAccounts = structuredClone(target.webAccounts);
	if (!configSemanticallyValid(decoded)) throw new Error("portable");
	return decoded;
}

const fieldLimits = {
	smtpServer: 253, smtpPort: 32, smtpUser: 254, smtpPass: 256, smtpSendTo: 254,
	adminPhone: 32, numberBlackList: 1024, phone: 32, content: 2048,
	cmd: 256, action: 32, type: 32, deviceName: 64, hostname: 32, notificationLocale: 16
};

function configSemanticallyValid(config) {
	const bounded = (value, limit) => typeof value === "string" && byteLength(value) <= limit;
	if (!bounded(config.deviceName, 64) || !config.deviceName || /[\x00-\x1f\x7f]/.test(config.deviceName) ||
		!bounded(config.hostname, 32) || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(config.hostname) ||
		!["zh-TW", "zh-CN", "en"].includes(config.notificationLocale) || !Number.isInteger(config.smtpPort) ||
		config.smtpPort < 1 || config.smtpPort > 65535 || !bounded(config.smtpServer, 253) ||
		!bounded(config.smtpUser, 254) || !bounded(config.smtpPass, 256) || !bounded(config.smtpSendTo, 254) ||
		!bounded(config.adminPhone, 32) || !bounded(config.numberBlackList, 1024) ||
		config.webAccounts.length !== 10 || config.webAccounts.some((account) => !bounded(account.username, 64) || !bounded(account.password, 96)) ||
		config.pushChannels.length !== 5) return false;
	return config.pushChannels.every((channel) => Number.isInteger(channel.type) && channel.type >= 0 && channel.type <= 12 &&
		typeof channel.enabled === "boolean" && bounded(channel.name, 64) && bounded(channel.url, 512) &&
		bounded(channel.key1, 256) && bounded(channel.key2, 256) && bounded(channel.titleTemplate, 256) &&
		bounded(channel.bodyTemplate, 2048) && bounded(channel.customBody, 2048) && !/[\r\n]/.test(channel.titleTemplate) &&
		(channel.type === 7 ? !channel.titleTemplate && !channel.bodyTemplate : !channel.customBody));
}

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
			deviceName: "SMS Forwarder 000001",
			hostname: "sms-forwarder-000001",
			notificationLocale: "zh-TW",
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
				name: `Channel ${index + 1}`,
				url: "",
				key1: "",
				key2: "",
				customBody: "",
				titleTemplate: "",
				bodyTemplate: ""
			}))
		}
	};
}

const actionCodes = new Set([
	"ACTION_CONFIG_SAVED",
	"ACTION_CONFIG_SAVE_FAILED",
	"ACTION_CONFIG_ACCOUNT_REQUIRED",
	"ACTION_INPUT_TOO_LONG",
	"ACTION_INPUT_INVALID",
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
	"ACTION_AT_REJECTED",
	"ACTION_AT_OK",
	"ACTION_AT_TIMEOUT",
	"ACTION_MODEM_BUSY",
	"ACTION_MODEM_RESTARTING",
	"ACTION_MODEM_HARD_RESTARTING",
	"ACTION_MODEM_OK",
	"ACTION_MODEM_FAILED",
	"ACTION_WIFI_RESTARTING",
	"ACTION_JOB_ACCEPTED", "ACTION_CONFIG_EXPORT_READY", "ACTION_CONFIG_RESTORED",
	"ACTION_OTA_UPLOAD_STARTED", "ACTION_OTA_CHUNK_OK", "ACTION_OTA_READY",
	"ACTION_JOB_NOT_FOUND", "ACTION_CSRF_INVALID", "ACTION_AUTH_THROTTLED", "ACTION_BUSY",
	"ACTION_CONFIG_EXPORT_FAILED", "ACTION_CONFIG_EXPORT_NOT_FOUND", "ACTION_CONFIG_INVALID",
	"ACTION_CONFIG_PASSPHRASE_INVALID", "ACTION_CONFIG_RESTORE_CHUNK_INVALID",
	"ACTION_CONFIG_RESTORE_CHUNK_OK", "ACTION_CONFIG_RESTORE_FAILED",
	"ACTION_CONFIG_RESTORE_FINISH_INVALID", "ACTION_CONFIG_RESTORE_INVALID",
	"ACTION_CONFIG_RESTORE_SAVE_FAILED", "ACTION_CONFIG_RESTORE_STARTED",
	"ACTION_CONFIG_RESTORE_START_FAILED", "ACTION_JOB_FAILED", "ACTION_JOB_QUEUE_FULL",
	"ACTION_JSON_FAILED", "ACTION_OTA_BEGIN_FAILED", "ACTION_OTA_BUSY",
	"ACTION_OTA_CHUNK_INVALID", "ACTION_OTA_FINALIZE_FAILED", "ACTION_OTA_HASH_INVALID",
	"ACTION_OTA_MANIFEST_INVALID", "ACTION_OTA_METADATA_FAILED", "ACTION_OTA_SESSION_INVALID",
	"ACTION_OTA_SIGNATURE_INVALID", "ACTION_OTA_WRITE_FAILED", "ACTION_TOO_MANY_FIELDS"
]);

function result(success, code, data = {}, detail = "") {
	if (!actionCodes.has(code)) throw new Error(`Undocumented action code: ${code}`);
	return { success, code, data, detail };
}

function rejectEnvelope(request, response, next) {
	const requestLineBytes = byteLength(`${request.method} ${request.originalUrl} HTTP/${request.httpVersion}\r\n`);
	const headerBytes = request.rawHeaders.reduce((total, value) => total + byteLength(value) + 2, 2);
	const contentLength = Number.parseInt(request.headers["content-length"] ?? "0", 10);
	const status = requestLineBytes > 2048 ? 414 : headerBytes > 8192 ? 431 : contentLength > 16384 ? 413 : 0;
	if (!status) return next();
	response.set({ "Cache-Control": "no-store", Connection: "close" }).status(status).end();
}

function rejectField(response, field) {
	response.status(400).json(result(false, "ACTION_INPUT_TOO_LONG", {}, field));
}

function overLimit(field, value, limit = fieldLimits[field]) {
	return limit !== undefined && byteLength(value) > limit;
}

function modemCommandAllowed(input) {
	const command = String(input ?? "").trim().toUpperCase();
	return command.startsWith("AT") && !/[\r\n]/.test(input) && !command.startsWith("ATD") && command !== "ATO" &&
		!["AT+CMGS", "AT+CMGW", "AT+CGDATA", "AT+CMUX"].some((prefix) => command.startsWith(prefix)) &&
		!["CIPSEND", "QISEND", "CASEND"].some((value) => command.includes(value));
}

export function createApp({ webRoot = defaultWebRoot, openApiPath = defaultOpenApiPath, authRequired = true } = {}) {
	const app = express();
	const state = initialState();
	const csrfToken = "mock-csrf-token";
	const jobs = new Map();
	const exportsById = new Map();
	let upload;
	let nextId = 1;
	const acceptJob = (type, finalResult, response) => {
		const jobId = nextId++;
		jobs.set(jobId, { id: jobId, type, state: finalResult.success ? "succeeded" : "failed", result: finalResult });
		while (jobs.size > 6) jobs.delete(jobs.keys().next().value);
		return response.status(202).json(result(true, "ACTION_JOB_ACCEPTED", { jobId }));
	};
	const indexPath = path.join(webRoot, "index.html");
	app.use(rejectEnvelope);

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

	app.use(express.urlencoded({ extended: false, limit: 16384 }));
	app.use((request, response, next) => {
		const stateChangingGet = request.method === "GET" && (
			request.path === "/api/config/export" ||
			(request.path === "/flight" && request.query.action !== "query") ||
			request.path === "/at" ||
			(request.path === "/modem" && ["restart", "hardreset"].includes(request.query.action)) ||
			(request.path === "/wifi" && request.query.action === "restart")
		);
		if ((["GET", "HEAD"].includes(request.method) && !stateChangingGet) || request.headers["x-csrf-token"] === csrfToken) return next();
		response.status(403).json(result(false, "ACTION_CSRF_INVALID"));
	});

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
			csrfToken,
			status: {
				ip: "192.168.1.50",
				wifiSsid: "MockNetwork",
				freeHeapKb: 247,
				uptimeSeconds: Math.floor((Date.now() - state.startedAt) / 1000),
				modemReady: true,
				emailConfigured: Boolean(config.smtpServer && config.smtpUser && config.smtpPass && config.smtpSendTo),
				enabledPushChannels: config.pushChannels.filter((channel) => channel.enabled).length,
				firmwareVersion: "1"
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
		for (const [field, limit] of Object.entries(fieldLimits)) {
			if (Object.hasOwn(body, field) && overLimit(field, body[field], limit)) return rejectField(response, field);
		}
		for (let index = 0; index < 10; index += 1) {
			const userKey = `account${index}user`;
			const passKey = `account${index}pass`;
			if (Object.hasOwn(body, userKey) && overLimit(userKey, body[userKey], 64)) return rejectField(response, userKey);
			if (Object.hasOwn(body, passKey) && overLimit(passKey, body[passKey], 96)) return rejectField(response, passKey);
			const username = Object.hasOwn(body, userKey) ? body[userKey].trim() : state.config.webAccounts[index].username;
			const password = username && Object.hasOwn(body, passKey) && body[passKey]
				? body[passKey] : username ? state.config.webAccounts[index].password : "";
			if ((Object.hasOwn(body, userKey) || Object.hasOwn(body, passKey)) && byteLength(`${username}:${password}`) > 180) {
				return rejectField(response, Object.hasOwn(body, passKey) ? passKey : userKey);
			}
		}
		for (let index = 0; index < 5; index += 1) {
			for (const [suffix, limit] of [["en", 32], ["type", 32], ["name", 64], ["url", 512], ["key1", 256], ["key2", 256], ["body", 2048], ["title", 256], ["template", 2048]]) {
				const field = `push${index}${suffix}`;
				if (Object.hasOwn(body, field) && overLimit(field, body[field], limit)) return rejectField(response, field);
			}
		}

		const config = structuredClone(state.config);
		const nextAccounts = config.webAccounts.map((account) => ({ ...account }));
		for (let index = 0; index < 10; index += 1) {
			const account = nextAccounts[index];
			const userKey = `account${index}user`;
			const passKey = `account${index}pass`;
			if (Object.hasOwn(body, userKey)) {
				account.username = body[userKey].trim();
				if (!account.username) account.password = "";
			}
			if (Object.hasOwn(body, passKey) && body[passKey]) account.password = body[passKey];
			if (!account.password) account.username = "";
		}
		if (!nextAccounts.some((account) => account.username && account.password)) {
			response.status(400).json(result(false, "ACTION_CONFIG_ACCOUNT_REQUIRED"));
			return;
		}
		config.webAccounts = nextAccounts;
		if (Object.hasOwn(body, "smtpServer")) config.smtpServer = body.smtpServer;
		if (Object.hasOwn(body, "smtpPort")) config.smtpPort = Number.parseInt(body.smtpPort, 10) || 465;
		if (Object.hasOwn(body, "smtpUser")) config.smtpUser = body.smtpUser;
		if (Object.hasOwn(body, "smtpPass")) config.smtpPass = body.smtpPass;
		if (Object.hasOwn(body, "smtpSendTo")) config.smtpSendTo = body.smtpSendTo;
		if (Object.hasOwn(body, "adminPhone")) config.adminPhone = body.adminPhone;
		if (Object.hasOwn(body, "numberBlackList")) config.numberBlackList = body.numberBlackList;
		if (Object.hasOwn(body, "deviceName")) config.deviceName = body.deviceName;
		if (Object.hasOwn(body, "hostname")) config.hostname = body.hostname;
		if (Object.hasOwn(body, "notificationLocale")) config.notificationLocale = body.notificationLocale;

		for (let index = 0; index < 5; index += 1) {
			const prefix = `push${index}`;
			const suffixes = ["en", "type", "url", "name", "key1", "key2", "body", "title", "template"];
			if (!suffixes.some((suffix) => Object.hasOwn(body, `${prefix}${suffix}`))) continue;
			const channel = config.pushChannels[index];
			channel.enabled = body[`${prefix}en`] === "on";
			channel.type = Number.parseInt(body[`${prefix}type`], 10) || 0;
			channel.url = body[`${prefix}url`] ?? "";
			channel.name = body[`${prefix}name`] || `Channel ${index + 1}`;
			channel.key1 = body[`${prefix}key1`] ?? "";
			channel.key2 = body[`${prefix}key2`] ?? "";
			channel.customBody = body[`${prefix}body`] ?? "";
			channel.titleTemplate = body[`${prefix}title`] ?? "";
			channel.bodyTemplate = body[`${prefix}template`] ?? "";
		}

		if (!configSemanticallyValid(config)) {
			return acceptJob("config-save", result(false, "ACTION_CONFIG_INVALID"), response);
		}
		state.config = config;
		state.logs.push("Configuration saved");
		acceptJob("config-save", result(true, "ACTION_CONFIG_SAVED"), response);
	});

	app.post("/sendsms", (request, response) => {
		if (overLimit("phone", request.body.phone)) return rejectField(response, "phone");
		if (overLimit("content", request.body.content)) return rejectField(response, "content");
		const phone = request.body.phone?.trim() ?? "";
		const content = request.body.content?.trim() ?? "";
		if (!phone) return response.json(result(false, "ACTION_SMS_PHONE_REQUIRED"));
		if (!content) return response.json(result(false, "ACTION_SMS_CONTENT_REQUIRED"));
		state.logs.push(`SMS sent to ${phone}`);
		return acceptJob("sms", result(true, "ACTION_SMS_SENT"), response);
	});

	app.post("/ping", (_request, response) => {
		state.logs.push("Ping completed");
		acceptJob("ping", result(true, "ACTION_PING_OK", { ip: "8.8.8.8", latencyMs: 24, ttl: 117 }), response);
	});

	app.get("/query", (request, response) => {
		if (overLimit("type", request.query.type)) return rejectField(response, "type");
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
		acceptJob("query", data ? result(true, "ACTION_QUERY_OK", data) : result(false, "ACTION_QUERY_UNKNOWN"), response);
	});

	app.get("/flight", (request, response) => {
		if (overLimit("action", request.query.action)) return rejectField(response, "action");
		if (request.query.action === "query") {
			acceptJob("flight", result(true, state.flightMode ? "ACTION_FLIGHT_STATUS_ON" : "ACTION_FLIGHT_STATUS_NORMAL", { mode: state.flightMode ? 4 : 1 }), response);
			return;
		}
		if (["toggle", "on", "off"].includes(request.query.action)) {
			state.flightMode = request.query.action === "toggle" ? !state.flightMode : request.query.action === "on";
			state.logs.push(`Flight mode ${state.flightMode ? "enabled" : "disabled"}`);
			acceptJob("flight", result(true, state.flightMode ? "ACTION_FLIGHT_ENABLED" : "ACTION_FLIGHT_DISABLED"), response);
			return;
		}
		acceptJob("flight", result(false, "ACTION_UNKNOWN"), response);
	});

	app.get("/at", (request, response) => {
		if (overLimit("cmd", request.query.cmd)) return rejectField(response, "cmd");
		const command = request.query.cmd?.trim() ?? "";
		if (!command) return response.json(result(false, "ACTION_AT_REQUIRED"));
		if (!modemCommandAllowed(request.query.cmd)) return response.status(400).json(result(false, "ACTION_AT_REJECTED"));
		state.logs.push(`AT command: ${command}`);
		return acceptJob("at", result(true, "ACTION_AT_OK", { raw: `${command}\r\nOK` }), response);
	});

	app.get("/log", (request, response) => {
		const limit = Math.min(Math.max(Number.parseInt(request.query.limit ?? "50", 10) || 50, 1), 50);
		const cursor = Number.parseInt(request.query.cursor ?? "0", 10);
		const all = state.logs.map((message, index) => ({ id: index + 1, message }))
			.filter((entry) => !cursor || entry.id < cursor);
		const entries = all.slice(-limit);
		response.json({
			entries,
			nextCursor: all.length > entries.length ? entries[0].id : null,
			hasMore: all.length > entries.length
		});
	});

	app.post("/api/config/export", (request, response) => {
		if (String(request.body.passphrase ?? "").length < 12) return response.status(400).json(result(false, "ACTION_CONFIG_PASSPHRASE_INVALID"));
		const exportId = nextId++;
		exportsById.clear();
		exportsById.set(exportId, { bytes: encryptConfig(portableConfig(state.config), request.body.passphrase), expiresAt: Date.now() + 120000 });
		return acceptJob("config-export", result(true, "ACTION_CONFIG_EXPORT_READY", { exportId }), response);
	});
	app.get("/api/config/export", (request, response) => {
		const id = Number.parseInt(request.query.id, 10);
		const item = exportsById.get(id);
		exportsById.delete(id);
		if (!item || item.expiresAt < Date.now()) return response.status(404).json(result(false, "ACTION_CONFIG_EXPORT_NOT_FOUND"));
		return response.set({
			"Content-Type": "application/vnd.sms-forwarding.config",
			"X-Config-Schema-Version": "2",
			"Content-Disposition": 'attachment; filename="sms-forwarding.smscfg"'
		}).send(item.bytes);
	});

	function startUpload(kind, metadata, response) {
		if (upload && Date.now() - upload.lastActivity > 120000) upload = undefined;
		if (upload) return response.status(409).json(result(false, kind === "ota" ? "ACTION_OTA_BUSY" : "ACTION_CONFIG_RESTORE_START_FAILED"));
		const uploadId = nextId++;
		upload = { kind, uploadId, bytes: Buffer.alloc(0), lastActivity: Date.now(), ...metadata };
		return response.status(201).json(result(true, kind === "ota" ? "ACTION_OTA_UPLOAD_STARTED" : "ACTION_CONFIG_RESTORE_STARTED", { uploadId, chunkSize: 8192, nextOffset: 0 }));
	}

	function decodeBase64Chunk(body) {
		if (typeof body !== "string" || !body.length || body.length > 10924 ||
			body.length % 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(body)) return undefined;
		const bytes = Buffer.from(body, "base64");
		return bytes.length <= 8192 && bytes.toString("base64") === body ? bytes : undefined;
	}

	app.post("/api/config/restore/start", (request, response) => {
		const expectedSize = Number.parseInt(request.body.size, 10);
		if (!Number.isInteger(expectedSize) || expectedSize < 60 || expectedSize > 32828) return response.status(400).json(result(false, "ACTION_CONFIG_RESTORE_START_FAILED"));
		return startUpload("restore", { expectedSize }, response);
	});
	app.post("/api/ota/start", (request, response) => {
		let manifest;
		try { manifest = JSON.parse(request.body.manifest); } catch { return response.status(400).json(result(false, "ACTION_OTA_MANIFEST_INVALID")); }
		const expectedSize = manifest?.size;
		if (!Number.isInteger(expectedSize) || expectedSize < 1 || expectedSize > 0x1e0000) return response.status(400).json(result(false, "ACTION_OTA_MANIFEST_INVALID"));
		return startUpload("ota", { expectedSize, manifest: request.body.manifest, signature: request.body.signature }, response);
	});

	for (const [kind, prefix] of [["restore", "/api/config/restore"], ["ota", "/api/ota"]]) {
		app.post(`${prefix}/chunk`, express.text({ type: "text/plain", limit: 10924 }), (request, response) => {
			const id = Number.parseInt(request.query.id, 10);
			const offset = Number.parseInt(request.query.offset, 10);
			const chunk = decodeBase64Chunk(request.body);
			if (upload && Date.now() - upload.lastActivity > 120000) upload = undefined;
			if (!upload || upload.kind !== kind || upload.uploadId !== id || upload.bytes.length !== offset) {
				return response.status(409).json(result(false, kind === "ota" ? "ACTION_OTA_CHUNK_INVALID" : "ACTION_CONFIG_RESTORE_CHUNK_INVALID"));
			}
			if (!chunk || upload.bytes.length + chunk.length > upload.expectedSize) {
				upload = undefined;
				return response.status(400).json(result(false, kind === "ota" ? "ACTION_OTA_CHUNK_INVALID" : "ACTION_CONFIG_RESTORE_CHUNK_INVALID"));
			}
			upload.bytes = Buffer.concat([upload.bytes, chunk]);
			upload.lastActivity = Date.now();
			return response.json(result(true, kind === "ota" ? "ACTION_OTA_CHUNK_OK" : "ACTION_CONFIG_RESTORE_CHUNK_OK", { nextOffset: upload.bytes.length }));
		});
		app.post(`${prefix}/finish`, (request, response) => {
			const id = Number.parseInt(request.query.id, 10);
			if (upload && Date.now() - upload.lastActivity > 120000) upload = undefined;
			if (!upload || upload.kind !== kind || upload.uploadId !== id) return response.status(409).json(result(false, kind === "ota" ? "ACTION_OTA_SESSION_INVALID" : "ACTION_CONFIG_RESTORE_FINISH_INVALID"));
			let restored;
			let failureCode = "";
			try {
				if (upload.bytes.length !== upload.expectedSize) throw new Error("size");
				if (kind === "restore") {
					restored = decodePortableConfig(decryptConfig(upload.bytes, request.body.passphrase), state.config);
				}
			} catch {
				failureCode = kind === "ota" ? "ACTION_OTA_FINALIZE_FAILED" : "ACTION_CONFIG_RESTORE_INVALID";
			}
			if (restored) state.config = restored;
			upload = undefined;
			return acceptJob(kind, result(!failureCode, failureCode || (kind === "ota" ? "ACTION_OTA_READY" : "ACTION_CONFIG_RESTORED")), response);
		});
	}

	app.get("/api/jobs", (request, response) => {
		const job = jobs.get(Number.parseInt(request.query.id, 10));
		return job ? response.json(job) : response.status(404).json(result(false, "ACTION_JOB_NOT_FOUND"));
	});

	app.get("/modem", (request, response) => {
		if (overLimit("action", request.query.action)) return rejectField(response, "action");
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
		acceptJob("modem", actionResult ?? result(false, "ACTION_UNKNOWN", {}, action), response);
	});

	app.get("/wifi", (request, response) => {
		if (overLimit("action", request.query.action)) return rejectField(response, "action");
		if (request.query.action !== "restart") return response.json(result(false, "ACTION_UNKNOWN"));
		state.logs.push("WiFi restart requested");
		return acceptJob("wifi", result(true, "ACTION_WIFI_RESTARTING"), response);
	});

	app.get("/openapi.json", (_request, response) => response.sendFile(openApiPath));

	app.use((error, _request, response, next) => {
		if (error?.type !== "entity.too.large") return next(error);
		response.set({ "Cache-Control": "no-store", Connection: "close" }).status(413).end();
	});

	return app;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
	const port = Number.parseInt(process.env.PORT ?? "3000", 10);
	const authRequired = process.env.AUTH_REQUIRED !== "false";
	createApp({ authRequired }).listen(port, "0.0.0.0", () => console.log(`Mock server: http://0.0.0.0:${port}`));
}
