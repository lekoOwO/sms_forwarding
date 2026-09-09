import {
	createCipheriv, createDecipheriv, createHash, createPublicKey, pbkdf2Sync, randomBytes,
	timingSafeEqual, verify
} from "node:crypto";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import express from "express";
import { previewMockRules } from "../web/src/lib/forward-rules.js";

const defaultWebRoot = process.env.WEB_ROOT ?? "/web";
const defaultOpenApiPath = process.env.OPENAPI_PATH ?? "/spec/openapi.json";
const byteLength = (value) => Buffer.byteLength(String(value ?? ""), "utf8");
const configMagic = Buffer.from("SMSCFG01");
const defaultOtaPublicKey = createPublicKey({
	key: Buffer.from("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJlXEJlsTg6C1qtMmfYI7cOfks5ZQYA6YY7XgNm5mEywW69bEv92uWA3ZrPmTkYAnGD0bhYj4xb6tzK1b/qzBYQ==", "base64"),
	format: "der",
	type: "spki"
});

const pushTestDetailKeys = [
	"transportPath", "dispatchAttempted", "failureStage", "httpStatus",
	"cleanupMessage", "failureReason", "cleanupReason", "resetNeeded",
	"failureResponseReason", "failureParseReason", "cleanupParseReason", "failureParseShape", "cleanupParseShape"
];
const pushTestFailureResponseReasons = ["timeout", "peer_eof", "modem_read", "tls_read", "http_parse", "http_incomplete", "modem_command", "unknown"];
const pushTestParseShapeKeys = ["fieldCount", "quoteMask", "presenceMask", "stateClass", "lineClass", "singleFieldClass"];
const pushTestParseReasons = ["oversize", "terminal", "urc", "prefix", "field_count", "quote", "cid", "state", "endpoint", "result", "read_data", "unknown"];
const pushTestParseStateClasses = ["none", "initial", "closed", "connected", "connecting", "unknown"];
const pushTestParseLineClasses = ["none", "missing", "unexpected", "duplicate", "extra"];
const pushTestParseSingleFieldClasses = ["none", "zero", "nonzero", "non_numeric"];
const pushTestDetailFixtures = Object.freeze({
	wifiSuccess: Object.freeze({ transportPath: "wifi", dispatchAttempted: true, failureStage: "none", httpStatus: 204 }),
	preflightFailure: Object.freeze({ transportPath: "none", dispatchAttempted: false, failureStage: "preflight" }),
	targetFailure: Object.freeze({ transportPath: "none", dispatchAttempted: false, failureStage: "target" }),
	responseInvalidFailure: Object.freeze({ failureReason: "response_invalid", failureParseReason: "field_count" }),
	responseInvalidCleanup: Object.freeze({ cleanupReason: "response_invalid", cleanupParseReason: "quote" })
});

function serializePushTestParseShape(value) {
	if (!value || typeof value !== "object" || Array.isArray(value) ||
		Object.keys(value).length !== pushTestParseShapeKeys.length ||
		pushTestParseShapeKeys.some((key) => !Object.hasOwn(value, key)) ||
		Object.keys(value).some((key) => !pushTestParseShapeKeys.includes(key))) return undefined;
	if (!Number.isInteger(value.fieldCount) || value.fieldCount < 0 || value.fieldCount > 8 ||
		!Number.isInteger(value.quoteMask) || value.quoteMask < 0 || value.quoteMask > 255 ||
		!Number.isInteger(value.presenceMask) || value.presenceMask < 0 || value.presenceMask > 31 ||
		!pushTestParseStateClasses.includes(value.stateClass) ||
		!pushTestParseLineClasses.includes(value.lineClass) ||
		!pushTestParseSingleFieldClasses.includes(value.singleFieldClass) ||
		(value.fieldCount === 1 ? value.singleFieldClass === "none" :
			value.singleFieldClass !== "none")) return undefined;
	return Object.fromEntries(pushTestParseShapeKeys.map((key) => [key, value[key]]));
}

export function serializePushTestStatus(status, includeDetail = false) {
	const serialized = {
		queued: Boolean(status.queued), running: Boolean(status.running), done: Boolean(status.done),
		success: Boolean(status.success), message: String(status.message ?? "")
	};
	if (!includeDetail || !serialized.done) return serialized;
	for (const key of pushTestDetailKeys) {
		if (!Object.hasOwn(status, key)) continue;
		if (key === "failureResponseReason") {
			if (status.success || status.failureStage !== "response" ||
				!pushTestFailureResponseReasons.includes(status[key])) continue;
			serialized[key] = status[key];
			continue;
		}
		if (key === "failureParseShape" || key === "cleanupParseShape") {
			const reasonKey = key === "failureParseShape" ? "failureReason" : "cleanupReason";
			const parseReasonKey = key === "failureParseShape" ? "failureParseReason" : "cleanupParseReason";
			if (status[reasonKey] !== "response_invalid" || !pushTestParseReasons.includes(status[parseReasonKey])) continue;
			const shape = serializePushTestParseShape(status[key]);
			if (shape) serialized[key] = shape;
		} else {
			serialized[key] = status[key];
		}
	}
	return serialized;
}

function defaultConfig() {
	return {
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
		wifiProfiles: Array.from({ length: 5 }, () => ({ ssid: "", password: "" })),
		networkMode: 0,
		heartbeatEnable: true,
		heartbeatInterval: 6,
		wifiTxPowerQuarterDbm: 34,
		emailEnabled: true,
		pushEnabled: true,
		forwardRules: "",
		kaEnabled: false,
		kaIntervalDays: 175,
		kaAction: 1,
		kaTarget: "",
		kaUrl: "http://gg.incrafttime.top/api/payload?size=64342",
		kaProfile: "",
		kaLastTime: 0,
		kaTrafficKB: 1,
		tzOffsetMin: 480,
		ntpServer: "ntp.aliyun.com",
		rebootEnabled: false,
		rebootHour: 4,
		smsHealthEnabled: false,
		smsHealthHour: 10,
		smsHealthNotify: true,
		netLedEnabled: true,
		callNotifyEnabled: true,
		dataEnabled: false,
		roamingEnabled: false,
		apn: "",
		operatorPlmn: "",
		phoneNumber: "",
		simCredentials: Array.from({ length: 5 }, () => ({
			iccid: "", pin: "", puk: "", pinMaxAttempts: 1, pukMaxAttempts: 1,
			pinFailedAttempts: 0, pukFailedAttempts: 0
		})),
		pushChannels: Array.from({ length: 5 }, (_, index) => ({
			enabled: false,
			cellularEnabled: true,
			type: 1,
			name: `Channel ${index + 1}`,
			url: "",
			cellularUrl: "",
			key1: "",
			key2: "",
			customBody: "",
			titleTemplate: "",
			bodyTemplate: ""
		})),
		schedTasks: Array.from({ length: 6 }, () => ({
			enabled: false, name: "", profile: "", switchBack: true, intervalDays: 30,
			action: 0, target: "", payload: "", lastRun: 0
		}))
	};
}

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
	const u8 = (value) => parts.push(Buffer.from([value]));
	const u32 = (value) => { const bytes = Buffer.alloc(4); bytes.writeUInt32LE(value >>> 0); parts.push(bytes); };
	const i32 = (value) => { const bytes = Buffer.alloc(4); bytes.writeInt32LE(value); parts.push(bytes); };
	const string = (value) => { const bytes = Buffer.from(value); const length = Buffer.alloc(2); length.writeUInt16LE(bytes.length); parts.push(length, bytes); };
	u32(config.smtpPort);
	for (const value of ["Portable backup", "portable-backup", config.notificationLocale, config.smtpServer, config.smtpUser, config.smtpPass, config.smtpSendTo, config.adminPhone, config.numberBlackList]) string(value);
	u8(10);
	for (let index = 0; index < 10; index += 1) { string(""); string(""); }
	u8(5);
	for (const channel of config.pushChannels) {
		u8(channel.enabled ? 1 : 0);
		u32(channel.type);
		for (const value of [channel.name, channel.url, channel.key1, channel.key2, channel.titleTemplate, channel.bodyTemplate, channel.customBody]) string(value);
		u8(channel.cellularEnabled ? 1 : 0);
		string(channel.cellularUrl);
	}
	u8(5);
	for (const profile of config.wifiProfiles) {
		string(profile.ssid);
		string(profile.password);
	}
	u32(config.networkMode);
	u8(config.heartbeatEnable ? 1 : 0);
	u32(config.heartbeatInterval);
	u32(34);
	u8(config.emailEnabled ? 1 : 0);
	u8(config.pushEnabled ? 1 : 0);
	string(config.forwardRules);
	u8(config.kaEnabled ? 1 : 0);
	u32(config.kaIntervalDays);
	u32(config.kaAction);
	string(config.kaTarget);
	string(config.kaUrl);
	string("");
	u32(0);
	i32(config.tzOffsetMin);
	string(config.ntpServer);
	u8(config.rebootEnabled ? 1 : 0);
	u32(config.rebootHour);
	u8(config.smsHealthEnabled ? 1 : 0);
	u32(config.smsHealthHour);
	for (const value of [config.smsHealthNotify, config.netLedEnabled, config.callNotifyEnabled, config.dataEnabled, false]) u8(value ? 1 : 0);
	string(config.apn);
	string(config.operatorPlmn);
	string("");
	u8(5);
	for (let index = 0; index < 5; index += 1) {
		string(""); string(""); string(""); u32(1); u32(1); u32(0); u32(0);
	}
	u8(6);
	for (const task of config.schedTasks) {
		u8(task.enabled ? 1 : 0);
		string(task.name);
		string("");
		u8(task.switchBack ? 1 : 0);
		u32(task.intervalDays);
		u32(task.action);
		string(task.target);
		string(task.payload);
		u32(0);
	}
	u32(config.kaTrafficKB);
	const payload = Buffer.concat(parts);
	const header = Buffer.alloc(20);
	header.write("CFG2"); header.writeUInt16LE(7, 4); header.writeUInt32LE(payload.length, 12); header.writeUInt32LE(crc32(payload), 16);
	return Buffer.concat([header, payload]);
}

function decodePortableConfig(bytes, target) {
	const schemaVersion = bytes.length >= 6 ? bytes.readUInt16LE(4) : 0;
	if (bytes.length < 20 || bytes.subarray(0, 4).toString() !== "CFG2" || ![1, 2, 3, 4, 5, 6, 7].includes(schemaVersion) ||
		bytes.readUInt16LE(6) !== 0 || bytes.readUInt32LE(8) !== 0 || bytes.readUInt32LE(12) !== bytes.length - 20 ||
		bytes.readUInt32LE(16) !== crc32(bytes.subarray(20))) throw new Error("portable");
	let offset = 20;
	const u32 = () => {
		if (offset + 4 > bytes.length) throw new Error("portable");
		const value = bytes.readUInt32LE(offset); offset += 4; return value;
	};
	const i32 = () => {
		if (offset + 4 > bytes.length) throw new Error("portable");
		const value = bytes.readInt32LE(offset); offset += 4; return value;
	};
	const u8 = () => {
		if (offset >= bytes.length) throw new Error("portable");
		return bytes[offset++];
	};
	const boolean = () => {
		const value = u8();
		if (value > 1) throw new Error("portable");
		return value === 1;
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
	if (schemaVersion >= 5) {
		const decoded = defaultConfig();
		decoded.smtpPort = u32();
		[decoded.deviceName, decoded.hostname, decoded.notificationLocale, decoded.smtpServer,
			decoded.smtpUser, decoded.smtpPass, decoded.smtpSendTo, decoded.adminPhone,
			decoded.numberBlackList] = Array.from({ length: 9 }, string);
		if (u8() !== 10) throw new Error("portable");
		decoded.webAccounts = Array.from({ length: 10 }, () => ({ username: string(), password: string() }));
		if (u8() !== 5) throw new Error("portable");
		decoded.pushChannels = Array.from({ length: 5 }, () => {
			const enabled = boolean();
			const type = u32();
			if (type < 1 || type > 12) throw new Error("portable");
			const [name, url, key1, key2, titleTemplate, bodyTemplate, customBody] = Array.from({ length: 7 }, string);
			const cellularEnabled = schemaVersion >= 7 ? boolean() : true;
			const cellularUrl = schemaVersion >= 7 ? string() : "";
			return { enabled, cellularEnabled, cellularUrl, type, name, url, key1, key2, titleTemplate, bodyTemplate, customBody };
		});
		if (u8() !== 5) throw new Error("portable");
		decoded.wifiProfiles = Array.from({ length: 5 }, () => ({ ssid: string(), password: string() }));
		decoded.networkMode = u32();
		decoded.heartbeatEnable = boolean();
		decoded.heartbeatInterval = u32();
		decoded.wifiTxPowerQuarterDbm = u32();
		decoded.emailEnabled = boolean();
		decoded.pushEnabled = boolean();
		decoded.forwardRules = string();
		decoded.kaEnabled = boolean();
		decoded.kaIntervalDays = u32();
		decoded.kaAction = u32();
		decoded.kaTarget = string();
		decoded.kaUrl = string();
		decoded.kaProfile = string();
		decoded.kaLastTime = u32();
		decoded.tzOffsetMin = i32();
		decoded.ntpServer = string();
		decoded.rebootEnabled = boolean();
		decoded.rebootHour = u32();
		decoded.smsHealthEnabled = boolean();
		decoded.smsHealthHour = u32();
		decoded.smsHealthNotify = boolean();
		decoded.netLedEnabled = boolean();
		decoded.callNotifyEnabled = boolean();
		decoded.dataEnabled = boolean();
		decoded.roamingEnabled = boolean();
		decoded.apn = string();
		decoded.operatorPlmn = string();
		decoded.phoneNumber = string();
		if (u8() !== 5) throw new Error("portable");
		decoded.simCredentials = Array.from({ length: 5 }, () => ({
			iccid: string(), pin: string(), puk: string(), pinMaxAttempts: u32(),
			pukMaxAttempts: u32(), pinFailedAttempts: u32(), pukFailedAttempts: u32()
		}));
		if (u8() !== 6) throw new Error("portable");
		decoded.schedTasks = Array.from({ length: 6 }, () => ({
			enabled: boolean(), name: string(), profile: string(), switchBack: boolean(),
			intervalDays: u32(), action: u32(), target: string(), payload: string(), lastRun: u32()
		}));
		decoded.kaTrafficKB = schemaVersion >= 6 ? u32() : target.kaTrafficKB;
		if (offset !== bytes.length) throw new Error("portable");
		if (!configSemanticallyValid(decoded)) throw new Error("portable");
		decoded.deviceName = target.deviceName;
		decoded.hostname = target.hostname;
		decoded.webAccounts = structuredClone(target.webAccounts);
		decoded.wifiTxPowerQuarterDbm = target.wifiTxPowerQuarterDbm;
		decoded.kaProfile = target.kaProfile;
		decoded.kaLastTime = target.kaLastTime;
		decoded.roamingEnabled = target.roamingEnabled;
		decoded.phoneNumber = target.phoneNumber;
		decoded.simCredentials = structuredClone(target.simCredentials);
		for (let index = 0; index < 6; index += 1) {
			decoded.schedTasks[index].profile = target.schedTasks[index].profile;
			decoded.schedTasks[index].lastRun = target.schedTasks[index].lastRun;
		}
		if (!configSemanticallyValid(decoded)) throw new Error("portable");
		return decoded;
	}
	const decoded = {
		deviceName: target.deviceName,
		hostname: target.hostname,
		notificationLocale: "zh-TW",
		wifiProfiles: Array.from({ length: 5 }, () => ({ ssid: "", password: "" })),
		networkMode: 0,
		heartbeatEnable: true,
		heartbeatInterval: 6,
		smtpPort: u32()
	};
	if (schemaVersion === 1) {
		[decoded.smtpServer, decoded.smtpUser, decoded.smtpPass, decoded.smtpSendTo,
			decoded.adminPhone, decoded.numberBlackList] = Array.from({ length: 6 }, string);
	} else {
		[decoded.deviceName, decoded.hostname, decoded.notificationLocale, decoded.smtpServer, decoded.smtpUser,
			decoded.smtpPass, decoded.smtpSendTo, decoded.adminPhone, decoded.numberBlackList] = Array.from({ length: 9 }, string);
	}
	decoded.webAccounts = Array.from({ length: 10 }, () => ({ username: string(), password: string() }));
	decoded.pushChannels = Array.from({ length: 5 }, () => {
		if (offset + 2 > bytes.length) throw new Error("portable");
		const enabledByte = bytes[offset++];
		if (enabledByte > 1) throw new Error("portable");
		const enabled = enabledByte === 1;
		const storedType = bytes[offset++];
		if (storedType > (schemaVersion < 3 ? 10 : 12)) throw new Error("portable");
		const type = storedType === 0 ? 1 : storedType;
		const values = Array.from({ length: schemaVersion === 1 ? 5 : 7 }, string);
		const [name, url, key1, key2] = values;
		const titleTemplate = schemaVersion === 1 ? "" : values[4];
		const bodyTemplate = schemaVersion === 1 ? "" : values[5];
		const customBody = schemaVersion === 1 ? (type === 7 ? values[4] : "") : values[6];
		return { enabled, cellularEnabled: true, cellularUrl: "", type, name, url, key1, key2, titleTemplate, bodyTemplate, customBody };
	});
	if (schemaVersion === 4) {
		decoded.wifiProfiles = Array.from({ length: 5 }, () => ({ ssid: string(), password: string() }));
		if (offset + 6 > bytes.length) throw new Error("portable");
		decoded.networkMode = bytes[offset++];
		const heartbeatEnable = bytes[offset++];
		if (heartbeatEnable > 1) throw new Error("portable");
		decoded.heartbeatEnable = heartbeatEnable === 1;
		decoded.heartbeatInterval = u32();
	} else {
		decoded.wifiProfiles = structuredClone(target.wifiProfiles);
		decoded.networkMode = target.networkMode;
		decoded.heartbeatEnable = target.heartbeatEnable;
		decoded.heartbeatInterval = target.heartbeatInterval;
	}
	if (offset !== bytes.length) throw new Error("portable");
	const currentDefaults = defaultConfig();
	for (const key of ["wifiTxPowerQuarterDbm", "emailEnabled", "pushEnabled", "forwardRules", "kaEnabled",
		"kaIntervalDays", "kaAction", "kaTarget", "kaUrl", "kaProfile", "kaLastTime", "kaTrafficKB",
		"tzOffsetMin", "ntpServer", "rebootEnabled", "rebootHour", "smsHealthEnabled", "smsHealthHour",
		"smsHealthNotify", "netLedEnabled", "callNotifyEnabled", "dataEnabled", "roamingEnabled", "apn",
		"operatorPlmn", "phoneNumber", "simCredentials", "schedTasks"]) {
		decoded[key] = structuredClone(target[key] ?? currentDefaults[key]);
	}
	if (!configSemanticallyValid(decoded)) throw new Error("portable");
	decoded.deviceName = target.deviceName;
	decoded.hostname = target.hostname;
	decoded.webAccounts = structuredClone(target.webAccounts);
	if (!configSemanticallyValid(decoded)) throw new Error("portable");
	return decoded;
}

const fieldLimits = {
	smtpServer: 253, smtpPort: 32, smtpUser: 254, smtpPass: 256, smtpSendTo: 256,
	adminPhone: 64, numberBlackList: 1024, phone: 32, content: 2048,
	forwardRules: 2048,
	cmd: 256, action: 32, type: 32, deviceName: 64, hostname: 32, notificationLocale: 16,
	networkMode: 32, heartbeatEnable: 32, heartbeatInterval: 32,
	emailEnabled: 32, pushEnabled: 32,
	kaEnabled: 32, kaIntervalDays: 32, kaTrafficKB: 32, kaUrl: 256
};

const forwardRulesValid = (rules) => previewMockRules(rules).success;

function configSemanticallyValid(config) {
	const bounded = (value, limit) => typeof value === "string" && byteLength(value) <= limit;
	const integer = (value, minimum, maximum) => Number.isInteger(value) && value >= minimum && value <= maximum;
	const boolean = (value) => typeof value === "boolean";
	if (!bounded(config.deviceName, 64) || !config.deviceName || [...config.deviceName].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127) ||
		!bounded(config.hostname, 32) || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(config.hostname) ||
		!["zh-TW", "zh-CN", "en"].includes(config.notificationLocale) || !integer(config.smtpPort, 1, 65535) ||
		!bounded(config.smtpServer, 253) ||
		!bounded(config.smtpUser, 254) || !bounded(config.smtpPass, 256) || !bounded(config.smtpSendTo, 256) ||
		!bounded(config.adminPhone, 64) || !bounded(config.numberBlackList, 1024) ||
		!Array.isArray(config.webAccounts) || config.webAccounts.length !== 10 ||
		config.webAccounts.some((account) => !bounded(account.username, 64) || !bounded(account.password, 96)) ||
		!Array.isArray(config.pushChannels) || config.pushChannels.length !== 5 ||
		!Array.isArray(config.wifiProfiles) || config.wifiProfiles.length !== 5 ||
		config.wifiProfiles.some((profile) => !bounded(profile.ssid, 31) || !bounded(profile.password, 63) ||
			(!profile.ssid && profile.password) || (profile.password && !/^[\x20-\x7e]{8,63}$/.test(profile.password))) ||
		!integer(config.networkMode, 0, 2) || !boolean(config.heartbeatEnable) ||
		!integer(config.heartbeatInterval, 1, 240) || ![8, 20, 28, 34, 44, 52, 56, 60, 66, 72, 80].includes(config.wifiTxPowerQuarterDbm) ||
		!boolean(config.emailEnabled) || !boolean(config.pushEnabled) || !bounded(config.forwardRules, 2048) ||
		!forwardRulesValid(config.forwardRules) ||
		!boolean(config.kaEnabled) || !integer(config.kaIntervalDays, 1, 3650) ||
		!integer(config.kaAction, 0, 3) || !bounded(config.kaTarget, 64) || !bounded(config.kaUrl, 256) ||
		!bounded(config.kaProfile, 64) || !integer(config.kaLastTime, 0, 0xffffffff) ||
		!integer(config.kaTrafficKB, 1, 10000) || !integer(config.tzOffsetMin, -720, 840) ||
		!bounded(config.ntpServer, 128) || !boolean(config.rebootEnabled) || !integer(config.rebootHour, 0, 23) ||
		!boolean(config.smsHealthEnabled) || !integer(config.smsHealthHour, 0, 23) ||
		![config.smsHealthNotify, config.netLedEnabled, config.callNotifyEnabled, config.dataEnabled, config.roamingEnabled].every(boolean) ||
		!bounded(config.apn, 96) || !bounded(config.operatorPlmn, 16) || !bounded(config.phoneNumber, 32) ||
		!Array.isArray(config.simCredentials) || config.simCredentials.length !== 5 ||
		config.simCredentials.some((credential) => !bounded(credential.iccid, 22) || !bounded(credential.pin, 8) ||
			!bounded(credential.puk, 8) || !integer(credential.pinMaxAttempts, 1, 2) ||
			!integer(credential.pukMaxAttempts, 1, 5) || !integer(credential.pinFailedAttempts, 0, 2) ||
			!integer(credential.pukFailedAttempts, 0, 5)) ||
		!Array.isArray(config.schedTasks) || config.schedTasks.length !== 6 ||
		config.schedTasks.some((task) => !boolean(task.enabled) || !bounded(task.name, 32) ||
			!bounded(task.profile, 64) || !boolean(task.switchBack) || !integer(task.intervalDays, 1, 3650) ||
			!integer(task.action, 0, 3) || !bounded(task.target, 128) || !bounded(task.payload, 128) ||
			!integer(task.lastRun, 0, 0xffffffff))) return false;
	return config.pushChannels.every((channel) => integer(channel.type, 1, 12) &&
		boolean(channel.enabled) && boolean(channel.cellularEnabled) && bounded(channel.name, 64) && bounded(channel.url, 512) && bounded(channel.cellularUrl, 512) &&
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

function initialState(startedAt = Date.now()) {
	return {
		startedAt,
		apMode: true,
		flightMode: false,
		logs: ["Mock device started", "WiFi connected: MockNetwork"],
		config: defaultConfig()
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
	"ACTION_WIFI_PASSWORD_REQUIRED",
	"ACTION_PING_OK",
	"ACTION_PING_MODEM_ERROR",
	"ACTION_PING_UNREACHABLE",
	"ACTION_PING_TIMEOUT",
	"ACTION_PING_UNSUPPORTED",
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
	"ACTION_DEVICE_RESTARTING",
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
	, "ACTION_ESIM_IDLE", "ACTION_ESIM_RUNNING", "ACTION_ESIM_COMPLETE", "ACTION_ESIM_FAILED"
	, "ACTION_ESIM_BUSY", "ACTION_ESIM_HANDLE_STALE"
	, "ACTION_ESIM_CONFIRMATION_STALE", "ACTION_ESIM_NOTIFICATION_PENDING", "ACTION_ESIM_INSTALLATION_UNCERTAIN"
	, "ACTION_ESIM_POSTPONED"
	, "ACTION_ESIM_CANCELLATION_FAILED"
	, "PUSH_CA_PROBE_READY", "PUSH_CA_PROBE_FAILED", "PUSH_CA_INSTALLED", "PUSH_CA_STALE"
	, "PUSH_CA_REJECTED", "PUSH_CA_STORE_FAILED", "PUSH_CA_STATUS"
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

function boundedUnsigned(value, minimum, maximum) {
	if (typeof value !== "string" || !/^\d+$/.test(value)) return undefined;
	const number = Number(value);
	return Number.isSafeInteger(number) && number >= minimum && number <= maximum ? number : undefined;
}

function parsePushTestQuery(query, originalUrl = "") {
	const queryText = originalUrl.split("?", 2)[1] ?? "";
	if (!queryText || queryText.length > 63 || queryText.startsWith("&") ||
		queryText.endsWith("&") || queryText.includes("&&")) return undefined;
	const keys = Object.keys(query);
	if (keys.length < 1 || keys.length > 2 || !keys.includes("channel") ||
		keys.some((key) => key !== "channel" && key !== "detail")) return undefined;
	const channel = boundedUnsigned(query.channel, 0, 4);
	if (channel === undefined) return undefined;
	if (!Object.hasOwn(query, "detail")) return { channel, detail: false };
	return query.detail === "1" ? { channel, detail: true } : undefined;
}

function saveFieldFamily(field) {
	const direct = {
		deviceName: "identity", hostname: "identity", notificationLocale: "locale",
		emailEnabled: "email", smtpServer: "email", smtpPort: "email", smtpUser: "email", smtpPass: "email", smtpSendTo: "email",
		pushEnabled: "push",
		adminPhone: "routing", numberBlackList: "routing", forwardRules: "routing", networkMode: "network",
		heartbeatEnable: "heartbeat", heartbeatInterval: "heartbeat",
		kaEnabled: "keepalive", kaIntervalDays: "keepalive", kaTrafficKB: "keepalive", kaUrl: "keepalive"
	};
	if (Object.hasOwn(direct, field)) return { family: direct[field] };
	let match = field.match(/^account([0-9])(user|pass)$/);
	if (match) return { family: "accounts" };
	match = field.match(/^wifi([0-4])(ssid|pass|open)$/);
	if (match) return { family: "wifi", index: Number(match[1]) };
	match = field.match(/^push([0-4])(en|type|name|url|key1|key2|body|title|template|cellularEnabled|cellularUrl|cellularUrlClear)$/);
	return match ? { family: "push", index: Number(match[1]) } : undefined;
}

function modemCommandAllowed(input) {
	const command = String(input ?? "").trim().toUpperCase();
	return command.startsWith("AT") && !/[\r\n]/.test(input) && !command.startsWith("ATD") && command !== "ATO" &&
		!["AT+CMGS", "AT+CMGW", "AT+CGDATA", "AT+CMUX"].some((prefix) => command.startsWith(prefix)) &&
		!["CIPSEND", "QISEND", "CASEND"].some((value) => command.includes(value));
}

function parseUint32(value, allowZero = false) {
	const text = typeof value === "string" ? value : "";
	if (!/^\d+$/.test(text)) return undefined;
	const parsed = Number(text);
	return Number.isSafeInteger(parsed) && parsed <= 0xffffffff && (allowZero || parsed > 0) ? parsed : undefined;
}

function parseOtaManifest(text) {
	if (typeof text !== "string" || byteLength(text) > 512) return undefined;
	const match = text.match(/^\{"format":1,"releaseCounter":([1-9][0-9]*),"sha256":"([0-9a-f]{64})","size":([1-9][0-9]*),"target":"esp32c3","version":"([A-Za-z0-9._+-]{1,32})"\}$/);
	if (!match) return undefined;
	const releaseCounter = Number(match[1]);
	const size = Number(match[3]);
	return Number.isInteger(releaseCounter) && releaseCounter <= 0xffffffff &&
		Number.isInteger(size) && size <= 0x1e0000
		? { releaseCounter, sha256: match[2], size, version: match[4] }
		: undefined;
}

export function createApp({
	webRoot = defaultWebRoot,
	openApiPath = defaultOpenApiPath,
	authRequired = true,
	apLocalAddress = "192.168.1.1",
	now = Date.now,
	jobDelayMs = 0,
	esimConfirmationRequired = false,
	esimNotificationPending = false,
	esimSchedule = (run, delay) => setTimeout(run, delay).unref(),
	pushCaRejectCount = 0,
	otaPublicKey = defaultOtaPublicKey,
	otaAcceptedCounter = 0
} = {}) {
	const app = express();
	const state = initialState(now());
	const csrfToken = "mock-csrf-token";
	const jobs = new Map();
	const pushTests = Array.from({ length: 5 }, () => ({
		queued: false, running: false, done: false, success: false, message: "Test not started"
	}));
	const pushTestDeadlines = Array(5).fill(0);
	const pushCa = Array.from({ length: 6 }, () => ({ configured: false, sha256: "" }));
	const keepalive = { jobQueued: false, jobRunning: false, jobDone: false, jobSuccess: false, jobMessage: "", bodyBytes: 0, requests: 0, cancelRequested: false };
	const keepaliveUrlValid = (url) => {
		try { const parsed = new URL(url); return url.startsWith("https://") && parsed.protocol === "https:" && !parsed.username && !parsed.password && !parsed.hash && !/\s/.test(url) && ![...url].some((ch) => ch.charCodeAt(0) < 32) && byteLength(url) <= 256; }
		catch { return false; }
	};
	const caChannel = (request) => request.path.startsWith("/api/keepalive/ca/") ? 5 : boundedUnsigned(request.query.channel, 0, 4);
	const caQuerySize = (channel, install = false) => (channel === 5 ? 0 : 1) + (install ? 1 : 0);
	const pushCaNonces = new Map();
	const exportsById = new Map();
	let upload;
	let deviceRestartPending = false;
	let otaRestartPending = false;
	let restoreRestartPending = false;
	let nextId = 1;
	let acceptedOtaCounter = otaAcceptedCounter;
	let remainingPushCaRejections = pushCaRejectCount;
	const esim = {
		eid: "89012345678901234567890123456789",
		profiles: [
			{ iccid: "8988212345678901234", isdpAid: "A0000005591010FFFFFFFF89000001", state: "enabled", nickname: "Primary", profileClass: "operational" },
			{ iccid: "8988212345678905678", isdpAid: "A0000005591010FFFFFFFF89000002", state: "disabled", nickname: "Backup", profileClass: "operational" }
		],
		handles: ["p1111111111111111", "p2222222222222222"],
		job: { id: 0, state: "idle", action: "", success: false, code: "ACTION_ESIM_IDLE", stage: "", confirmationRequired: false, notificationPending: false, profileName: "", providerName: "" },
		nextJobId: 1
	};
	let esimConfirmationDeadline = 0;
	const esimStatus = () => ({
		eid: { available: Boolean(esim.eid), state: esim.eid ? "available" : "unavailable", length: esim.eid.length },
		profiles: esim.profiles.map((profile, index) => ({
			handle: esim.handles[index], displayId: "••••", state: profile.state,
			nickname: profile.nickname, profileClass: profile.profileClass
		})),
		job: { ...esim.job }
	});
	const finishEsimJob = (job, action, handle, nickname) => {
		if (job.state !== "queued" && job.state !== "running") return;
		const index = handle ? esim.handles.indexOf(handle) : -1;
		if (action !== "refresh" && action !== "info" && action !== "install" && index < 0) {
			job.state = "failed";
			job.success = false;
			job.code = "ACTION_ESIM_HANDLE_STALE";
			return;
		}
		if (action === "install") {
			esim.profiles.push({ state: "disabled", nickname: "Installed profile", profileClass: "operational" });
			esim.handles = esim.profiles.map((_, profileIndex) => `p${(job.id * 32 + profileIndex + 1).toString(16).padStart(16, "0")}`);
			job.stage = "completed";
			job.notificationPending = esimNotificationPending;
		} else if (action === "refresh") {
			esim.handles = esim.profiles.map((_, profileIndex) => `p${(profileIndex + 1).toString(16).padStart(16, "0")}`);
		} else if (action === "info") {
			// The mock keeps the same structural EID state.
		} else if (action === "nickname") {
			esim.profiles[index].nickname = nickname;
		} else if (action === "delete") {
			esim.profiles.splice(index, 1);
			esim.handles.splice(index, 1);
		} else {
			if (action === "enable" || action === "switch") esim.profiles.forEach((profile, profileIndex) => { profile.state = profileIndex === index ? "enabled" : "disabled"; });
			if (action === "disable") esim.profiles[index].state = "disabled";
		}
		job.state = "succeeded";
		job.success = true;
		job.code = job.notificationPending ? "ACTION_ESIM_NOTIFICATION_PENDING" : "ACTION_ESIM_COMPLETE";
	};
	const startEsimInstall = (job) => {
		job.state = "running";
		job.stage = "awaiting_confirmation";
		job.confirmationRequired = esimConfirmationRequired;
		job.profileName = "Installed profile";
		job.providerName = "Example carrier";
		esimConfirmationDeadline = now() + 300000;
		esimSchedule(() => {
			if (esim.job !== job || job.stage !== "awaiting_confirmation") return;
			job.confirmationRequired = false;
			job.profileName = job.providerName = job.stage = "";
			job.state = "failed";
			job.code = "ACTION_ESIM_FAILED";
			esimConfirmationDeadline = 0;
		}, 300000);
	};
	const expireUpload = () => {
		if (upload && now() - upload.lastActivity >= 120000) upload = undefined;
	};
	const expireExports = () => {
		for (const [id, item] of exportsById) if (now() >= item.expiresAt) exportsById.delete(id);
	};
	const expireJobs = () => {
		for (const [id, job] of jobs) {
			if (["succeeded", "failed"].includes(job.state) && now() - job.completedAt >= 60000) jobs.delete(id);
		}
	};
	const pushTestFailure = (message, details = {}) => ({
		queued: false, running: false, done: true, success: false, message, ...details
	});
	const expirePushTests = () => pushTests.forEach((status, channel) => {
		if (!status.queued || !pushTestDeadlines[channel] || now() < pushTestDeadlines[channel]) return;
		pushTests[channel] = pushTestFailure("Test push timed out before it could start", pushTestDetailFixtures.preflightFailure);
		pushTestDeadlines[channel] = 0;
	});
	const pushTestActive = () => {
		expirePushTests();
		return pushTests.some((test) => test.queued || test.running);
	};
	const pushChannelConfigured = (channel) => {
		if (!channel.enabled || (channel.type === 7
			? !channel.customBody || channel.titleTemplate || channel.bodyTemplate
			: channel.customBody)) return false;
		if ([1, 2, 3, 4, 7, 8, 11, 12].includes(channel.type)) return Boolean(channel.url);
		if ([5, 6].includes(channel.type)) return Boolean(channel.key1);
		if (channel.type === 9) return Boolean(channel.url && channel.key1);
		return channel.type === 10 && Boolean(channel.key1 && channel.key2);
	};
	const acceptJob = (type, finalResult, response, { allowOta = false } = {}) => {
		expireJobs();
		if (!allowOta && (esim.job.state === "queued" || esim.job.state === "running")) {
			return response.status(409).json(result(false, "ACTION_BUSY"));
		}
		if (!allowOta && upload?.kind === "ota") {
			return response.status(409).json(result(false, "ACTION_BUSY"));
		}
		const active = [...jobs.values()].filter((job) => job.state === "queued" || job.state === "running").length;
		if (active >= 3 || jobs.size >= 6) {
			return response.status(429).json(result(false, "ACTION_JOB_QUEUE_FULL"));
		}
		const jobId = nextId++;
		const job = { id: jobId, type, state: "queued" };
		jobs.set(jobId, job);
		const finish = () => {
			if (!jobs.has(jobId)) return;
			job.state = "running";
			const completed = typeof finalResult === "function" ? finalResult() : finalResult;
			job.result = completed;
			job.state = completed.success ? "succeeded" : "failed";
			job.completedAt = now();
		};
		if (jobDelayMs > 0) setTimeout(finish, jobDelayMs);
		else finish();
		return response.status(202).json(result(true, "ACTION_JOB_ACCEPTED", { jobId }));
	};
	const indexPath = path.join(webRoot, "index.html");
	const provisioningPath = path.join(webRoot, "provisioning.html");
	const localAddress = (request) => request.socket.localAddress?.replace(/^::ffff:/, "");
	const apLocal = (request) => state.apMode && localAddress(request) === apLocalAddress;
	const apAuthBypass = (request) => apLocal(request) && (
		(request.method === "GET" && request.originalUrl === "/") ||
		(request.method === "GET" && ["/wifiscan", "/apstatus"].some((route) =>
			request.originalUrl === route || request.originalUrl.startsWith(`${route}?`))) ||
		(request.method === "POST" && request.originalUrl === "/wificonfig")
	);
	const csrfRoutes = new Set([
		"POST /save", "POST /sendsms", "POST /ping", "GET /flight", "GET /at", "GET /modem",
		"GET /wifi", "GET /api/config/export", "POST /api/config/export", "POST /api/config/restore/start",
		"POST /api/config/restore/chunk", "POST /api/config/restore/finish", "POST /api/ota/start",
		"POST /api/ota/chunk", "POST /api/ota/finish", "POST /api/push/test", "POST /api/device/restart",
		"POST /api/esim", "POST /wificonfig", "POST /api/push/ca/probe", "POST /api/push/ca/install", "POST /api/rules/preview",
		"POST /api/keepalive", "POST /api/keepalive/ca/probe", "POST /api/keepalive/ca/install"
	]);
	app.use(rejectEnvelope);
	app.use("/api/esim", (_request, response, next) => {
		response.set("Cache-Control", "no-store, max-age=0");
		next();
	});
	app.use((request, response, next) => request.method === "HEAD" &&
		!["/api/push/test", "/api/device/restart", "/api/push/ca/status", "/api/push/ca/probe", "/api/push/ca/install"].includes(request.path)
		? response.set("Allow", "GET, POST").status(405).json(result(false, "ACTION_INPUT_INVALID"))
		: next());

	if (authRequired) app.use((request, response, next) => {
		if (apAuthBypass(request)) return next();
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

	app.use(express.raw({ type: "application/pkix-cert", limit: 8192 }));
	app.use(express.urlencoded({ extended: false, limit: 16384 }));
	app.use((request, _response, next) => {
		request.body ??= {};
		next();
	});
	app.use((request, response, next) => {
		const apCsrf = apLocal(request) && request.method === "POST" && request.originalUrl === "/wificonfig" &&
			request.headers["x-sms-csrf"] === "1";
		if (apCsrf || !csrfRoutes.has(`${request.method} ${request.path}`) || request.headers["x-csrf-token"] === csrfToken) return next();
		response.status(403).json(result(false, "ACTION_CSRF_INVALID"));
	});

	for (const route of ["/", "/tools", "/sms"]) {
		app.get(route, (request, response) => {
			const pagePath = route === "/" && apLocal(request) && request.originalUrl === "/"
				? provisioningPath : indexPath;
			if (!existsSync(pagePath)) {
				response.status(503).type("text/plain").send("Web bundle missing. Run scripts/dev.sh build frontend.");
				return;
			}
			response.set("Cache-Control", "no-store");
			response.sendFile(path.basename(pagePath), { root: path.dirname(pagePath) });
		});
	}

	app.get("/wifiscan", (_request, response) => {
		response.set({ "X-WiFi-Scan-Busy": "0", "X-WiFi-Scan-Ready": "1" }).json([
			{ ssid: "MockNetwork", rssi: -54, enc: true },
			{ ssid: "Guest", rssi: -68, enc: false }
		]);
	});
	app.get("/apstatus", (_request, response) => response.json({ apMode: state.apMode, connected: false, ip: "" }));
	app.post("/wificonfig", (request, response) => {
		const ssid = String(request.body.ssid ?? "");
		const password = String(request.body.pass ?? "");
		if (!ssid || byteLength(ssid) > 31 || (password && !/^[\x20-\x7e]{8,63}$/.test(password))) {
			return response.status(400).json({ success: false, message: "Invalid WiFi configuration" });
		}
		state.config.wifiProfiles[0] = { ssid, password };
		return response.json({ success: true, message: "Saved; connecting" });
	});

	app.get("/api/config", (_request, response) => {
		const config = state.config;
		response.json({
			csrfToken,
			status: {
				ip: "192.168.1.1",
				wifiSsid: "sms-forwarder-000001",
				apMode: true,
				freeHeapKb: 247,
				uptimeSeconds: Math.floor((now() - state.startedAt) / 1000),
				modemReady: true,
				emailConfigured: Boolean(config.smtpServer && config.smtpUser && config.smtpPass && config.smtpSendTo),
				enabledPushChannels: config.pushChannels.filter((channel) => channel.enabled).length,
				firmwareVersion: "1"
			},
			config: {
				deviceName: config.deviceName, hostname: config.hostname, notificationLocale: config.notificationLocale,
				emailEnabled: config.emailEnabled, pushEnabled: config.pushEnabled,
				smtpServer: config.smtpServer, smtpPort: config.smtpPort, smtpUser: config.smtpUser,
				smtpSendTo: config.smtpSendTo, adminPhone: config.adminPhone, numberBlackList: config.numberBlackList,
				forwardRules: config.forwardRules,
				networkMode: config.networkMode, heartbeatEnable: config.heartbeatEnable,
				heartbeatInterval: config.heartbeatInterval, kaEnabled: config.kaEnabled,
				kaIntervalDays: config.kaIntervalDays, kaTrafficKB: config.kaTrafficKB,
				webAccounts: config.webAccounts.map((account) => ({ username: account.username, password: "" })),
				smtpPass: "",
				wifiProfiles: config.wifiProfiles.map((profile) => ({ ssid: profile.ssid, password: "", open: Boolean(profile.ssid && !profile.password) })),
				pushChannels: config.pushChannels.map((channel) => ({
					...channel,
					cellularUrl: undefined, cellularUrlSet: Boolean(channel.cellularUrl),
					url: "", urlSet: Boolean(channel.url),
					key1: "", key1Set: Boolean(channel.key1),
					key2: "", key2Set: Boolean(channel.key2),
					customBody: "", customBodySet: Boolean(channel.customBody)
				}))
			}
		});
	});

	app.all("/api/esim", (request, response, next) => {
		if (request.method === "GET" || request.method === "POST") return next();
		return response.set({ "Allow": "GET, POST", "Cache-Control": "no-store, max-age=0" }).status(405)
			.json(result(false, "ACTION_INPUT_INVALID", {}, "method"));
	});
	app.get("/api/esim", (request, response) => {
		if (Object.keys(request.query).length || Number(request.headers["content-length"] ?? 0) > 0 || request.headers["transfer-encoding"])
			return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, Object.keys(request.query).length ? "query" : "body"));
		return response.set("Cache-Control", "no-store, max-age=0").json(esimStatus());
	});
	app.post("/api/esim", (request, response) => {
		response.once("finish", () => {
			if (request.body) { delete request.body.activationCode; delete request.body.confirmationCode; }
		});
		if (Number(request.headers["content-length"] ?? 0) > 2048) return response.status(413).json(result(false, "ACTION_INPUT_TOO_LONG", {}, "body"));
		if (!request.body || !Object.keys(request.body).length || Object.keys(request.body).length > 4)
			return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, "body"));
		if (Object.keys(request.query).length) return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, "query"));
		const action = request.body.action;
		const allowed = new Set(action === "install" ? ["action", "activationCode"] : action === "confirm" ? ["action", "jobId", "accepted", "confirmationCode"] : ["action", "handle", "nickname"]);
		if (Object.keys(request.body).some((key) => !allowed.has(key)) || typeof request.body.action !== "string")
			return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, "body"));
		if (action === "confirm") {
			const code = request.body.confirmationCode;
			const jobIdText = request.body.jobId;
			const consent = request.body.accepted;
			if (Object.keys(request.body).length < 3 || !["true", "false"].includes(consent) || typeof jobIdText !== "string" || !/^[1-9][0-9]*$/.test(jobIdText) || Number(jobIdText) > 0xffffffff ||
				(code !== undefined && (typeof code !== "string" || !/^[\x20-\x7e]{1,128}$/.test(code)))) return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, "body"));
			const job = esim.job;
			if (job.id !== Number(jobIdText) || job.stage !== "awaiting_confirmation" || now() >= esimConfirmationDeadline)
				return response.status(409).json(result(false, "ACTION_ESIM_CONFIRMATION_STALE"));
			if ((consent === "true" && job.confirmationRequired) !== (code !== undefined)) return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, "confirmationCode"));
			job.confirmationRequired = false;
			job.profileName = job.providerName = "";
			esimConfirmationDeadline = 0;
			if (consent === "true") {
				job.stage = "preparing";
				finishEsimJob(job, "install", "", "");
			} else {
				job.stage = ""; job.state = "failed"; job.code = "ACTION_ESIM_POSTPONED";
			}
			return response.status(202).json(result(true, "ACTION_JOB_ACCEPTED", { jobId: job.id }));
		}
		if (action === "install" && (Object.keys(request.body).length !== 2 || typeof request.body.activationCode !== "string" ||
			!request.body.activationCode || byteLength(request.body.activationCode) > 516 || /[^\x20-\x7e]/.test(request.body.activationCode)))
			return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, "activationCode"));
		if (!["refresh", "info", "enable", "disable", "delete", "nickname", "switch", "install"].includes(action))
			return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, "action"));
		const handle = typeof request.body.handle === "string" ? request.body.handle : "";
		const nickname = typeof request.body.nickname === "string" ? request.body.nickname : "";
		if ((action === "refresh" || action === "info" || action === "install") ? handle || nickname : !handle)
			return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, "handle"));
		if (action !== "nickname" && nickname) return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, "nickname"));
		if (byteLength(nickname) > 64 || /[\r\n\t]/.test(nickname)) return response.status(400).json(result(false, "ACTION_INPUT_TOO_LONG", {}, "nickname"));
		if (handle && !/^p[0-9a-f]{16}$/.test(handle)) return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, "handle"));
		if (handle && !esim.handles.includes(handle)) return response.status(409).json(result(false, "ACTION_ESIM_HANDLE_STALE"));
		if (esim.job.state === "queued" || esim.job.state === "running" || deviceRestartPending || otaRestartPending || restoreRestartPending || upload || pushTestActive() ||
			[...jobs.values()].some((job) => job.state === "queued" || job.state === "running")) return response.status(409).json(result(false, "ACTION_ESIM_BUSY"));
		const job = esim.job = { id: esim.nextJobId++, state: "queued", action, success: false, code: "ACTION_ESIM_RUNNING", stage: action === "install" ? "validating" : "", confirmationRequired: false, notificationPending: false, profileName: "", providerName: "" };
		const finish = () => { job.state = "running"; if (action === "install") startEsimInstall(job); else finishEsimJob(job, action, handle, nickname); };
		if (jobDelayMs > 0) setTimeout(finish, jobDelayMs);
		else finish();
		return response.status(202).json(result(true, "ACTION_JOB_ACCEPTED", { jobId: job.id }));
	});

	app.all("/api/device/restart", (request, response, next) => {
		if (request.method === "POST") return next();
		return response.set("Allow", "POST").status(405)
			.json(result(false, "ACTION_INPUT_INVALID", {}, "method"));
	});
	app.post("/api/device/restart", (request, response) => {
		if (Number(request.headers["content-length"] ?? 0) > 0 || request.headers["transfer-encoding"] ||
			Object.keys(request.body).length) {
			return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, "body"));
		}
		expireJobs();
		expireUpload();
		expireExports();
		if (deviceRestartPending || otaRestartPending || restoreRestartPending || upload || exportsById.size || pushTestActive() ||
			[...jobs.values()].some((job) => job.state === "queued" || job.state === "running")) {
			return response.status(409).json(result(false, "ACTION_BUSY"));
		}
		deviceRestartPending = true;
		state.logs.push("Web UI requested device restart");
		return response.status(200).json(result(true, "ACTION_DEVICE_RESTARTING"));
	});

	app.all("/api/push/test", (request, response, next) => {
		if (request.method === "GET" || request.method === "POST") return next();
		return response.set("Allow", "GET, POST").status(405)
			.json(serializePushTestStatus(pushTestFailure("Push tests require GET or POST")));
	});
	app.get("/api/push/test", (request, response) => {
		expirePushTests();
		const parsed = parsePushTestQuery(request.query, request.originalUrl);
		return !parsed
			? response.status(400).json(serializePushTestStatus(pushTestFailure("Invalid channel index")))
			: response.json(serializePushTestStatus(pushTests[parsed.channel], parsed.detail));
	});
	app.post("/api/push/test", (request, response) => {
		expirePushTests();
		if (Number(request.headers["content-length"] ?? 0) > 0 || request.headers["transfer-encoding"]) {
			return response.status(400).json(serializePushTestStatus(pushTestFailure("Push test request body is not allowed")));
		}
		const parsed = parsePushTestQuery(request.query, request.originalUrl);
		if (!parsed) return response.status(400).json(serializePushTestStatus(pushTestFailure("Invalid channel index")));
		const channel = parsed.channel;
		const current = pushTests[channel];
		if (current.queued || current.running) return response.status(409).json(serializePushTestStatus(current, parsed.detail));
		expireJobs();
		if (upload || [...jobs.values()].some((job) => job.state === "queued" || job.state === "running")) {
			return response.status(409).json(serializePushTestStatus(pushTestFailure("Device is busy; try again later"), parsed.detail));
		}
		if (!state.config.pushEnabled) {
			return response.status(409).json(serializePushTestStatus(pushTestFailure("Push is disabled; test push is unavailable"), parsed.detail));
		}
		if (state.config.networkMode === 1) {
			return response.status(409).json(serializePushTestStatus(pushTestFailure("Cellular push is not supported; test was not queued"), parsed.detail));
		}
		if (!pushChannelConfigured(state.config.pushChannels[channel])) {
			return response.status(409).json(serializePushTestStatus(pushTestFailure(
				"Channel is disabled or incomplete; save its configuration first", pushTestDetailFixtures.targetFailure), parsed.detail));
		}
		const status = {
			queued: true, running: false, done: false, success: false,
			message: "Test push queued; you can continue to refresh the page"
		};
		pushTests[channel] = status;
		pushTestDeadlines[channel] = now() + 60000;
		const finish = () => {
			if (pushTests[channel] !== status || (!status.queued && !status.running)) return;
			status.queued = false;
			status.running = false;
			status.done = true;
			status.success = true;
			status.message = "Test push sent";
			Object.assign(status, pushTestDetailFixtures.wifiSuccess);
			pushTestDeadlines[channel] = 0;
			state.logs.push(`Channel ${channel + 1} test push sent`);
		};
		if (jobDelayMs > 0) setTimeout(finish, jobDelayMs);
		else finish();
		return response.status(202).json(serializePushTestStatus(status, parsed.detail));
	});

	app.use(["/api/push/ca", "/api/keepalive"], (_request, response, next) => {
		response.set("Cache-Control", "no-store, max-age=0");
		next();
	});
	for (const [route, allow] of [["/api/push/ca/status", "GET"], ["/api/push/ca/probe", "POST"], ["/api/push/ca/install", "POST"], ["/api/keepalive/ca/status", "GET"], ["/api/keepalive/ca/probe", "POST"], ["/api/keepalive/ca/install", "POST"]]) {
		app.all(route, (request, response, next) => request.method === allow ? next() : response.set("Allow", allow).status(405)
			.json(result(false, "ACTION_INPUT_INVALID", {}, "method")));
	}

	app.get(["/api/push/ca/status", "/api/keepalive/ca/status"], (request, response) => {
		const channel = caChannel(request);
		if (channel === undefined || Object.keys(request.query).length !== caQuerySize(channel) || request.headers["transfer-encoding"] ||
			Number(request.headers["content-length"] ?? 0) > 0 || Object.keys(request.body).length) {
			return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, "channel"));
		}
		return response.json(result(true, "PUSH_CA_STATUS", { ...pushCa[channel] }));
	});

	app.post(["/api/push/ca/probe", "/api/keepalive/ca/probe"], (request, response) => {
		const channel = caChannel(request);
		if (channel === undefined || Object.keys(request.query).length !== caQuerySize(channel) || request.headers["transfer-encoding"] ||
			Number(request.headers["content-length"] ?? 0) > 0 || Object.keys(request.body).length) {
			return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, "channel"));
		}
		if (channel === 5 ? !keepaliveUrlValid(state.config.kaUrl) : !state.config.pushChannels[channel].cellularEnabled) return response.status(409).json(result(false, "PUSH_CA_PROBE_FAILED"));
		return acceptJob("push_ca_probe", () => {
			const nonce = randomBytes(16).toString("hex");
			pushCaNonces.set(nonce, { channel, expiresAt: now() + 30000, url: channel === 5 ? state.config.kaUrl : "" });
			return result(true, "PUSH_CA_PROBE_READY", {
				nonce, expiresInMs: 30000,
				chain: [{ certSha256: "0".repeat(64), issuerDer: "MAMBAQ==", aki: "" }]
			});
		}, response);
	});

	app.post(["/api/push/ca/install", "/api/keepalive/ca/install"], (request, response) => {
		const channel = caChannel(request);
		const nonce = typeof request.query.nonce === "string" && /^[0-9a-f]{32}$/.test(request.query.nonce) ? request.query.nonce : "";
		if (channel === undefined || !nonce || Object.keys(request.query).length !== caQuerySize(channel, true)) return response.status(400).json(result(false, "ACTION_INPUT_INVALID"));
		if (request.headers["content-type"] !== "application/pkix-cert") return response.status(415).json(result(false, "ACTION_INPUT_INVALID"));
		const contentLength = typeof request.headers["content-length"] === "string" && /^\d+$/.test(request.headers["content-length"])
			? Number(request.headers["content-length"]) : 0;
		if (request.headers["transfer-encoding"] || !Buffer.isBuffer(request.body) || request.body.length < 1 ||
			request.body.length > 8192 || contentLength !== request.body.length) return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, "body"));
		const admission = pushCaNonces.get(nonce);
		pushCaNonces.delete(nonce);
		if (!admission || admission.channel !== channel || now() >= admission.expiresAt || (channel === 5 && admission.url !== state.config.kaUrl)) return response.status(409).json(result(false, "PUSH_CA_STALE"));
		const certificate = Buffer.from(request.body);
		return acceptJob("push_ca_install", () => {
			if (remainingPushCaRejections > 0) { remainingPushCaRejections -= 1; return result(false, "PUSH_CA_REJECTED"); }
			if (certificate[0] !== 0x30) return result(false, "PUSH_CA_REJECTED");
			const sha256 = createHash("sha256").update(certificate).digest("hex");
			pushCa[channel] = { configured: true, sha256 };
			return result(true, "PUSH_CA_INSTALLED", { sha256 });
		}, response);
	});

	app.all("/api/keepalive", (request, response) => {
		if (!["GET", "POST"].includes(request.method)) return response.set("Allow", "GET, POST").status(405).json(result(false, "ACTION_INPUT_INVALID"));
		const action = request.query.action ?? "";
		if (request.headers["transfer-encoding"] || Number(request.headers["content-length"] ?? 0) > 0 ||
			byteLength(request.originalUrl.split("?")[1] ?? "") >= 64 ||
			Object.keys(request.query).some((key) => key !== "action") || !["", "run", "reset", "cancel"].includes(action) || Object.keys(request.body).length) return response.status(400).json(result(false, "ACTION_INPUT_INVALID"));
		const config = state.config;
		const ready = config.kaAction !== 1 || (keepaliveUrlValid(config.kaUrl) && pushCa[5].configured && config.kaTrafficKB <= 512);
		if (action && request.method !== "POST") return response.json({ success: false, message: "This action requires POST" });
		if (action === "cancel") { keepalive.cancelRequested = true; return response.json({ success: true, message: "Cancellation requested" }); }
		if (action === "reset") { config.kaLastTime = Math.floor(now() / 1000); return response.json({ success: true, message: "Baseline date reset" }); }
		if (action === "run") {
			if (!ready) return response.json({ success: false, queued: false, message: "Check HTTPS URL and root CA first" });
			if (keepalive.jobQueued || keepalive.jobRunning) return response.json({ success: true, queued: true, message: "Keepalive already running" });
			Object.assign(keepalive, { jobQueued: true, jobRunning: false, jobDone: false, jobSuccess: false, bodyBytes: 0, requests: 0, cancelRequested: false });
			setTimeout(() => {
				Object.assign(keepalive, { jobQueued: false, jobDone: true, jobSuccess: !keepalive.cancelRequested, bodyBytes: keepalive.cancelRequested ? 0 : config.kaTrafficKB * 1024, requests: keepalive.cancelRequested ? 0 : 1 });
				if (keepalive.jobSuccess) config.kaLastTime = Math.floor(now() / 1000);
			}, Math.max(20, jobDelayMs));
			return response.json({ success: true, queued: true, message: "Keepalive queued" });
		}
		return response.json({ ...keepalive, enabled: config.kaEnabled, intervalDays: config.kaIntervalDays, trafficKB: config.kaTrafficKB, action: config.kaAction, url: config.kaUrl, target: config.kaTarget, profile: config.kaProfile, timeValid: true, lastTimeLocal: config.kaLastTime ? new Date(config.kaLastTime * 1000).toISOString() : "", daysLeft: config.kaIntervalDays, ready, readinessMessage: ready ? "" : "Check HTTPS URL and root CA first" });
	});

	app.post("/api/rules/preview", (request, response) => {
		const body = request.body ?? {};
		if (Object.keys(body).some((key) => !["rules", "sender", "text"].includes(key)) ||
			Object.entries(body).some(([key, value]) => typeof value !== "string" || value.includes("\0") || byteLength(value) > (key === "sender" ? 32 : 2048)))
			return response.status(400).json(result(false, "ACTION_INPUT_INVALID"));
		const preview = previewMockRules(body.rules ?? "", body.sender ?? "", body.text ?? "");
		preview.data.previewEngine = "mock";
		return acceptJob("rules_preview", preview, response);
	});
	app.post("/save", (request, response) => {
		if (pushTestActive()) return response.status(409).json(result(false, "ACTION_BUSY"));
		const body = request.body;
		const fields = Object.keys(body);
		if (!fields.length) return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, "form"));
		if (fields.length > 51) return response.status(400).json(result(false, "ACTION_TOO_MANY_FIELDS", {}, "form"));
		let saveFamily;
		let saveIndex;
		let mixedFamily = false;
		for (const field of fields) {
			if (typeof body[field] !== "string") return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, field));
			const current = saveFieldFamily(field);
			if (!current) return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, field));
			if (saveFamily && saveFamily !== current.family) mixedFamily = true;
			if (current.index !== undefined && saveIndex !== undefined && current.index !== saveIndex) mixedFamily = true;
			saveFamily = saveFamily ?? current.family;
			saveIndex = saveIndex ?? current.index;
		}
		if (mixedFamily) return acceptJob("save", result(false, "ACTION_CONFIG_INVALID"), response);
		if (Object.hasOwn(body, "forwardRules") && fields.length !== 1) {
			return acceptJob("config-save", result(false, "ACTION_CONFIG_INVALID", {}, "forwardRules"), response);
		}
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
			for (const [suffix, limit] of [["ssid", 31], ["pass", 63], ["open", 32]]) {
				const field = `wifi${index}${suffix}`;
				if (Object.hasOwn(body, field) && overLimit(field, body[field], limit)) return rejectField(response, field);
			}
			for (const [suffix, limit] of [["en", 32], ["type", 32], ["name", 64], ["url", 512], ["key1", 256], ["key2", 256], ["body", 2048], ["title", 256], ["template", 2048], ["cellularEnabled", 32], ["cellularUrl", 512], ["cellularUrlClear", 32]]) {
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
		if (Object.hasOwn(body, "forwardRules")) config.forwardRules = body.forwardRules;
		if (Object.hasOwn(body, "forwardRules") && !forwardRulesValid(config.forwardRules)) {
			return acceptJob("config-save", result(false, "ACTION_CONFIG_INVALID", {}, "forwardRules"), response);
		}
		if (Object.hasOwn(body, "deviceName")) config.deviceName = body.deviceName;
		if (Object.hasOwn(body, "hostname")) config.hostname = body.hostname;
		if (Object.hasOwn(body, "notificationLocale")) config.notificationLocale = body.notificationLocale;
		for (const field of ["emailEnabled", "pushEnabled"]) {
			if (!Object.hasOwn(body, field)) continue;
			if (!["0", "1"].includes(body[field])) return acceptJob("config-save", result(false, "ACTION_CONFIG_INVALID", {}, field), response);
			config[field] = body[field] === "1";
		}
		if (Object.hasOwn(body, "networkMode")) {
			const value = boundedUnsigned(body.networkMode, 0, 2);
			if (value === undefined) return response.status(400).json(result(false, "ACTION_CONFIG_INVALID", {}, "networkMode"));
			config.networkMode = value;
		}
		if (Object.hasOwn(body, "heartbeatEnable") || Object.hasOwn(body, "heartbeatInterval")) {
			config.heartbeatEnable = body.heartbeatEnable === "on";
			if (Object.hasOwn(body, "heartbeatInterval")) {
				const value = boundedUnsigned(body.heartbeatInterval, 1, 240);
				if (value === undefined) return response.status(400).json(result(false, "ACTION_CONFIG_INVALID", {}, "heartbeatInterval"));
				config.heartbeatInterval = value;
			}
		}
		if (["kaEnabled", "kaIntervalDays", "kaTrafficKB", "kaUrl"].some((key) => Object.hasOwn(body, key))) {
			config.kaEnabled = body.kaEnabled === "on";
			const url = body.kaUrl ?? config.kaUrl;
			if (config.kaAction === 1 && (config.kaEnabled || url !== config.kaUrl) && !keepaliveUrlValid(url)) return acceptJob("save", result(false, "ACTION_CONFIG_INVALID", {}, "kaUrl"), response);
			if (url !== config.kaUrl && (!keepaliveUrlValid(config.kaUrl) || !keepaliveUrlValid(url) || new URL(url).origin !== new URL(config.kaUrl).origin)) pushCa[5] = { configured: false, sha256: "" };
			config.kaUrl = url;
			for (const [field, minimum, maximum] of [["kaIntervalDays", 1, 3650], ["kaTrafficKB", 1, 10000]]) {
				if (!Object.hasOwn(body, field)) continue;
				const value = boundedUnsigned(body[field], minimum, maximum);
				if (value === undefined) return acceptJob("save", result(false, "ACTION_CONFIG_INVALID"), response);
				config[field] = value;
			}
			if (config.kaEnabled && config.kaAction === 1 && config.kaTrafficKB > 512) return acceptJob("save", result(false, "ACTION_CONFIG_INVALID", {}, "kaTrafficKB"), response);
		}
		for (let index = 0; index < 5; index += 1) {
			const prefix = `wifi${index}`;
			if (!["ssid", "pass", "open"].some((suffix) => Object.hasOwn(body, `${prefix}${suffix}`))) continue;
			const profile = config.wifiProfiles[index];
			const ssid = Object.hasOwn(body, `${prefix}ssid`) ? body[`${prefix}ssid`] : profile.ssid;
			const open = body[`${prefix}open`] === "on";
			const password = body[`${prefix}pass`] ?? "";
			if (ssid && !open && !password && (ssid !== profile.ssid || (profile.ssid && !profile.password))) {
				return response.status(400).json(result(false, "ACTION_WIFI_PASSWORD_REQUIRED", {}, `${prefix}ssid`));
			}
			profile.ssid = ssid;
			if (!ssid || open) profile.password = "";
			else if (password) profile.password = password;
		}

		for (let index = 0; index < 5; index += 1) {
			const prefix = `push${index}`;
			const suffixes = ["en", "type", "url", "name", "key1", "key2", "body", "title", "template", "cellularEnabled", "cellularUrl", "cellularUrlClear"];
			if (!suffixes.some((suffix) => Object.hasOwn(body, `${prefix}${suffix}`))) continue;
			const channel = config.pushChannels[index];
			const previousType = channel.type;
			if (Object.hasOwn(body, `${prefix}cellularEnabled`)) {
				if (!["0", "1"].includes(body[`${prefix}cellularEnabled`])) return acceptJob("config-save", result(false, "ACTION_CONFIG_INVALID", {}, `${prefix}cellularEnabled`), response);
				channel.cellularEnabled = body[`${prefix}cellularEnabled`] === "1";
			}
			if (body[`${prefix}cellularUrl`] && body[`${prefix}cellularUrlClear`] === "1") return acceptJob("config-save", result(false, "ACTION_CONFIG_INVALID", {}, `${prefix}cellularUrl`), response);
			if (body[`${prefix}cellularUrlClear`] === "1") channel.cellularUrl = "";
			else if (body[`${prefix}cellularUrl`]) channel.cellularUrl = body[`${prefix}cellularUrl`];
			channel.enabled = body[`${prefix}en`] === "on";
			if (Object.hasOwn(body, `${prefix}type`)) channel.type = Number.parseInt(body[`${prefix}type`], 10) || 0;
			if (channel.type !== previousType) {
				channel.url = "";
				channel.key1 = "";
				channel.key2 = "";
				channel.customBody = "";
			}
			if (Object.hasOwn(body, `${prefix}name`)) channel.name = body[`${prefix}name`];
			if (body[`${prefix}url`]) channel.url = body[`${prefix}url`];
			if (body[`${prefix}key1`]) channel.key1 = body[`${prefix}key1`];
			if (body[`${prefix}key2`]) channel.key2 = body[`${prefix}key2`];
			if (body[`${prefix}body`]) channel.customBody = body[`${prefix}body`];
			if (Object.hasOwn(body, `${prefix}title`)) channel.titleTemplate = body[`${prefix}title`];
			if (Object.hasOwn(body, `${prefix}template`)) channel.bodyTemplate = body[`${prefix}template`];
			if (channel.type === 7) {
				channel.titleTemplate = "";
				channel.bodyTemplate = "";
			} else {
				channel.customBody = "";
			}
			if (!channel.name) channel.name = `Channel ${index + 1}`;
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
		state.logs.push("Cellular ping is unsupported");
		acceptJob("ping", result(false, "ACTION_PING_UNSUPPORTED"), response);
	});

	app.get("/query", (request, response) => {
		if (overLimit("type", request.query.type)) return rejectField(response, "type");
		if (request.query.type === undefined) {
			return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, "type"));
		}
		const dataByType = {
			ati: { manufacturer: "Mock Telecom", model: "Mock LTE-C3", revision: "1.0.0" },
			signal: { rsrpDbm: -82, rsrqDb: -9, cesq: "-82,-9,16" },
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
		if (!data) return response.status(400).json(result(false, "ACTION_QUERY_UNKNOWN", {}, "type"));
		acceptJob("query", result(true, "ACTION_QUERY_OK", data), response);
	});

	app.get("/flight", (request, response) => {
		if (overLimit("action", request.query.action)) return rejectField(response, "action");
		const action = String(request.query.action ?? "query");
		if (action === "query") {
			acceptJob("flight", result(true, state.flightMode ? "ACTION_FLIGHT_STATUS_ON" : "ACTION_FLIGHT_STATUS_NORMAL", { mode: state.flightMode ? 4 : 1 }), response);
			return;
		}
		if (["toggle", "on", "off"].includes(action)) {
			state.flightMode = action === "toggle" ? !state.flightMode : action === "on";
			state.logs.push(`Flight mode ${state.flightMode ? "enabled" : "disabled"}`);
			acceptJob("flight", result(true, state.flightMode ? "ACTION_FLIGHT_ENABLED" : "ACTION_FLIGHT_DISABLED"), response);
			return;
		}
		return response.status(400).json(result(false, "ACTION_UNKNOWN", {}, "action"));
	});

	app.get("/at", (request, response) => {
		if (overLimit("cmd", request.query.cmd)) return rejectField(response, "cmd");
		const command = request.query.cmd?.trim() ?? "";
		if (!command || !modemCommandAllowed(request.query.cmd)) {
			return response.status(400).json(result(false, "ACTION_AT_REJECTED", {}, "cmd"));
		}
		state.logs.push(`AT command: ${command}`);
		return acceptJob("at", result(true, "ACTION_AT_OK", { raw: `${command}\r\nOK` }), response);
	});

	app.get("/log", (request, response) => {
		const limitText = String(request.query.limit ?? "50");
		const cursorText = String(request.query.cursor ?? "0");
		if (!/^\d+$/.test(limitText) || !/^\d+$/.test(cursorText)) {
			return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {},
				!/^\d+$/.test(limitText) ? "limit" : "cursor"));
		}
		const limit = Number.parseInt(limitText, 10);
		const cursor = Number.parseInt(cursorText, 10);
		if (limit < 1 || limit > 50) {
			return response.status(400).json(result(false, "ACTION_INPUT_INVALID", {}, "limit"));
		}
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
		if (pushTestActive()) return response.status(409).json(result(false, "ACTION_BUSY"));
		if (typeof request.body.passphrase !== "string" || byteLength(request.body.passphrase) < 12 ||
			byteLength(request.body.passphrase) > 128) return response.status(400).json(result(false, "ACTION_CONFIG_PASSPHRASE_INVALID"));
		const exportId = nextId++;
		exportsById.clear();
		exportsById.set(exportId, { bytes: encryptConfig(portableConfig(state.config), request.body.passphrase), expiresAt: now() + 120000 });
		const accepted = acceptJob("config-export", () => {
			const completed = result(true, "ACTION_CONFIG_EXPORT_READY", { exportId });
			const item = exportsById.get(exportId);
			if (completed.success && item) item.expiresAt = now() + 120000;
			return completed;
		}, response);
		if (response.statusCode !== 202) exportsById.delete(exportId);
		return accepted;
	});
	app.get("/api/config/export", (request, response) => {
		expireExports();
		const id = parseUint32(request.query.id);
		const item = exportsById.get(id);
		exportsById.delete(id);
		if (!item) return response.status(404).json(result(false, "ACTION_CONFIG_EXPORT_NOT_FOUND"));
		return response.set({
			"Content-Type": "application/vnd.sms-forwarding.config",
			"X-Config-Schema-Version": "7",
			"Content-Disposition": 'attachment; filename="sms-forwarding.smscfg"'
		}).send(item.bytes);
	});

	function startUpload(kind, metadata, response) {
		if (pushTestActive()) return response.status(409).json(result(false, "ACTION_BUSY"));
		expireUpload();
		if (upload) return response.status(409).json(result(false, kind === "ota" ? "ACTION_OTA_BUSY" : "ACTION_BUSY"));
		const uploadId = nextId++;
		upload = { kind, uploadId, bytes: Buffer.alloc(0), lastActivity: now(), ...metadata };
		return response.status(201).json(result(true, kind === "ota" ? "ACTION_OTA_UPLOAD_STARTED" : "ACTION_CONFIG_RESTORE_STARTED", { uploadId, chunkSize: 8192, nextOffset: 0 }));
	}

	function decodeBase64Chunk(body) {
		if (typeof body !== "string" || !body.length || body.length > 10924 ||
			body.length % 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(body)) return undefined;
		const bytes = Buffer.from(body, "base64");
		return bytes.length <= 8192 && bytes.toString("base64") === body ? bytes : undefined;
	}

	app.post("/api/config/restore/start", (request, response) => {
		const expectedSize = Object.keys(request.body).length === 1 ? parseUint32(request.body.size) : undefined;
		if (expectedSize === undefined || expectedSize < 60 || expectedSize > 32828) {
			return response.status(400).json(result(false, "ACTION_CONFIG_RESTORE_INVALID"));
		}
		return startUpload("restore", { expectedSize }, response);
	});
	app.post("/api/ota/start", (request, response) => {
		expireJobs();
		if (pushTestActive() || upload || [...jobs.values()].some((job) => job.state === "queued" || job.state === "running")) {
			return response.status(409).json(result(false, "ACTION_BUSY"));
		}
		if (!request.body || Object.keys(request.body).length !== 2 ||
			!Object.hasOwn(request.body, "manifest") || !Object.hasOwn(request.body, "signature")) {
			return response.status(400).json(result(false, "ACTION_OTA_MANIFEST_INVALID"));
		}
		const manifest = parseOtaManifest(request.body.manifest);
		if (!manifest || manifest.releaseCounter <= acceptedOtaCounter) {
			return response.status(400).json(result(false, "ACTION_OTA_MANIFEST_INVALID"));
		}
		const signature = request.body.signature;
		if (typeof signature !== "string" || signature.length < 16 || signature.length > 144 ||
			(signature.length & 1) !== 0 || !/^[0-9a-f]+$/.test(signature) ||
			!verify("sha256", Buffer.from(request.body.manifest), otaPublicKey, Buffer.from(signature, "hex"))) {
			return response.status(400).json(result(false, "ACTION_OTA_SIGNATURE_INVALID"));
		}
		return startUpload("ota", { expectedSize: manifest.size, manifest }, response);
	});

	for (const [kind, prefix] of [["restore", "/api/config/restore"], ["ota", "/api/ota"]]) {
		app.post(`${prefix}/chunk`, express.text({ type: "text/plain", limit: 10924 }), (request, response) => {
			const id = parseUint32(request.query.id);
			const offset = parseUint32(request.query.offset, true);
			const chunk = decodeBase64Chunk(request.body);
			expireUpload();
			if (id === undefined || offset === undefined || !upload || upload.kind !== kind || upload.uploadId !== id) {
				return response.status(409).json(result(false, kind === "ota" ? "ACTION_OTA_SESSION_INVALID" : "ACTION_CONFIG_RESTORE_CHUNK_INVALID"));
			}
			if (upload.bytes.length !== offset) {
				if (kind === "ota") upload = undefined;
				return response.status(kind === "ota" ? 400 : 409).json(result(false,
					kind === "ota" ? "ACTION_OTA_CHUNK_INVALID" : "ACTION_CONFIG_RESTORE_CHUNK_INVALID"));
			}
			if (!chunk || upload.bytes.length + chunk.length > upload.expectedSize) {
				upload = undefined;
				return response.status(kind === "ota" ? 400 : 409).json(result(false,
					kind === "ota" ? "ACTION_OTA_CHUNK_INVALID" : "ACTION_CONFIG_RESTORE_CHUNK_INVALID"));
			}
			upload.bytes = Buffer.concat([upload.bytes, chunk]);
			upload.lastActivity = now();
			return response.json(result(true, kind === "ota" ? "ACTION_OTA_CHUNK_OK" : "ACTION_CONFIG_RESTORE_CHUNK_OK", { nextOffset: upload.bytes.length }));
		});
		app.post(`${prefix}/finish`, (request, response) => {
			const id = parseUint32(request.query.id);
			expireUpload();
			if (id === undefined || !upload || upload.kind !== kind || upload.uploadId !== id) {
				return response.status(409).json(result(false,
					kind === "ota" ? "ACTION_OTA_SESSION_INVALID" : "ACTION_CONFIG_RESTORE_FINISH_INVALID"));
			}
			if (kind === "ota" && upload.finishing) {
				return response.status(409).json(result(false, "ACTION_OTA_SESSION_INVALID"));
			}
			if (kind === "restore" && (Object.keys(request.body).length !== 1 ||
				typeof request.body.passphrase !== "string" || byteLength(request.body.passphrase) < 12 ||
				byteLength(request.body.passphrase) > 128)) {
				upload = undefined;
				return response.status(400).json(result(false, "ACTION_CONFIG_PASSPHRASE_INVALID"));
			}
			if (upload.bytes.length !== upload.expectedSize) {
				if (kind === "ota") upload = undefined;
				return response.status(409).json(result(false,
					kind === "ota" ? "ACTION_OTA_SESSION_INVALID" : "ACTION_CONFIG_RESTORE_FINISH_INVALID"));
			}
			const session = upload;
			if (kind === "restore") upload = undefined;
			else session.finishing = true;
			const accepted = acceptJob(kind, () => {
				if (kind === "ota") {
					upload = undefined;
					if (createHash("sha256").update(session.bytes).digest("hex") !== session.manifest.sha256) {
						return result(false, "ACTION_OTA_HASH_INVALID");
					}
					acceptedOtaCounter = session.manifest.releaseCounter;
					otaRestartPending = true;
					return result(true, "ACTION_OTA_READY");
				}
				try {
					const restored = decodePortableConfig(decryptConfig(session.bytes, request.body.passphrase), state.config);
					state.config = restored;
					restoreRestartPending = true;
					return result(true, "ACTION_CONFIG_RESTORED");
				} catch {
					return result(false, "ACTION_CONFIG_RESTORE_INVALID");
				}
			}, response, { allowOta: kind === "ota" });
			if (kind === "ota" && response.statusCode !== 202) session.finishing = false;
			return accepted;
		});
	}

	app.get("/api/jobs", (request, response) => {
		expireJobs();
		const job = jobs.get(parseUint32(request.query.id));
		return job ? response.json({ id: job.id, type: job.type, state: job.state, ...(job.result ? { result: job.result } : {}) })
			: response.status(404).json(result(false, "ACTION_JOB_NOT_FOUND"));
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
		if (!actionResult) return response.status(400).json(result(false, "ACTION_UNKNOWN", {}, "action"));
		state.logs.push(`Modem action: ${request.query.action}`);
		acceptJob("modem", actionResult, response);
	});

	app.get("/wifi", (request, response) => {
		if (overLimit("action", request.query.action)) return rejectField(response, "action");
		if (request.query.action !== "restart") return response.status(400).json(result(false, "ACTION_UNKNOWN", {}, "action"));
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
