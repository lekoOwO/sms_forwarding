export type Locale = "zh-TW" | "zh-CN" | "en";

export type PushChannel = {
	enabled: boolean;
	type: number;
	name: string;
	url: string;
	urlSet: boolean;
	key1: string;
	key1Set: boolean;
	key2: string;
	key2Set: boolean;
	customBody: string;
	customBodySet: boolean;
	titleTemplate: string;
	bodyTemplate: string;
};

export type PushTestStatus = {
	queued: boolean;
	running: boolean;
	done: boolean;
	success: boolean;
	message: string;
};

export type EsimProfile = {
	handle: string;
	displayId: string;
	state: "enabled" | "disabled" | "unknown";
	nickname: string;
	profileClass: "operational" | "provisioning" | "unknown";
};

export type EsimStatus = {
	eid: {
		available: boolean;
		state: "available" | "unavailable";
		length: number;
	};
	profiles: EsimProfile[];
	job: {
		id: number;
		state: "idle" | "queued" | "running" | "succeeded" | "failed";
		action: string;
		success: boolean;
		code: string;
	};
};

export type WebAccount = {
	username: string;
	password: string;
};

export type WifiProfile = {
	ssid: string;
	password: string;
	open: boolean;
};

export type DeviceSnapshot = {
	csrfToken: string;
	status: {
		ip: string;
		wifiSsid: string;
		apMode: boolean;
		freeHeapKb: number;
		uptimeSeconds: number;
		modemReady: boolean;
		emailConfigured: boolean;
		enabledPushChannels: number;
		firmwareVersion: string;
	};
	config: {
		deviceName: string;
		hostname: string;
		notificationLocale: Locale;
		emailEnabled: boolean;
		pushEnabled: boolean;
		webAccounts: WebAccount[];
		smtpServer: string;
		smtpPort: number;
		smtpUser: string;
		smtpPass: string;
		smtpSendTo: string;
		adminPhone: string;
		numberBlackList: string;
		forwardRules: string;
		wifiProfiles: WifiProfile[];
		networkMode: number;
		heartbeatEnable: boolean;
		heartbeatInterval: number;
		kaEnabled: boolean;
		kaIntervalDays: number;
		kaTrafficKB: number;
		pushChannels: PushChannel[];
	};
};

export type LogEntry = { id: number; message: string };

export type LogPage = {
	entries: LogEntry[];
	nextCursor: number | null;
	hasMore: boolean;
};

export type Job = {
	id: number;
	type: string;
	state: "queued" | "running" | "succeeded" | "failed";
	result?: ActionResult;
};

export type ActionResult = {
	success: boolean;
	code: string;
	data: Record<string, string | number | boolean | null>;
	detail: string;
};

export type UiResult = {
	state: "idle" | "loading" | "success" | "error";
	code: string;
	data: ActionResult["data"];
	detail: string;
};
