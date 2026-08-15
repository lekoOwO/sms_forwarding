export type Locale = "zh-TW" | "zh-CN" | "en";

export type PushChannel = {
	enabled: boolean;
	type: number;
	name: string;
	url: string;
	key1: string;
	key2: string;
	customBody: string;
	titleTemplate: string;
	bodyTemplate: string;
};

export type WebAccount = {
	username: string;
	password: string;
};

export type DeviceSnapshot = {
	csrfToken: string;
	status: {
		ip: string;
		wifiSsid: string;
		freeHeapKb: number;
		uptimeSeconds: number;
		modemReady: boolean;
		emailConfigured: boolean;
		enabledPushChannels: number;
	};
	config: {
		deviceName: string;
		hostname: string;
		notificationLocale: Locale;
		webAccounts: WebAccount[];
		smtpServer: string;
		smtpPort: number;
		smtpUser: string;
		smtpPass: string;
		smtpSendTo: string;
		adminPhone: string;
		numberBlackList: string;
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
