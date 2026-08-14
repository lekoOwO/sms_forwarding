export type Locale = "zh-TW" | "zh-CN" | "en";

export type PushChannel = {
	enabled: boolean;
	type: number;
	name: string;
	url: string;
	key1: string;
	key2: string;
	customBody: string;
};

export type WebAccount = {
	username: string;
	password: string;
};

export type DeviceSnapshot = {
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
