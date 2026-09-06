export type Locale = "zh-TW" | "zh-CN" | "en";

export type PushChannel = {
	enabled: boolean;
	cellularEnabled: boolean;
	cellularUrl: string;
	cellularUrlSet: boolean;
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

export type PushTestDiagnosticReason =
	| "command_failure"
	| "timeout"
	| "response_invalid"
	| "terminal_failure"
	| "poll_timeout"
	| "result_nonzero"
	| "unknown";

export type PushTestCleanupReason =
	| "command_failure"
	| "timeout"
	| "response_invalid"
	| "result_nonzero"
	| "unknown";

export type PushTestFailureResponseReason =
	| "timeout"
	| "peer_eof"
	| "modem_read"
	| "tls_read"
	| "http_parse"
	| "http_incomplete"
	| "modem_command"
	| "unknown";

export type PushTestParseReason =
	| "oversize"
	| "terminal"
	| "urc"
	| "prefix"
	| "field_count"
	| "quote"
	| "cid"
	| "state"
	| "endpoint"
	| "result"
	| "read_data"
	| "unknown";

export type PushTestFailureParseReason = PushTestParseReason;
export type PushTestCleanupParseReason = PushTestParseReason;

export type PushTestCleanupMessage =
	| "HTTPS cleanup socket close failed"
	| "HTTPS cleanup SSL config restore failed"
	| "HTTPS cleanup autofree config restore failed"
	| "HTTPS cleanup encoding config restore failed"
	| "HTTPS cleanup PDP deactivate failed"
	| "HTTPS cleanup PDP profile restore failed";

export type PushTestParseShape = {
	fieldCount: number;
	quoteMask: number;
	presenceMask: number;
	responseTraceMask: number;
	rtcpRecvLength: number;
	rtcpTotalLength: number;
	stateClass: "none" | "initial" | "closed" | "connected" | "connecting" | "unknown";
	lineClass: "none" | "missing" | "unexpected" | "duplicate" | "extra";
	singleFieldClass: "none" | "zero" | "nonzero" | "non_numeric";
};

export type PushTestTransportPath = "none" | "wifi" | "cellular";

export type PushTestFailureStage =
	| "none"
	| "preflight"
	| "target"
	| "ca"
	| "modem"
	| "registration"
	| "pdp"
	| "socket"
	| "tls"
	| "request"
	| "response"
	| "http"
	| "cleanup";

export type PushTestDiagnosticFields = {
	cleanupMessage?: PushTestCleanupMessage;
	failureReason?: PushTestDiagnosticReason;
	cleanupReason?: PushTestCleanupReason;
	failureResponseReason?: PushTestFailureResponseReason;
	failureParseReason?: PushTestFailureParseReason;
	cleanupParseReason?: PushTestCleanupParseReason;
	failureParseShape?: PushTestParseShape;
	cleanupParseShape?: PushTestParseShape;
	resetNeeded?: boolean;
	transportPath?: PushTestTransportPath;
	dispatchAttempted?: boolean;
	failureStage?: PushTestFailureStage;
	httpStatus?: number;
};

type PushTestActive = {
	queued: boolean;
	running: boolean;
	done: false;
	success: false;
	message: string;
} & { [Key in keyof PushTestDiagnosticFields]?: never };

type PushTestTerminal = {
	queued: false;
	running: false;
	done: true;
	success: boolean;
	message: string;
} & PushTestDiagnosticFields;

export type PushTestStatus = PushTestActive | PushTestTerminal;

export type PushCaStatus = { configured: boolean; sha256: string };

export type OtaState = {
	activeOffset: 65536 | 2031616;
	imageState: "other" | "pending-verify" | "valid";
	pendingVerify: boolean;
	accepted: number;
	pending: number;
	pendingAddress: 0 | 65536 | 2031616;
	publicKeySha256: string;
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
		stage: "" | "validating" | "recovering_notifications" | "authenticating" | "awaiting_confirmation" | "preparing" | "downloading" | "notifying" | "completed";
		confirmationRequired: boolean;
		notificationPending: boolean;
		profileName: string;
		providerName: string;
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
