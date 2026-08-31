<script lang="ts">
	import { onMount, tick } from "svelte";
	import MoonIcon from "@lucide/svelte/icons/moon";
	import MenuIcon from "@lucide/svelte/icons/menu";
	import SunIcon from "@lucide/svelte/icons/sun";
	import ActionResult from "$lib/components/ActionResult.svelte";
	import CellularCaResult from "$lib/components/CellularCaResult.svelte";
	import * as Accordion from "$lib/components/ui/accordion";
	import * as Alert from "$lib/components/ui/alert";
	import { Badge } from "$lib/components/ui/badge";
	import { Button, buttonVariants } from "$lib/components/ui/button";
	import * as Card from "$lib/components/ui/card";
	import { Dialog } from "bits-ui";
	import * as Empty from "$lib/components/ui/empty";
	import * as Field from "$lib/components/ui/field";
	import { Input } from "$lib/components/ui/input";
	import * as InputGroup from "$lib/components/ui/input-group";
	import * as NativeSelect from "$lib/components/ui/native-select";
	import { Separator } from "$lib/components/ui/separator";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { Spinner } from "$lib/components/ui/spinner";
	import { Switch } from "$lib/components/ui/switch";
	import * as Tabs from "$lib/components/ui/tabs";
	import { Textarea } from "$lib/components/ui/textarea";
	import { demoMode, exportEncryptedConfig, loadEsim, loadLogs, loadPushCaStatus, loadSnapshot, postEsimAction, postForm, provisionPushCa, runAction, runPushTest, uploadOta, uploadRestore, waitForAccepted } from "$lib/api";
	import { BACKUP_ENVELOPE, CONFIG_FIELD_LIMITS, CONFIG_VALUE_LIMITS } from "$lib/config-schema.generated";
	import { detectLocale, translate, type TranslationKey } from "$lib/i18n";
	import { DEVICE_SUBPAGES, parseDeviceHash } from "$lib/device-navigation.js";
	import { pushProviderKeyFields, pushSecretRequired, switchProviderDraft } from "$lib/push-template-defaults.js";
	import { closeEsimDeleteDialog, refreshEsimAfterTerminal } from "$lib/esim-ui.js";
	import type { DeviceSnapshot, EsimProfile, EsimStatus, Locale, PushCaStatus, PushChannel, PushTestStatus, UiResult } from "$lib/types";

	type MainTab = "overview" | "notifications" | "messaging" | "cellular" | "device" | "security";
	type DeviceSubpage = "connection" | "diagnostics" | "maintenance" | "advanced";
	type Theme = "light" | "dark";
	type PushProviderDraft = Pick<PushChannel, "url" | "urlSet" | "key1" | "key1Set" | "key2" | "key2Set" | "customBody" | "customBodySet" | "titleTemplate" | "bodyTemplate">;

	const idle = (): UiResult => ({ state: "idle", code: "", data: {}, detail: "" });
	const idlePushTest = (): PushTestStatus => ({ queued: false, running: false, done: false, success: false, message: "" });
	const encoder = new TextEncoder();
	const byteLimits: Record<string, number> = {
		...CONFIG_FIELD_LIMITS, forwardRules: 2048, smtpPort: 32, phone: 32, content: 2048, cmd: 256
	};
	const providers = [
		"POST JSON",
		"Bark",
		"GET",
		"DingTalk",
		"PushPlus",
		"ServerChan",
		"Custom JSON",
		"Feishu",
		"Gotify",
		"Telegram",
		"Discord Webhook",
		"ntfy"
	];
	const navigationGroups: { label: TranslationKey; items: { value: MainTab; label: TranslationKey }[] }[] = [
		{ label: "navGroupWorkspace", items: [
			{ value: "overview", label: "navOverview" },
			{ value: "messaging", label: "navMessaging" },
			{ value: "notifications", label: "navNotifications" }
		] },
		{ label: "navGroupConnectivity", items: [{ value: "cellular", label: "navCellular" }] },
		{ label: "navGroupDevice", items: [
			{ value: "device", label: "navDeviceAccess" },
			{ value: "security", label: "navSecurity" }
		] }
	];
	const deviceSubpages = DEVICE_SUBPAGES as Array<{ value: DeviceSubpage; label: TranslationKey; description: TranslationKey }>;

	let locale = $state<Locale>("zh-TW");
	let mainTab = $state<MainTab>("overview");
	let deviceSubpage = $state<DeviceSubpage>("connection");
	let mobileNavDialog: HTMLDialogElement;
	let pushTab = $state("0");
	let wifiTab = $state("0");
	let theme = $state<Theme>("light");
	let snapshot = $state<DeviceSnapshot | null>(null);
	let loading = $state(true);
	let loadError = $state("");
	let pushProviderTypes = $state<number[]>(Array.from({ length: 5 }, () => 1));
	let pushProviderDrafts = $state<Array<Record<number, PushProviderDraft>>>(Array.from({ length: 5 }, () => ({})));
	let emailResult = $state(idle());
	let heartbeatResult = $state(idle());
	let keepaliveResult = $state(idle());
	let pushResult = $state(idle());
	let pushTestResults = $state(Array.from({ length: 5 }, idlePushTest));
	let pushTestBusy = $state(Array.from({ length: 5 }, () => false));
	let pushCaResults = $state(Array.from({ length: 5 }, idle));
	let pushCellularSaveResults = $state(Array.from({ length: 5 }, idle));
	let pushCaStatuses = $state<Array<PushCaStatus | null>>(Array.from({ length: 5 }, () => null));
	let cellularUrlClears = $state(Array.from({ length: 5 }, () => false));
	let wifiResult = $state(idle());
	let networkModeResult = $state(idle());
	let routingResult = $state(idle());
	let forwardRulesResult = $state(idle());
	let forwardRulesDialogOpen = $state(false);
	let securityResult = $state(idle());
	let smsResult = $state(idle());
	let overviewResult = $state(idle());
	let diagnosticsResult = $state(idle());
	let networkResult = $state(idle());
	let controlResult = $state(idle());
	let terminalResult = $state(idle());
	let logsResult = $state(idle());
	let identityResult = $state(idle());
	let notificationLocaleResult = $state(idle());
	let emailSwitchResult = $state(idle());
	let pushSwitchResult = $state(idle());
	let emailEnabledDraft = $state(false);
	let pushEnabledDraft = $state(false);
	let notificationSwitchSaving = $derived(emailSwitchResult.state === "loading" || pushSwitchResult.state === "loading");
	let esim = $state<EsimStatus | null>(null);
	let esimLoading = $state(false);
	let esimError = $state("");
	let esimResult = $state(idle());
	let esimPollTimer: number | undefined;
	let esimPollBusy = false;
	let deleteHandle = $state("");
	let deleteOriginId = $state("");
	let deleteDialog: HTMLDialogElement;
	let configFileResult = $state(idle());
	let otaResult = $state(idle());
	let phone = $state("");
	let message = $state("");
	let command = $state("");
	let logs = $state<string[]>([]);
	let logCursor = $state<number | null>(null);
	let hasMoreLogs = $state(false);
	let autoRefresh = $state(false);
	let backupPassphrase = $state("");
	let backupConfirmation = $state("");
	let restorePassphrase = $state("");
	let restoreFile = $state<File | null>(null);
	let otaFile = $state<File | null>(null);
	let originalWifiSsids = $state(Array.from({ length: 5 }, () => ""));
	let originalWifiOpen = $state(Array.from({ length: 5 }, () => false));
	let openWifiProfiles = $state(Array.from({ length: 5 }, () => false));
	let currentDeviceSubpage = $derived(deviceSubpages.find((page) => page.value === deviceSubpage) ?? deviceSubpages[0]!);
	let activeDeviceRoute = "";
	let routeScrollGeneration = 0;

	const t = (key: TranslationKey) => translate(locale, key);

	onMount(() => {
		const scrollToDeviceSubpage = async (route: ReturnType<typeof parseDeviceHash>) => {
			if (route.mainTab !== "device") {
				routeScrollGeneration += 1;
				return;
			}
			const generation = ++routeScrollGeneration;
			await tick();
			if (generation !== routeScrollGeneration) return;
			document.getElementById(route.canonicalHash.slice(1))?.scrollIntoView({ block: "start", inline: "nearest", behavior: "auto" });
		};
		const applyHash = () => {
			const route = parseDeviceHash(location.hash);
			const nextDeviceRoute = route.mainTab === "device" ? `device/${route.deviceSubpage}` : route.mainTab;
			if (activeDeviceRoute === "device/maintenance" && nextDeviceRoute !== activeDeviceRoute) {
				restoreFile = null;
				otaFile = null;
			}
			activeDeviceRoute = nextDeviceRoute;
			mainTab = route.mainTab as MainTab;
			deviceSubpage = route.deviceSubpage as DeviceSubpage;
			if (location.hash !== route.canonicalHash) history.replaceState(null, "", route.canonicalHash);
			void scrollToDeviceSubpage(route);
		};
		applyHash();
		window.addEventListener("hashchange", applyHash);
		window.addEventListener("popstate", applyHash);
		const saved = localStorage.getItem("locale") as Locale | null;
		locale = saved && ["zh-TW", "zh-CN", "en"].includes(saved) ? saved : detectLocale(navigator.language);
		const savedTheme = localStorage.getItem("theme") as Theme | null;
		theme = savedTheme && ["light", "dark"].includes(savedTheme)
			? savedTheme
			: matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
		document.documentElement.classList.toggle("dark", theme === "dark");
		void refreshSnapshot().then(() => void scrollToDeviceSubpage(parseDeviceHash(location.hash)));
		void refreshEsim();
		return () => {
			window.removeEventListener("hashchange", applyHash);
			window.removeEventListener("popstate", applyHash);
			if (esimPollTimer !== undefined) window.clearInterval(esimPollTimer);
		};
	});

	$effect(() => {
		if (typeof document === "undefined") return;
		document.documentElement.lang = locale;
		localStorage.setItem("locale", locale);
	});

	$effect(() => {
		if (!autoRefresh || mainTab !== "device" || deviceSubpage !== "diagnostics") return;
		const timer = window.setInterval(refreshLogs, 2000);
		return () => window.clearInterval(timer);
	});

	async function refreshSnapshot() {
		loading = true;
		loadError = "";
		try {
			snapshot = await loadSnapshot();
			pushProviderTypes = snapshot.config.pushChannels.map((channel) => channel.type);
			pushProviderDrafts = snapshot.config.pushChannels.map(() => ({}));
			pushCaStatuses = await Promise.all(snapshot.config.pushChannels.map((_channel, index) => loadPushCaStatus(index).catch(() => null)));
			cellularUrlClears = Array.from({ length: 5 }, () => false);
			emailEnabledDraft = snapshot.config.emailEnabled;
			pushEnabledDraft = snapshot.config.pushEnabled;
			originalWifiSsids = snapshot.config.wifiProfiles.map((profile) => profile.ssid);
			originalWifiOpen = snapshot.config.wifiProfiles.map((profile) => profile.open);
			openWifiProfiles = snapshot.config.wifiProfiles.map((profile) => profile.open);
		} catch (error) {
			loadError = error instanceof Error ? error.message : String(error);
		} finally {
			loading = false;
		}
	}

	function openMobileNavigation() {
		mobileNavDialog?.showModal();
	}

	function closeMobileNavigation() {
		if (mobileNavDialog?.open) mobileNavDialog.close();
	}

	async function refreshEsim() {
		esimLoading = true;
		esimError = "";
		try {
			esim = await loadEsim();
			if (esim.job.state === "queued" || esim.job.state === "running") startEsimPoll(esim.job.id);
		} catch (error) {
			esimError = error instanceof Error ? error.message : String(error);
		} finally {
			esimLoading = false;
		}
	}

	function stopEsimPoll() {
		if (esimPollTimer !== undefined) {
			window.clearInterval(esimPollTimer);
			esimPollTimer = undefined;
		}
	}

	function startEsimPoll(jobId: number) {
		stopEsimPoll();
		const deadline = Date.now() + 90000;
		const poll = async () => {
			if (esimPollBusy) return;
			esimPollBusy = true;
			try {
				const status = await loadEsim();
				if (status.job.id >= jobId && (status.job.state === "succeeded" || status.job.state === "failed")) {
					stopEsimPoll();
					const freshStatus = await refreshEsimAfterTerminal(loadEsim, status);
					esim = freshStatus;
					esimResult = { state: freshStatus.job.success ? "success" : "error", code: freshStatus.job.code, data: {}, detail: "" };
				} else if (Date.now() >= deadline) {
					esim = status;
					stopEsimPoll();
					esimResult = { state: "error", code: "ACTION_REQUEST_FAILED", data: {}, detail: "" };
				} else {
					esim = status;
				}
			} catch {
				stopEsimPoll();
				esimResult = { state: "error", code: "ACTION_REQUEST_FAILED", data: {}, detail: "" };
			} finally {
				esimPollBusy = false;
			}
		};
		void poll();
		esimPollTimer = window.setInterval(() => void poll(), 750);
	}

	async function runEsimAction(actionName: string, profile?: EsimProfile, nickname?: string) {
		esimResult = { state: "loading", code: "commonRunning", data: {}, detail: "" };
		try {
			const result = await postEsimAction(actionName, profile?.handle, nickname);
			if (!result.success || result.code !== "ACTION_JOB_ACCEPTED") {
				esimResult = { state: "error", code: result.code, data: {}, detail: "" };
				if (result.code === "ACTION_ESIM_HANDLE_STALE") await refreshEsim();
				return;
			}
			const jobId = Number(result.data.jobId);
			if (!Number.isInteger(jobId)) throw new Error("Invalid eSIM job.");
			startEsimPoll(jobId);
		} catch {
			esimResult = { state: "error", code: "ACTION_REQUEST_FAILED", data: {}, detail: "" };
		}
	}

	function askDelete(handle: string, originId: string) {
		deleteHandle = handle;
		deleteOriginId = originId;
		deleteDialog?.showModal();
	}

	function clearDeleteDialog() {
		const next = closeEsimDeleteDialog({ handle: deleteHandle, originId: deleteOriginId });
		deleteHandle = next.handle;
		deleteOriginId = next.originId;
		if (next.focusId) document.getElementById(next.focusId)?.focus();
	}

	function closeDeleteDialog() {
		if (deleteDialog?.open) deleteDialog.close();
		else clearDeleteDialog();
	}

	function cancelDelete() {
		closeDeleteDialog();
	}

	function confirmDelete() {
		const handle = deleteHandle;
		cancelDelete();
		const profile = esim?.profiles.find((candidate) => candidate.handle === handle);
		if (profile) void runEsimAction("delete", profile);
	}

	async function save(setResult: (value: UiResult) => void, values: Record<string, string | number | boolean>) {
		const invalid = tooLong(values);
		if (invalid) {
			setResult({ state: "error", code: "ACTION_INPUT_TOO_LONG", data: {}, detail: invalid });
			return;
		}
		setResult({ state: "loading", code: "commonSaving", data: {}, detail: "" });
		try {
			const response = await waitForAccepted(await postForm("/save", values));
			setResult({ state: response.success ? "success" : "error", code: response.code, data: response.data, detail: response.detail });
			if (response.success) {
				const cellularField = Object.keys(values).find((field) => /^push[0-4]cellularEnabled$/.test(field));
				const cellularIndex = cellularField ? Number(cellularField[4]) : -1;
				await refreshSnapshot();
				if (cellularIndex >= 0 && snapshot?.config.pushChannels[cellularIndex]?.cellularEnabled) await provisionCa(cellularIndex);
			}
		} catch (error) {
			setResult({ state: "error", code: "ACTION_REQUEST_FAILED", data: {}, detail: error instanceof Error ? error.message : String(error) });
		}
	}

	async function action(setResult: (value: UiResult) => void, path: string, confirmText?: string, init?: RequestInit) {
		if (confirmText && !window.confirm(confirmText)) return;
		setResult({ state: "loading", code: "commonRunning", data: {}, detail: "" });
		try {
			const response = await waitForAccepted(await runAction(path, init));
			setResult({ state: response.success ? "success" : "error", code: response.code, data: response.data, detail: response.detail });
		} catch (error) {
			setResult({ state: "error", code: "ACTION_REQUEST_FAILED", data: {}, detail: error instanceof Error ? error.message : String(error) });
		}
	}

	async function testPush(index: number) {
		pushTestBusy[index] = true;
		try {
			pushTestResults[index] = await runPushTest(index, (status) => pushTestResults[index] = status);
		} catch (error) {
			pushTestResults[index] = {
				queued: false,
				running: false,
				done: true,
				success: false,
				message: error instanceof Error ? error.message : String(error)
			};
		} finally {
			pushTestBusy[index] = false;
		}
	}

	async function provisionCa(index: number) {
		pushCaResults[index] = { state: "loading", code: "commonRunning", data: {}, detail: "" };
		try {
			const response = await provisionPushCa(index);
			pushCaStatuses[index] = await loadPushCaStatus(index);
			pushCaResults[index] = { state: response.success && pushCaStatuses[index]?.configured ? "success" : "error", code: response.code, data: response.data, detail: response.detail };
		} catch (error) {
			pushCaStatuses[index] = { configured: false, sha256: "" };
			pushCaResults[index] = { state: "error", code: "ACTION_REQUEST_FAILED", data: {}, detail: error instanceof Error ? error.message : String(error) };
		}
	}

	function saveCellular(index: number) {
		pushTab = String(index);
		void save((value) => pushCellularSaveResults[index] = value, pushValues());
	}

	async function sendSms() {
		const invalid = tooLong({ phone, content: message });
		if (invalid) {
			smsResult = { state: "error", code: "ACTION_INPUT_TOO_LONG", data: {}, detail: invalid };
			return;
		}
		smsResult = { state: "loading", code: "sending", data: {}, detail: "" };
		try {
			const response = await waitForAccepted(await postForm("/sendsms", { phone, content: message }));
			smsResult = { state: response.success ? "success" : "error", code: response.code, data: response.data, detail: response.detail };
			if (response.success) message = "";
		} catch (error) {
			smsResult = { state: "error", code: "ACTION_REQUEST_FAILED", data: {}, detail: error instanceof Error ? error.message : String(error) };
		}
	}

	async function refreshLogs() {
		try {
			const page = await loadLogs();
			logs = page.entries.map((entry) => entry.message);
			logCursor = page.nextCursor;
			hasMoreLogs = page.hasMore;
			logsResult = idle();
		} catch (error) {
			logsResult = { state: "error", code: "ACTION_LOGS_FAILED", data: {}, detail: error instanceof Error ? error.message : String(error) };
		}
	}

	async function loadMoreLogs() {
		if (logCursor === null) return;
		try {
			const page = await loadLogs(logCursor);
			logs = [...page.entries.map((entry) => entry.message), ...logs];
			logCursor = page.nextCursor;
			hasMoreLogs = page.hasMore;
			logsResult = idle();
		} catch (error) {
			logsResult = { state: "error", code: "ACTION_LOGS_FAILED", data: {}, detail: error instanceof Error ? error.message : String(error) };
		}
	}

	function download(bytes: Uint8Array, filename: string) {
		const url = URL.createObjectURL(new Blob([bytes.buffer as ArrayBuffer]));
		const anchor = document.createElement("a");
		anchor.href = url;
		anchor.download = filename;
		anchor.click();
		URL.revokeObjectURL(url);
	}

	async function backupConfig() {
		if (backupPassphrase.length < 12 || backupPassphrase !== backupConfirmation) {
			configFileResult = { state: "error", code: "ACTION_PASSPHRASE_INVALID", data: {}, detail: "" };
			return;
		}
		configFileResult = { state: "loading", code: "commonRunning", data: {}, detail: "" };
		try {
			download(await exportEncryptedConfig(backupPassphrase), `${snapshot!.config.hostname}.smscfg`);
			configFileResult = { state: "success", code: "ACTION_CONFIG_EXPORT_READY", data: {}, detail: "" };
		} catch (error) {
			configFileResult = { state: "error", code: "ACTION_REQUEST_FAILED", data: {}, detail: error instanceof Error ? error.message : String(error) };
		}
	}

	async function restoreConfig() {
		if (!restoreFile || restorePassphrase.length < 12) {
			configFileResult = { state: "error", code: "ACTION_PASSPHRASE_INVALID", data: {}, detail: "" };
			return;
		}
		configFileResult = { state: "loading", code: "commonRunning", data: {}, detail: "" };
		try {
			const result = await waitForAccepted(await uploadRestore(new Uint8Array(await restoreFile.arrayBuffer()), restorePassphrase));
			configFileResult = { state: result.success ? "success" : "error", code: result.code, data: result.data, detail: result.detail };
			if (result.success) await refreshSnapshot();
		} catch (error) {
			configFileResult = { state: "error", code: "ACTION_REQUEST_FAILED", data: {}, detail: error instanceof Error ? error.message : String(error) };
		}
	}

	async function installOta() {
		if (!otaFile) return;
		otaResult = { state: "loading", code: "commonRunning", data: {}, detail: "" };
		try {
			const result = await waitForAccepted(await uploadOta(new Uint8Array(await otaFile.arrayBuffer())));
			otaResult = { state: result.success ? "success" : "error", code: result.code, data: result.data, detail: result.detail };
		} catch (error) {
			otaResult = { state: "error", code: "ACTION_REQUEST_FAILED", data: {}, detail: error instanceof Error ? error.message : String(error) };
		}
	}

	function formatUptime(seconds: number) {
		const days = Math.floor(seconds / 86400);
		const time = new Date(seconds * 1000).toISOString().slice(11, 19);
		return days > 0 ? `${days}d ${time}` : time;
	}

	function providerHint(type: number) {
		return t(`providerHint${type}` as TranslationKey);
	}

	function keyLabel(type: number, field: "key1" | "key2") {
		if (field === "key2") return type === 5 ? t("keyChannel") : t("keyBotToken");
		if (type === 4 || type === 8) return t("keySecret");
		if (type === 5 || type === 9) return t("keyToken");
		if (type === 6) return t("keySendKey");
		return t("keyChatId");
	}

	function endpointLabel(type: number) {
		return t(`providerEndpoint${type}` as TranslationKey);
	}

	function changeProvider(channel: PushChannel, index: number) {
		const previousType = pushProviderTypes[index] ?? channel.type;
		switchProviderDraft(
			channel,
			pushProviderDrafts[index],
			previousType,
			channel.type,
			t("defaultTitleTemplate"),
			t("defaultBodyTemplate")
		);
		pushProviderTypes[index] = channel.type;
	}

	function savedSecretHint(value: string, isSet: boolean) {
		return !value && isSet ? t("sensitiveValueSavedHint") : "";
	}

	function pushValues() {
		const values: Record<string, string | number | boolean> = {};
		const index = Number(pushTab);
		const channel = snapshot?.config.pushChannels[index];
		if (!channel) return values;
		values[`push${index}en`] = channel.enabled;
		values[`push${index}cellularEnabled`] = channel.cellularEnabled ? 1 : 0;
		if (channel.cellularUrl) values[`push${index}cellularUrl`] = channel.cellularUrl;
		else if (cellularUrlClears[index]) values[`push${index}cellularUrlClear`] = 1;
		values[`push${index}type`] = channel.type;
		values[`push${index}name`] = channel.name;
		if (channel.url) values[`push${index}url`] = channel.url;
		if (channel.key1) values[`push${index}key1`] = channel.key1;
		if (channel.key2) values[`push${index}key2`] = channel.key2;
		if (channel.type === 7 && channel.customBody) values[`push${index}body`] = channel.customBody;
		values[`push${index}title`] = channel.type === 7 ? "" : channel.titleTemplate;
		values[`push${index}template`] = channel.type === 7 ? "" : channel.bodyTemplate;
		return values;
	}

	function wifiValues(index: number) {
		const profile = snapshot?.config.wifiProfiles[index];
		if (!profile) return {};
		return {
			[`wifi${index}ssid`]: profile.ssid,
			...(profile.password ? { [`wifi${index}pass`]: profile.password } : {}),
			...(openWifiProfiles[index] ? { [`wifi${index}open`]: true } : {})
		};
	}

	function wifiPasswordRequired(index: number) {
		const profile = snapshot?.config.wifiProfiles[index];
		return Boolean(profile?.ssid && (profile.ssid !== originalWifiSsids[index] || originalWifiOpen[index]) && !openWifiProfiles[index]);
	}

	function fieldLimit(field: string) {
		if (/^account\d+user$/.test(field)) return 64;
		if (/^account\d+pass$/.test(field)) return 96;
		if (/^wifi\d+ssid$/.test(field)) return CONFIG_FIELD_LIMITS.wifiSsid;
		if (/^wifi\d+pass$/.test(field)) return CONFIG_FIELD_LIMITS.wifiPassword;
		if (/^wifi\d+open$/.test(field)) return 32;
		if (/^push\d+name$/.test(field)) return 64;
		if (/^push\d+(en|type)$/.test(field)) return 32;
		if (/^push\d+cellular(Enabled|UrlClear)$/.test(field)) return 32;
		if (/^push\d+cellularUrl$/.test(field)) return 512;
		if (/^push\d+url$/.test(field)) return 512;
		if (/^push\d+key[12]$/.test(field)) return 256;
		if (/^push\d+body$/.test(field)) return CONFIG_FIELD_LIMITS.pushCustomBody;
		if (/^push\d+title$/.test(field)) return CONFIG_FIELD_LIMITS.pushTitleTemplate;
		if (/^push\d+template$/.test(field)) return CONFIG_FIELD_LIMITS.pushBodyTemplate;
		return byteLimits[field];
	}

	function tooLong(values: Record<string, string | number | boolean>) {
		for (const [field, value] of Object.entries(values)) {
			const limit = fieldLimit(field);
			if (limit !== undefined && encoder.encode(String(value)).length > limit) return field;
		}
		return "";
	}

	function sendAtCommand() {
		if (tooLong({ cmd: command })) {
			terminalResult = { state: "error", code: "ACTION_INPUT_TOO_LONG", data: {}, detail: "cmd" };
			return;
		}
		void action((value) => terminalResult = value, `/at?cmd=${encodeURIComponent(command)}`);
	}

	function accountValues() {
		const values: Record<string, string> = {};
		snapshot?.config.webAccounts.forEach((account, index) => {
			values[`account${index}user`] = account.username;
			if (account.password) values[`account${index}pass`] = account.password;
		});
		return values;
	}

	function toggleTheme() {
		theme = theme === "dark" ? "light" : "dark";
		document.documentElement.classList.toggle("dark", theme === "dark");
		localStorage.setItem("theme", theme);
	}
</script>

<svelte:head>
	<title>{snapshot?.config.deviceName || t("appName")}</title>
	<meta name="description" content={t("appSubtitle")} />
</svelte:head>

<a class="skip-link" href="#main-content">{t("skipToContent")}</a>
	<header class="app-header sticky top-0 z-20 border-b bg-background/95 supports-[backdrop-filter]:bg-background/80 backdrop-blur">
	<div class="app-header-inner mx-auto flex h-20 max-w-6xl items-center justify-between gap-4 px-4 sm:px-6">
		<div class="app-header-title min-w-0">
			<p class="truncate text-lg font-semibold tracking-tight sm:text-2xl">{snapshot?.config.deviceName || t("appName")}</p>
			<p class="truncate text-sm text-muted-foreground">{t("appSubtitle")}</p>
		</div>
		<div class="app-header-controls flex items-center gap-2">
			<Button id="mobile-nav-trigger" class="lg:hidden" variant="outline" size="icon-sm" aria-label={t("navMenu")} aria-haspopup="dialog" onclick={openMobileNavigation}>
				<MenuIcon />
			</Button>
			{#if demoMode}<Badge variant="secondary">{t("demoBadge")}</Badge>{/if}
			<Button variant="outline" size="icon-sm" aria-label={theme === "dark" ? t("dayMode") : t("darkMode")} onclick={toggleTheme}>
				{#if theme === "dark"}<SunIcon />{:else}<MoonIcon />{/if}
			</Button>
			{#if snapshot}
				<Badge variant={snapshot.status.modemReady ? "default" : "secondary"}>
					{snapshot.status.modemReady ? t("commonReady") : t("commonUnavailable")}
				</Badge>
			{/if}
			<label class="sr-only" for="locale">{t("localeLabel")}</label>
			<NativeSelect.Root id="locale" size="sm" bind:value={locale} aria-label={t("localeLabel")}>
				<NativeSelect.Option value="zh-TW">{t("localeZhTw")}</NativeSelect.Option>
				<NativeSelect.Option value="zh-CN">{t("localeZhCn")}</NativeSelect.Option>
				<NativeSelect.Option value="en">{t("localeEn")}</NativeSelect.Option>
			</NativeSelect.Root>
		</div>
	</div>
</header>

<dialog bind:this={mobileNavDialog} class="mobile-nav-dialog lg:hidden" aria-labelledby="mobile-nav-title" onclick={(event) => { if (event.target === mobileNavDialog) closeMobileNavigation(); }} onclose={() => document.getElementById("mobile-nav-trigger")?.focus()}>
	<div class="flex items-center justify-between gap-4 border-b pb-4">
		<h2 id="mobile-nav-title" class="text-lg font-semibold">{t("navMenuTitle")}</h2>
		<Button variant="ghost" size="sm" onclick={closeMobileNavigation}>{t("commonClose")}</Button>
	</div>
	<nav class="flex flex-col gap-5 pt-5" aria-label={t("navMenuTitle")}>
		{#each navigationGroups as group (group.label)}
			<div class="flex flex-col gap-1">
				<p class="sidebar-group-label">{t(group.label)}</p>
				{#each group.items as item (item.value)}
					<a class="sidebar-link" href={`#${item.value === "device" ? "device/connection" : item.value}`} data-active={mainTab === item.value ? "true" : undefined} aria-current={mainTab === item.value ? "page" : undefined} onclick={closeMobileNavigation}>{t(item.label)}</a>
					{#if item.value === "device" && mainTab === "device"}
						<nav class="device-subnav" aria-label={t("deviceSubpageMenu")}>
							{#each deviceSubpages as subpage (subpage.value)}
								<a class="device-subnav-link" href={`#device/${subpage.value}`} data-active={deviceSubpage === subpage.value ? "true" : undefined} aria-current={deviceSubpage === subpage.value ? "page" : undefined} onclick={closeMobileNavigation}>{t(subpage.label)}</a>
							{/each}
						</nav>
					{/if}
				{/each}
			</div>
		{/each}
	</nav>
</dialog>

<main id="main-content" tabindex="-1" class="mx-auto max-w-6xl px-4 py-6 outline-none sm:px-6 sm:py-10">
	{#if loading}
		<div class="flex flex-col gap-6" aria-live="polite">
			<div class="flex flex-col gap-2">
				<Skeleton class="h-7 w-52" />
				<Skeleton class="h-4 w-80 max-w-full" />
			</div>
			<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
				{#each Array(4) as _, index (index)}<Skeleton class="h-28" />{/each}
			</div>
			<div><p class="text-sm font-medium">{t("loadingTitle")}</p><p class="text-sm text-muted-foreground">{t("loadingBody")}</p></div>
		</div>
	{:else if loadError || !snapshot}
		<Alert.Root variant="destructive">
			<Alert.Title>{t("loadErrorTitle")}</Alert.Title>
			<Alert.Description class="flex flex-col items-start gap-3">
				<span>{loadError}</span>
				<Button variant="outline" onclick={refreshSnapshot}>{t("retry")}</Button>
			</Alert.Description>
		</Alert.Root>
	{:else}
		<div class="app-layout">
			<aside class="desktop-sidebar hidden lg:block" aria-label={t("navMenuTitle")}>
				<nav class="flex flex-col gap-5">
		{#each navigationGroups as group (group.label)}
						<div class="flex flex-col gap-1">
							<p class="sidebar-group-label">{t(group.label)}</p>
							{#each group.items as item (item.value)}
								<a class="sidebar-link" href={`#${item.value === "device" ? "device/connection" : item.value}`} data-active={mainTab === item.value ? "true" : undefined} aria-current={mainTab === item.value ? "page" : undefined} onclick={closeMobileNavigation}>{t(item.label)}</a>
								{#if item.value === "device" && mainTab === "device"}
									<nav class="device-subnav" aria-label={t("deviceSubpageMenu")}>
										{#each deviceSubpages as subpage (subpage.value)}
											<a class="device-subnav-link" href={`#device/${subpage.value}`} data-active={deviceSubpage === subpage.value ? "true" : undefined} aria-current={deviceSubpage === subpage.value ? "page" : undefined} onclick={closeMobileNavigation}>{t(subpage.label)}</a>
										{/each}
									</nav>
								{/if}
							{/each}
						</div>
					{/each}
				</nav>
			</aside>
			<div class="min-w-0 flex flex-col gap-8">

			{#if mainTab === "overview"}
					<section class="flex flex-col gap-6">
						<div><h1 class="text-2xl font-semibold tracking-tight">{t("overviewTitle")}</h1><p class="mt-1 text-sm text-muted-foreground">{t("overviewDescription")}</p></div>
						{#if snapshot.status.apMode}<Alert.Root><Alert.Title>{t("apModeTitle")}</Alert.Title><Alert.Description>{t("apModeDescription")} <strong>http://192.168.1.1</strong></Alert.Description></Alert.Root>{/if}
					<dl data-overview-group="identity" class="grid gap-6 md:grid-cols-2">
						{#each [
							["deviceName", t("deviceName"), snapshot.config.deviceName],
							["hostname", t("hostname"), snapshot.config.hostname]
						] as item (item[0])}
							<div class="min-w-0 border-l-2 pl-4">
								<dt class="text-sm text-muted-foreground">{item[1]}</dt>
								<dd class="mt-1 truncate text-lg font-semibold tabular-nums" title={item[2]}>{item[2]}</dd>
							</div>
						{/each}
					</dl>
					<dl data-overview-group="details" class="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
						{#each [
							["ip", t("overviewIp"), snapshot.status.ip],
							["wifi", t("overviewWifi"), snapshot.status.wifiSsid || t("commonUnknown")],
							["heap", t("overviewHeap"), `${snapshot.status.freeHeapKb} KB`],
							["uptime", t("overviewUptime"), formatUptime(snapshot.status.uptimeSeconds)]
						] as item (item[0])}
							<div class="min-w-0 border-l-2 pl-4">
								<dt class="text-sm text-muted-foreground">{item[1]}</dt>
								<dd class="mt-1 truncate text-lg font-semibold tabular-nums" title={item[2]}>{item[2]}</dd>
							</div>
						{/each}
					</dl>
					<Separator />
					<div class="flex flex-col gap-3 sm:grid sm:grid-cols-[1fr_auto_1fr_auto_1fr] sm:items-stretch">
						<dl class="flex items-center justify-between gap-3"><dt class="text-sm text-muted-foreground">{t("overviewModem")}</dt><dd><Badge variant={snapshot.status.modemReady ? "default" : "outline"}>{snapshot.status.modemReady ? t("commonReady") : t("commonUnavailable")}</Badge></dd></dl>
						<Separator class="sm:hidden" /><Separator orientation="vertical" class="hidden h-auto sm:block" />
						<dl class="flex items-center justify-between gap-3"><dt class="text-sm text-muted-foreground">{t("overviewEmail")}</dt><dd><Badge variant={snapshot.status.emailConfigured ? "default" : "outline"}>{snapshot.status.emailConfigured ? t("commonConfigured") : t("commonNotConfigured")}</Badge></dd></dl>
						<Separator class="sm:hidden" /><Separator orientation="vertical" class="hidden h-auto sm:block" />
						<dl class="flex items-center justify-between gap-3"><dt class="text-sm text-muted-foreground">{t("overviewPush")}</dt><dd><Badge variant={snapshot.status.enabledPushChannels > 0 ? "default" : "outline"}>{snapshot.status.enabledPushChannels} / 5</Badge></dd></dl>
					</div>
					<Separator />
					<section class="flex flex-col gap-3"><div><h2 class="font-semibold">{t("overviewQuick")}</h2><p class="text-sm text-muted-foreground">{t("overviewQuickDescription")}</p></div><div class="flex flex-wrap gap-2"><Button variant="outline" onclick={() => action((value) => overviewResult = value, "/query?type=wifi")}>{t("overviewQueryWifi")}</Button><Button variant="outline" onclick={() => action((value) => overviewResult = value, "/query?type=signal")}>{t("overviewQuerySignal")}</Button><Button variant="outline" onclick={() => action((value) => overviewResult = value, "/query?type=network")}>{t("overviewQueryNetwork")}</Button></div><ActionResult result={overviewResult} title={t("resultTitle")} {locale} /></section>
				</section>
				{:else if mainTab === "notifications"}
					<section class="flex flex-col gap-6">
					<div><h1 class="text-2xl font-semibold tracking-tight">{t("notificationTitle")}</h1><p class="mt-1 text-sm text-muted-foreground">{t("notificationDescription")}</p></div>
					<div class="grid gap-4 md:grid-cols-2">
						<Card.Root>
							<Card.Header><Card.Title>{t("emailTitle")}</Card.Title><Card.Description>{t("emailDescription")}</Card.Description></Card.Header>
							<Card.Content class="flex flex-col gap-4"><form id="email-global-form" onsubmit={(event) => { event.preventDefault(); if (notificationSwitchSaving) return; void save((value) => emailSwitchResult = value, { emailEnabled: emailEnabledDraft ? "1" : "0" }); }}><Field.Field orientation="horizontal"><Field.Label for="email-global-enabled">{t("emailGlobalEnabled")}</Field.Label><Switch id="email-global-enabled" bind:checked={emailEnabledDraft} /></Field.Field></form><ActionResult result={emailSwitchResult} title={t("resultTitle")} {locale} /></Card.Content>
							<Card.Footer class="justify-end"><Button type="submit" form="email-global-form" disabled={notificationSwitchSaving}>{emailSwitchResult.state === "loading" ? t("commonSaving") : t("commonSave")}</Button></Card.Footer>
						</Card.Root>
						<Card.Root>
							<Card.Header><Card.Title>{t("pushTitle")}</Card.Title><Card.Description>{t("pushDescription")}</Card.Description></Card.Header>
							<Card.Content class="flex flex-col gap-4"><form id="push-global-form" onsubmit={(event) => { event.preventDefault(); if (notificationSwitchSaving) return; void save((value) => pushSwitchResult = value, { pushEnabled: pushEnabledDraft ? "1" : "0" }); }}><Field.Field orientation="horizontal"><Field.Label for="push-global-enabled">{t("pushGlobalEnabled")}</Field.Label><Switch id="push-global-enabled" bind:checked={pushEnabledDraft} /></Field.Field></form><ActionResult result={pushSwitchResult} title={t("resultTitle")} {locale} /></Card.Content>
							<Card.Footer class="justify-end"><Button type="submit" form="push-global-form" disabled={notificationSwitchSaving}>{pushSwitchResult.state === "loading" ? t("commonSaving") : t("commonSave")}</Button></Card.Footer>
						</Card.Root>
					</div>
					<Accordion.Root type="single" value="notification-locale">
						<Accordion.Item value="notification-locale">
							<Accordion.Trigger><span class="flex items-center gap-2"><span>{t("notificationLocale")}</span><Badge variant="outline">{snapshot.config.notificationLocale}</Badge></span></Accordion.Trigger>
							<Accordion.Content class="flex flex-col gap-4">
								<form id="notification-locale-form" onsubmit={(event) => { event.preventDefault(); void save((value) => notificationLocaleResult = value, { notificationLocale: snapshot!.config.notificationLocale }); }}>
									<Field.Field><Field.Label for="notification-locale">{t("notificationLocale")}</Field.Label><NativeSelect.Root id="notification-locale" class="w-full" bind:value={snapshot.config.notificationLocale}><NativeSelect.Option value="zh-TW">{t("localeZhTw")}</NativeSelect.Option><NativeSelect.Option value="zh-CN">{t("localeZhCn")}</NativeSelect.Option><NativeSelect.Option value="en">{t("localeEn")}</NativeSelect.Option></NativeSelect.Root><Field.Description>{t("notificationLocaleHint")}</Field.Description></Field.Field>
								</form>
								<div class="flex justify-end"><Button type="submit" form="notification-locale-form" disabled={notificationLocaleResult.state === "loading"}>{notificationLocaleResult.state === "loading" ? t("commonSaving") : t("commonSave")}</Button></div>
								<ActionResult result={notificationLocaleResult} title={t("resultTitle")} {locale} />
							</Accordion.Content>
							</Accordion.Item>
							<Accordion.Item value="heartbeat">
								<Accordion.Trigger><span class="flex items-center gap-2"><span>{t("heartbeatTitle")}</span><Badge variant={snapshot.config.heartbeatEnable ? "secondary" : "outline"}>{snapshot.config.heartbeatEnable ? t("commonEnabled") : t("commonDisabled")}</Badge></span></Accordion.Trigger>
								<Accordion.Content class="flex flex-col gap-5">
									<p class="text-muted-foreground">{t("heartbeatDescription")}</p>
									<Alert.Root><Alert.Title>{t("heartbeatNtpTitle")}</Alert.Title><Alert.Description>{t("heartbeatNtpDescription")}</Alert.Description></Alert.Root>
									<form id="heartbeat-form" onsubmit={(event) => { event.preventDefault(); const c = snapshot!.config; void save((value) => heartbeatResult = value, { heartbeatEnable: c.heartbeatEnable, heartbeatInterval: c.heartbeatInterval }); }}>
										<Field.Group>
											<Field.Field orientation="horizontal"><Field.Label for="heartbeat-enabled">{t("heartbeatEnabled")}</Field.Label><Switch id="heartbeat-enabled" bind:checked={snapshot.config.heartbeatEnable} /></Field.Field>
											<Field.Field><Field.Label for="heartbeat-interval">{t("heartbeatInterval")}</Field.Label><Input id="heartbeat-interval" type="number" min={CONFIG_VALUE_LIMITS.heartbeatInterval.min} max={CONFIG_VALUE_LIMITS.heartbeatInterval.max} required bind:value={snapshot.config.heartbeatInterval} /><Field.Description>{t("heartbeatIntervalHint")}</Field.Description></Field.Field>
										</Field.Group>
									</form>
									<div class="flex justify-end"><Button type="submit" form="heartbeat-form" disabled={heartbeatResult.state === "loading"}>{heartbeatResult.state === "loading" ? t("commonSaving") : t("commonSave")}</Button></div>
									<ActionResult result={heartbeatResult} title={t("resultTitle")} {locale} />
								</Accordion.Content>
							</Accordion.Item>
							<Accordion.Item value="email">
							<Accordion.Trigger><span class="flex items-center gap-2"><span>{t("emailTitle")}</span><Badge variant={snapshot.status.emailConfigured ? "secondary" : "outline"}>{snapshot.status.emailConfigured ? t("commonConfigured") : t("commonNotConfigured")}</Badge></span></Accordion.Trigger>
							<Accordion.Content class="flex flex-col gap-5"><p class="text-muted-foreground">{t("emailDescription")}</p><form id="email-form" onsubmit={(event) => { event.preventDefault(); const c = snapshot!.config; void save((v) => emailResult = v, { smtpServer: c.smtpServer, smtpPort: c.smtpPort, smtpUser: c.smtpUser, ...(c.smtpPass ? { smtpPass: c.smtpPass } : {}), smtpSendTo: c.smtpSendTo }); }}><Field.Group class="grid gap-5 md:grid-cols-2"><Field.Field><Field.Label for="smtp-server">{t("smtpServer")}</Field.Label><Input id="smtp-server" bind:value={snapshot.config.smtpServer} /></Field.Field><Field.Field><Field.Label for="smtp-port">{t("smtpPort")}</Field.Label><Input id="smtp-port" type="number" min="1" max="65535" bind:value={snapshot.config.smtpPort} /></Field.Field><Field.Field><Field.Label for="smtp-user">{t("smtpUser")}</Field.Label><Input id="smtp-user" type="email" bind:value={snapshot.config.smtpUser} /></Field.Field><Field.Field><Field.Label for="smtp-pass">{t("smtpPassword")}</Field.Label><Input id="smtp-pass" type="password" autocomplete="new-password" bind:value={snapshot.config.smtpPass} /><Field.Description>{t("smtpPasswordHint")}</Field.Description></Field.Field><Field.Field class="md:col-span-2"><Field.Label for="smtp-to">{t("smtpRecipient")}</Field.Label><Input id="smtp-to" type="email" bind:value={snapshot.config.smtpSendTo} /></Field.Field></Field.Group></form><div class="flex justify-end"><Button type="submit" form="email-form" disabled={emailResult.state === "loading"}>{emailResult.state === "loading" ? t("commonSaving") : t("commonSave")}</Button></div><ActionResult result={emailResult} title={t("resultTitle")} {locale} /></Accordion.Content>
						</Accordion.Item>
						<Accordion.Item value="push">
							<Accordion.Trigger><span class="flex items-center gap-2"><span>{t("pushTitle")}</span><Badge variant={snapshot.status.enabledPushChannels > 0 ? "secondary" : "outline"}>{snapshot.status.enabledPushChannels} / 5</Badge></span></Accordion.Trigger>
			<Accordion.Content class="flex flex-col gap-5"><p class="text-muted-foreground">{t("pushDescription")}</p><Tabs.Root bind:value={pushTab} class="flex flex-col gap-6"><div class="overflow-x-auto pb-1"><Tabs.List class="min-w-max">{#each snapshot.config.pushChannels as channel, index (index)}<Tabs.Trigger value={String(index)}><span class="flex items-center gap-2"><span>{channel.name || `${t("pushChannel")} ${index + 1}`}</span><Badge variant={channel.enabled ? "secondary" : "outline"}>{channel.enabled ? t("commonEnabled") : t("commonDisabled")}</Badge></span></Tabs.Trigger>{/each}</Tabs.List></div>{#each snapshot.config.pushChannels as channel, index (index)}<Tabs.Content value={String(index)}><Field.Group class="grid gap-5 md:grid-cols-2"><Field.Field orientation="horizontal" class="md:col-span-2"><Field.Label for={`push-enabled-${index}`}>{t("channelEnabled")}</Field.Label><Switch id={`push-enabled-${index}`} bind:checked={channel.enabled} /></Field.Field><Field.Field><Field.Label for={`push-name-${index}`}>{t("channelName")}</Field.Label><Input id={`push-name-${index}`} bind:value={channel.name} /></Field.Field><Field.Field><Field.Label for={`push-type-${index}`}>{t("providerType")}</Field.Label><NativeSelect.Root id={`push-type-${index}`} class="w-full" bind:value={channel.type} onchange={() => changeProvider(channel, index)}>{#each providers as provider, providerIndex (provider)}<NativeSelect.Option value={providerIndex + 1}>{provider}</NativeSelect.Option>{/each}</NativeSelect.Root><Field.Description>{providerHint(channel.type)}</Field.Description></Field.Field><Field.Field class="md:col-span-2"><Field.Label for={`push-url-${index}`}>{endpointLabel(channel.type)}</Field.Label><Input id={`push-url-${index}`} type="url" required={pushSecretRequired(channel, "url")} bind:value={channel.url} />{#if savedSecretHint(channel.url, channel.urlSet)}<Field.Description>{savedSecretHint(channel.url, channel.urlSet)}</Field.Description>{/if}</Field.Field>{#if pushProviderKeyFields(channel.type).includes("key1")}<Field.Field><Field.Label for={`push-key1-${index}`}>{keyLabel(channel.type, "key1")}</Field.Label><Input id={`push-key1-${index}`} required={pushSecretRequired(channel, "key1")} bind:value={channel.key1} />{#if savedSecretHint(channel.key1, channel.key1Set)}<Field.Description>{savedSecretHint(channel.key1, channel.key1Set)}</Field.Description>{/if}{#if channel.type === 5}<Field.Description>{t("keyTokenHint")}</Field.Description>{/if}</Field.Field>{/if}{#if pushProviderKeyFields(channel.type).includes("key2")}<Field.Field><Field.Label for={`push-key2-${index}`}>{keyLabel(channel.type, "key2")}</Field.Label><Input id={`push-key2-${index}`} required={pushSecretRequired(channel, "key2")} bind:value={channel.key2} />{#if savedSecretHint(channel.key2, channel.key2Set)}<Field.Description>{savedSecretHint(channel.key2, channel.key2Set)}</Field.Description>{/if}{#if channel.type === 5}<Field.Description>{t("keyChannelHint")}</Field.Description>{/if}</Field.Field>{/if}<Separator class="md:col-span-2" /><div class="md:col-span-2"><p class="font-medium">{t("templateTitle")}</p><p class="text-sm text-muted-foreground">{t("templateDescription")}</p><p class="mt-1 text-sm text-muted-foreground">{t("templateValuesHint")}</p></div>{#if channel.type === 7}<Field.Field class="md:col-span-2"><Field.Label for={`push-body-${index}`}>{t("customBody")}</Field.Label><Textarea id={`push-body-${index}`} rows={5} class="font-mono" required={pushSecretRequired(channel, "customBody")} bind:value={channel.customBody} /><Field.Description>{savedSecretHint(channel.customBody, channel.customBodySet) || t("customBodyHint")}</Field.Description></Field.Field>{:else}<Field.Field class="md:col-span-2"><Field.Label for={`push-title-template-${index}`}>{t("titleTemplate")}</Field.Label><Input id={`push-title-template-${index}`} placeholder={t("templateInherited")} bind:value={channel.titleTemplate} /><Field.Description>{t("titleTemplateHint")}</Field.Description></Field.Field><Field.Field class="md:col-span-2"><Field.Label for={`push-body-template-${index}`}>{t("bodyTemplate")}</Field.Label><Textarea id={`push-body-template-${index}`} rows={4} placeholder={t("templateInherited")} bind:value={channel.bodyTemplate} /><Field.Description>{t("bodyTemplateHint")}</Field.Description></Field.Field>{/if}<Card.Root class="md:col-span-2"><Card.Header><Card.Title>{t("pushTestTitle")}</Card.Title><Card.Description>{t("pushTestDescription")}</Card.Description></Card.Header><Card.Content><p class="text-sm text-muted-foreground" role={pushTestResults[index].done && !pushTestResults[index].success ? "alert" : "status"} aria-live="polite">{pushTestBusy[index] && !pushTestResults[index].done ? t("pushTestRunning") : pushTestResults[index].message || t("pushTestIdle")}</p></Card.Content><Card.Footer class="justify-end"><Button variant="outline" disabled={pushTestBusy[index]} aria-label={`${t("pushTestButton")} ${channel.name || `${t("pushChannel")} ${index + 1}`}`} onclick={() => void testPush(index)}>{#if pushTestBusy[index]}<Spinner data-icon="inline-start" />{t("pushTestRunning")}{:else}{t("pushTestButton")}{/if}</Button></Card.Footer></Card.Root></Field.Group></Tabs.Content>{/each}</Tabs.Root><div class="flex justify-end"><Button onclick={() => save((v) => pushResult = v, pushValues())} disabled={pushResult.state === "loading"}>{pushResult.state === "loading" ? t("commonSaving") : t("commonSave")}</Button></div><ActionResult result={pushResult} title={t("resultTitle")} {locale} /></Accordion.Content>
						</Accordion.Item>
						<Accordion.Item value="push-cellular">
							<Accordion.Trigger>{t("cellularPushTitle")}</Accordion.Trigger>
							<Accordion.Content class="grid gap-5 lg:grid-cols-2">
								{#each snapshot.config.pushChannels as channel, index (index)}
									<Card.Root>
										<Card.Header><Card.Title>{channel.name || `${t("pushChannel")} ${index + 1}`}</Card.Title><Card.Description>{t("cellularPushDescription")}</Card.Description></Card.Header>
										<Card.Content><Field.Group><Field.Field orientation="horizontal"><Field.Label for={`push-cellular-enabled-${index}`}>{t("cellularPushEnabled")}</Field.Label><Switch id={`push-cellular-enabled-${index}`} bind:checked={channel.cellularEnabled} /></Field.Field><Field.Field><Field.Label for={`push-cellular-url-${index}`}>{t("cellularPushUrl")}</Field.Label><Input id={`push-cellular-url-${index}`} type="url" placeholder={t("cellularPushUrlInherited")} bind:value={channel.cellularUrl} />{#if savedSecretHint(channel.cellularUrl, channel.cellularUrlSet)}<Field.Description>{savedSecretHint(channel.cellularUrl, channel.cellularUrlSet)}</Field.Description>{/if}<Button type="button" variant="ghost" disabled={!channel.cellularUrlSet && !channel.cellularUrl} onclick={() => { channel.cellularUrl = ""; cellularUrlClears[index] = true; }}>{t("cellularPushUrlClear")}</Button></Field.Field><CellularCaResult status={pushCaStatuses[index]} saveResult={pushCellularSaveResults[index]} result={pushCaResults[index]} title={t("cellularCaStatus")} saveTitle={t("resultTitle")} ready={t("cellularCaReady")} notReady={t("cellularCaNotReady")} {locale} /></Field.Group></Card.Content>
										<Card.Footer class="flex-wrap justify-end gap-2"><Button variant="outline" disabled={pushCaResults[index].state === "loading" || !channel.cellularEnabled} onclick={() => void provisionCa(index)}>{#if pushCaResults[index].state === "loading"}<Spinner data-icon="inline-start" />{/if}{t("cellularCaProvision")}</Button><Button disabled={pushCellularSaveResults[index].state === "loading"} onclick={() => saveCellular(index)}>{t("commonSave")}</Button></Card.Footer>
									</Card.Root>
								{/each}
							</Accordion.Content>
						</Accordion.Item>
					</Accordion.Root>
				</section>
				{:else if mainTab === "messaging"}
					<section class="flex flex-col gap-6">
					<div><h1 class="text-2xl font-semibold tracking-tight">{t("messagingTitle")}</h1><p class="mt-1 text-sm text-muted-foreground">{t("messagingDescription")}</p></div>
					<Accordion.Root type="single" value="sms">
						<Accordion.Item value="sms"><Accordion.Trigger>{t("sendSmsTitle")}</Accordion.Trigger><Accordion.Content class="flex flex-col gap-5"><p class="text-muted-foreground">{t("sendSmsDescription")}</p><form id="sms-form" onsubmit={(event) => { event.preventDefault(); void sendSms(); }}><Field.Group><Field.Field><Field.Label for="sms-phone">{t("targetPhone")}</Field.Label><Input id="sms-phone" type="tel" required bind:value={phone} /></Field.Field><Field.Field><Field.Label for="sms-message">{t("smsContent")}</Field.Label><Textarea id="sms-message" rows={8} required bind:value={message} /></Field.Field></Field.Group></form><div class="flex items-center justify-between gap-4"><div class="min-w-0 flex-1"><ActionResult result={smsResult} title={t("resultTitle")} {locale} /></div><Button type="submit" form="sms-form" disabled={smsResult.state === "loading"}>{smsResult.state === "loading" ? t("sending") : t("send")}</Button></div></Accordion.Content></Accordion.Item>
						<Accordion.Item value="routing"><Accordion.Trigger>{t("routingTitle")}</Accordion.Trigger><Accordion.Content class="flex flex-col gap-5"><p class="text-muted-foreground">{t("routingDescription")}</p><form id="routing-form" onsubmit={(event) => { event.preventDefault(); const c = snapshot!.config; void save((v) => routingResult = v, { adminPhone: c.adminPhone, numberBlackList: c.numberBlackList }); }}><Field.Group><Field.Field><Field.Label for="admin-phone">{t("adminPhone")}</Field.Label><Input id="admin-phone" type="tel" bind:value={snapshot.config.adminPhone} /><Field.Description>{t("adminPhoneHint")}</Field.Description></Field.Field><Field.Field><Field.Label for="blocklist">{t("blacklist")}</Field.Label><Textarea id="blocklist" rows={6} bind:value={snapshot.config.numberBlackList} /><Field.Description>{t("blacklistHint")}</Field.Description></Field.Field></Field.Group></form><div class="flex items-center justify-between gap-4"><div class="min-w-0 flex-1"><ActionResult result={routingResult} title={t("resultTitle")} {locale} /></div><Button type="submit" form="routing-form" disabled={routingResult.state === "loading"}>{routingResult.state === "loading" ? t("commonSaving") : t("commonSave")}</Button></div></Accordion.Content></Accordion.Item>
						<Accordion.Item value="forward-rules">
							<Accordion.Trigger>{t("forwardRulesTitle")}</Accordion.Trigger>
							<Accordion.Content class="flex flex-col gap-5">
								<div class="flex flex-wrap items-start justify-between gap-3">
									<p class="max-w-2xl text-muted-foreground">{t("forwardRulesDescription")}</p>
									<Dialog.Root bind:open={forwardRulesDialogOpen}>
										<Dialog.Trigger type="button" class={buttonVariants({ variant: "outline", size: "sm" })} aria-haspopup="dialog">{t("forwardRulesTips")}</Dialog.Trigger>
										<Dialog.Portal>
										<Dialog.Overlay class="fixed inset-0 bg-black/45" />
										<Dialog.Content class="fixed left-1/2 top-1/2 flex max-h-[min(42rem,calc(100dvh-2rem))] w-[min(42rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 flex-col gap-5 overflow-y-auto rounded-xl border border-border bg-background p-6 text-foreground shadow-2xl outline-none">
												<div class="flex flex-col gap-1.5">
													<Dialog.Title class="text-lg font-semibold">{t("forwardRulesDialogTitle")}</Dialog.Title>
													<Dialog.Description class="text-sm text-muted-foreground">{t("forwardRulesDialogDescription")}</Dialog.Description>
												</div>
												<div class="flex flex-col gap-4 text-sm">
													<div><p class="font-medium">{t("forwardRulesSyntaxLabel")}</p><p class="mt-1 text-muted-foreground">{t("forwardRulesSyntax")}</p></div>
													<ul class="list-disc space-y-2 pl-5 text-muted-foreground">
														<li><code class="rounded bg-muted px-1 py-0.5 font-mono text-xs">kw</code>：{t("forwardRulesKeyword")}</li>
														<li><code class="rounded bg-muted px-1 py-0.5 font-mono text-xs">from</code>：{t("forwardRulesFrom")}</li>
														<li><code class="rounded bg-muted px-1 py-0.5 font-mono text-xs">re</code>：{t("forwardRulesRegex")}</li>
													</ul>
													<div><p class="font-medium">{t("forwardRulesActionsLabel")}</p><p class="mt-1 text-muted-foreground">{t("forwardRulesActions")}</p></div>
													<div><p class="font-medium">{t("forwardRulesPrecedenceLabel")}</p><p class="mt-1 text-muted-foreground">{t("forwardRulesPrecedence")}</p></div>
													<div><p class="font-medium">{t("forwardRulesEmptyLabel")}</p><p class="mt-1 text-muted-foreground">{t("forwardRulesEmpty")}</p></div>
													<div><p class="font-medium">{t("forwardRulesEscapingLabel")}</p><p class="mt-1 text-muted-foreground">{t("forwardRulesEscaping")}</p></div>
													<div>
														<p class="font-medium">{t("forwardRulesExamplesLabel")}</p>
														<p class="mt-1 text-xs text-muted-foreground">{t("forwardRulesTabNotation")}</p>
														<ul class="mt-2 space-y-2">
															<li><code class="block overflow-x-auto rounded-md bg-muted p-2 font-mono text-xs">{t("forwardRulesExample1")}</code></li>
															<li><code class="block overflow-x-auto rounded-md bg-muted p-2 font-mono text-xs">{t("forwardRulesExample2")}</code></li>
														</ul>
													</div>
												</div>
												<div class="flex justify-end"><Dialog.Close type="button" class={buttonVariants({ variant: "outline" })}>{t("commonClose")}</Dialog.Close></div>
											</Dialog.Content>
										</Dialog.Portal>
									</Dialog.Root>
								</div>
								<form id="forward-rules-form" onsubmit={(event) => { event.preventDefault(); void save((v) => forwardRulesResult = v, { forwardRules: snapshot!.config.forwardRules }); }}><Field.Group><Field.Field><Field.Label for="forward-rules">{t("forwardRulesTitle")}</Field.Label><Textarea id="forward-rules" rows={10} spellcheck={false} aria-describedby="forward-rules-hint" bind:value={snapshot.config.forwardRules} /><Field.Description id="forward-rules-hint">{t("forwardRulesHint")}</Field.Description></Field.Field></Field.Group></form><div class="flex items-center justify-between gap-4"><div class="min-w-0 flex-1"><ActionResult result={forwardRulesResult} title={t("resultTitle")} {locale} /></div><Button type="submit" form="forward-rules-form" disabled={forwardRulesResult.state === "loading"}>{forwardRulesResult.state === "loading" ? t("commonSaving") : t("commonSave")}</Button></div>
							</Accordion.Content>
						</Accordion.Item>
					</Accordion.Root>
					</section>
				{:else if mainTab === "cellular"}
					<section class="flex flex-col gap-6">
						<div class="flex flex-wrap items-start justify-between gap-4">
							<div><h1 class="text-2xl font-semibold tracking-tight">{t("esimTitle")}</h1><p class="mt-1 max-w-2xl text-sm text-muted-foreground">{t("esimDescription")}</p></div>
							<Button variant="outline" onclick={() => void refreshEsim()} disabled={esimLoading}><span class="flex items-center gap-2">{#if esimLoading}<Spinner data-icon="inline-start" />{/if}{t("esimRefresh")}</span></Button>
						</div>
						{#if esimError}
							<Alert.Root variant="destructive"><Alert.Title>{t("esimError")}</Alert.Title><Alert.Description class="flex flex-col items-start gap-3"><span>{t("esimErrorBody")}</span><Button variant="outline" onclick={() => void refreshEsim()}>{t("retry")}</Button></Alert.Description></Alert.Root>
						{:else if esimLoading && !esim}
							<div class="grid gap-4 sm:grid-cols-2"><Skeleton class="h-32" /><Skeleton class="h-32" /></div>
						{:else if esim}
							<Card.Root>
								<Card.Header><Card.Title>{t("esimEid")}</Card.Title><Card.Description>{t(esim.eid.available ? "esimEidAvailable" : "esimEidUnavailable")}</Card.Description></Card.Header>
								<Card.Content><dl class="grid gap-4 sm:grid-cols-2"><div><dt class="text-sm text-muted-foreground">{t("esimEidState")}</dt><dd class="mt-1"><Badge variant={esim.eid.available ? "default" : "outline"}>{t(esim.eid.available ? "esimEidAvailable" : "esimEidUnavailable")}</Badge></dd></div><div><dt class="text-sm text-muted-foreground">{t("esimEidLength")}</dt><dd class="mt-1 font-medium tabular-nums">{esim.eid.length}</dd></div></dl></Card.Content>
							</Card.Root>
							<section class="flex flex-col gap-4" aria-labelledby="esim-profiles-title">
								<div><h2 id="esim-profiles-title" class="text-xl font-semibold">{t("esimProfiles")}</h2></div>
								{#if esim.profiles.length === 0}
									<Empty.Root><Empty.Header><Empty.Title>{t("esimEmpty")}</Empty.Title></Empty.Header><Empty.Content><Button variant="outline" onclick={() => void runEsimAction("refresh")}>{t("esimRefresh")}</Button></Empty.Content></Empty.Root>
								{:else}
									<div class="grid gap-4 md:grid-cols-2">
										{#each esim.profiles as profile, profileIndex (profile.handle)}
											<Card.Root>
												<Card.Header><div class="flex items-start justify-between gap-3"><div class="min-w-0"><Card.Title>{profile.nickname || t("esimProfileUnnamed")}</Card.Title><Card.Description>{t("esimProfileDisplayId")}: {profile.displayId}</Card.Description></div><Badge variant={profile.state === "enabled" ? "default" : "outline"}>{t(profile.state === "enabled" ? "esimProfileEnabled" : profile.state === "disabled" ? "esimProfileDisabled" : "esimProfileUnknown")}</Badge></div></Card.Header>
												<Card.Content class="flex flex-col gap-4"><dl class="grid gap-3 sm:grid-cols-2"><div><dt class="text-sm text-muted-foreground">{t("esimNickname")}</dt><dd class="mt-1 font-medium">{profile.nickname || t("esimProfileUnnamed")}</dd></div><div><dt class="text-sm text-muted-foreground">{t("esimProfileClass")}</dt><dd class="mt-1 font-medium">{t(profile.profileClass === "operational" ? "esimClassOperational" : profile.profileClass === "provisioning" ? "esimClassProvisioning" : "esimClassUnknown")}</dd></div></dl><form class="flex flex-col gap-3" onsubmit={(event) => { event.preventDefault(); void runEsimAction("nickname", profile, profile.nickname); }}><Field.Field><Field.Label for={`esim-nickname-${profile.handle}`}>{t("esimNickname")}</Field.Label><Input id={`esim-nickname-${profile.handle}`} maxlength={64} autocomplete="off" placeholder={t("esimNicknamePlaceholder")} bind:value={profile.nickname} /></Field.Field><Button type="submit" variant="outline" disabled={esimResult.state === "loading"}>{t("esimSaveNickname")}</Button></form></Card.Content>
														<Card.Footer class="flex flex-wrap justify-end gap-2"><Button variant="outline" disabled={esimResult.state === "loading" || profile.state === "enabled"} onclick={() => void runEsimAction("enable", profile)}>{t("esimEnable")}</Button><Button variant="outline" disabled={esimResult.state === "loading" || profile.state !== "enabled"} onclick={() => void runEsimAction("disable", profile)}>{t("esimDisable")}</Button><Button variant="outline" disabled={esimResult.state === "loading"} onclick={() => void runEsimAction("switch", profile)}>{t("esimSwitch")}</Button><Button id={`esim-delete-${profileIndex}`} variant="destructive" disabled={esimResult.state === "loading"} onclick={() => askDelete(profile.handle, `esim-delete-${profileIndex}`)}>{t("esimDelete")}</Button></Card.Footer>
											</Card.Root>
										{/each}
									</div>
								{/if}
								<ActionResult result={esimResult} title={t("resultTitle")} {locale} />
							</section>
						{/if}
					</section>
				{:else if mainTab === "device"}
					<section id={`device/${deviceSubpage}`} class="device-page flex flex-col gap-6">
						<section class="device-subpage-header" aria-label={t("deviceTitle")}>
							<div>
								<p class="device-breadcrumb">{t("deviceTitle")}</p>
								<h1 id="device-subpage-title" class="text-2xl font-semibold tracking-tight">{t(currentDeviceSubpage.label)}</h1>
								<p class="mt-1 max-w-2xl text-sm text-muted-foreground">{t(currentDeviceSubpage.description)}</p>
							</div>
						</section>
						<details class="device-subpage-menu lg:hidden">
							<summary>{t("deviceSubpageMenu")}: {t(currentDeviceSubpage.label)}</summary>
							<nav aria-label={t("deviceSubpageMenu")}>
								{#each deviceSubpages as subpage (subpage.value)}
									<a class="device-subpage-menu-link" href={`#device/${subpage.value}`} data-active={deviceSubpage === subpage.value ? "true" : undefined} aria-current={deviceSubpage === subpage.value ? "page" : undefined}>{t(subpage.label)}</a>
								{/each}
							</nav>
						</details>
						<Accordion.Root type="multiple" value={deviceSubpage === "connection" ? ["identity", "wifi-profiles", "network-mode", "keepalive-compatibility"] : deviceSubpage === "diagnostics" ? ["diagnostics", "network"] : deviceSubpage === "advanced" ? ["control", "terminal"] : ["config-backup", "config-restore", "ota"]}>
						{#if deviceSubpage === "connection"}
						<div class="device-subpage" data-device-subpage="connection">
								<section class="device-tool-group" data-tool-group="connection" aria-labelledby="device-group-connection">
								<div class="device-tool-group-heading"><h2 id="device-group-connection" class="text-sm font-semibold">{t("deviceGroupConnection")}</h2></div>
							<Accordion.Item value="identity">
								<Accordion.Trigger>{t("deviceTabIdentity")}</Accordion.Trigger>
									<Accordion.Content class="flex flex-col gap-4"><form id="identity-form" data-device-action="identity-save" onsubmit={(event) => { event.preventDefault(); void save((value) => identityResult = value, { deviceName: snapshot!.config.deviceName, hostname: snapshot!.config.hostname }); }}><Field.Group><Field.Field><Field.Label for="device-name">{t("deviceName")}</Field.Label><Input id="device-name" required bind:value={snapshot.config.deviceName} /><Field.Description>{t("deviceNameHint")}</Field.Description></Field.Field><Field.Field><Field.Label for="hostname">{t("hostname")}</Field.Label><Input id="hostname" required pattern="[a-z0-9](?:[a-z0-9-]*[a-z0-9])?" bind:value={snapshot.config.hostname} /><Field.Description>{t("hostnameHint")}</Field.Description></Field.Field></Field.Group></form><div class="flex justify-end"><Button type="submit" form="identity-form">{t("commonSave")}</Button></div><ActionResult result={identityResult} title={t("resultTitle")} {locale} /></Accordion.Content>
							</Accordion.Item>
							<Accordion.Item value="wifi-profiles">
								<Accordion.Trigger>{t("wifiProfilesTitle")}</Accordion.Trigger>
								<Accordion.Content class="flex flex-col gap-5">
									<p class="text-muted-foreground">{t("wifiProfilesDescription")}</p>
									{#if snapshot.status.apMode}<Alert.Root><Alert.Title>{t("apModeTitle")}</Alert.Title><Alert.Description>{t("apModeDescription")} <strong>http://192.168.1.1</strong></Alert.Description></Alert.Root>{/if}
									<Tabs.Root bind:value={wifiTab} class="flex flex-col gap-6">
										<div class="overflow-x-auto pb-1"><Tabs.List class="min-w-max">{#each snapshot.config.wifiProfiles as profile, index (index)}<Tabs.Trigger value={String(index)}><span class="flex items-center gap-2"><span>{t("wifiProfile")} {index + 1}</span><Badge variant={profile.ssid ? "secondary" : "outline"}>{profile.ssid ? t("commonEnabled") : t("commonDisabled")}</Badge></span></Tabs.Trigger>{/each}</Tabs.List></div>
										{#each snapshot.config.wifiProfiles as profile, index (index)}
											<Tabs.Content value={String(index)}>
														<form class="flex flex-col gap-5" data-device-action="wifi-profile-save" onsubmit={(event) => { event.preventDefault(); void save((value) => wifiResult = value, wifiValues(index)); }}>
													<Field.Group>
														<Field.Field><Field.Label for={`wifi-ssid-${index}`}>{t("wifiSsid")}</Field.Label><Input id={`wifi-ssid-${index}`} maxlength={CONFIG_FIELD_LIMITS.wifiSsid} bind:value={profile.ssid} /><Field.Description>{t("wifiSsidHint")}</Field.Description></Field.Field>
														<Field.Field data-invalid={wifiPasswordRequired(index) && !profile.password}><Field.Label for={`wifi-password-${index}`}>{t("wifiPassword")}</Field.Label><Input id={`wifi-password-${index}`} type="password" minlength={8} maxlength={CONFIG_FIELD_LIMITS.wifiPassword} pattern={"[ -~]{8,63}"} autocomplete="new-password" required={wifiPasswordRequired(index)} aria-invalid={wifiPasswordRequired(index) && !profile.password} disabled={!profile.ssid || openWifiProfiles[index]} bind:value={profile.password} /><Field.Description>{wifiPasswordRequired(index) ? t("wifiPasswordChangedHint") : t("wifiPasswordHint")}</Field.Description></Field.Field>
														<Field.Field orientation="horizontal" data-disabled={!profile.ssid}><Field.Label for={`wifi-open-${index}`}>{t("wifiOpenNetwork")}</Field.Label><Switch id={`wifi-open-${index}`} disabled={!profile.ssid} bind:checked={openWifiProfiles[index]} onchange={() => { if (openWifiProfiles[index]) profile.password = ""; }} /></Field.Field>
													</Field.Group>
													<div class="flex justify-end"><Button type="submit" disabled={wifiResult.state === "loading"}>{wifiResult.state === "loading" ? t("commonSaving") : t("commonSave")}</Button></div>
												</form>
												<ActionResult result={wifiResult} title={t("resultTitle")} {locale} />
											</Tabs.Content>
										{/each}
									</Tabs.Root>
								</Accordion.Content>
							</Accordion.Item>
							<Accordion.Item value="network-mode">
								<Accordion.Trigger>{t("networkModeTitle")}</Accordion.Trigger>
								<Accordion.Content class="flex flex-col gap-5">
									<Alert.Root><Alert.Title>{t("networkModeWarningTitle")}</Alert.Title><Alert.Description>{t("networkModeWarningDescription")}</Alert.Description></Alert.Root>
									<form id="network-mode-form" data-device-action="network-mode-save" onsubmit={(event) => { event.preventDefault(); void save((value) => networkModeResult = value, { networkMode: snapshot!.config.networkMode }); }}>
										<Field.Field><Field.Label for="network-mode">{t("networkMode")}</Field.Label><NativeSelect.Root id="network-mode" class="w-full" bind:value={snapshot.config.networkMode}><NativeSelect.Option value={0}>{t("networkModeWifiOnly")}</NativeSelect.Option><NativeSelect.Option value={1}>{t("networkMode4gOnly")}</NativeSelect.Option><NativeSelect.Option value={2}>{t("networkModeMix")}</NativeSelect.Option></NativeSelect.Root><Field.Description>{t("networkModeHint")}</Field.Description></Field.Field>
									</form>
									<div class="flex justify-end"><Button type="submit" form="network-mode-form" disabled={networkModeResult.state === "loading"}>{networkModeResult.state === "loading" ? t("commonSaving") : t("commonSave")}</Button></div>
									<ActionResult result={networkModeResult} title={t("resultTitle")} {locale} />
								</Accordion.Content>
							</Accordion.Item>
							<Accordion.Item value="keepalive-compatibility">
								<Accordion.Trigger><span class="flex items-center gap-2"><span>{t("keepaliveTitle")}</span><Badge variant={snapshot.config.kaEnabled ? "destructive" : "outline"}>{snapshot.config.kaEnabled ? t("keepaliveLegacyEnabled") : t("commonDisabled")}</Badge></span></Accordion.Trigger>
								<Accordion.Content class="flex flex-col gap-5">
									<Alert.Root><Alert.Title>{t("keepaliveUnsupportedTitle")}</Alert.Title><Alert.Description>{t("keepaliveUnsupportedDescription")}</Alert.Description></Alert.Root>
									<p class="text-muted-foreground">{snapshot.config.kaEnabled ? t("keepaliveEnabledDescription") : t("keepaliveDisabledDescription")}</p>
									<dl class="grid gap-4 sm:grid-cols-2">
										<div><dt class="text-sm text-muted-foreground">{t("keepaliveIntervalDays")}</dt><dd class="mt-1 font-medium tabular-nums">{snapshot.config.kaIntervalDays}</dd></div>
										<div><dt class="text-sm text-muted-foreground">{t("keepaliveTrafficKB")}</dt><dd class="mt-1 font-medium tabular-nums">{snapshot.config.kaTrafficKB}</dd></div>
									</dl>
									{#if snapshot.config.kaEnabled}
										<div class="flex justify-end"><Button variant="destructive" data-device-action="keepalive-disable" disabled={keepaliveResult.state === "loading"} onclick={() => { const c = snapshot!.config; void save((value) => keepaliveResult = value, { kaIntervalDays: c.kaIntervalDays, kaTrafficKB: c.kaTrafficKB }); }}>{keepaliveResult.state === "loading" ? t("commonSaving") : t("keepaliveDisable")}</Button></div>
									{/if}
									<ActionResult result={keepaliveResult} title={t("resultTitle")} {locale} />
								</Accordion.Content>
							</Accordion.Item>
							</section>
						</div>
						{:else if deviceSubpage === "diagnostics"}
						<div class="device-subpage" data-device-subpage="diagnostics">
							<section class="device-tool-group" data-tool-group="diagnostics" aria-labelledby="device-group-diagnostics">
							<div class="device-tool-group-heading"><h2 id="device-group-diagnostics" class="text-sm font-semibold">{t("deviceGroupDiagnostics")}</h2></div>
								<Accordion.Item value="diagnostics"><Accordion.Trigger>{t("deviceTabDiagnostics")}</Accordion.Trigger><Accordion.Content class="flex flex-col gap-4"><div class="flex flex-wrap gap-2"><Button variant="outline" data-device-action="diagnostics-modem-info" onclick={() => action((value) => diagnosticsResult = value, "/query?type=ati")}>{t("modemInfo")}</Button><Button variant="outline" data-device-action="diagnostics-signal" onclick={() => action((value) => diagnosticsResult = value, "/query?type=signal")}>{t("signal")}</Button><Button variant="outline" data-device-action="diagnostics-sim-info" onclick={() => action((value) => diagnosticsResult = value, "/query?type=siminfo")}>{t("simInfo")}</Button><Button variant="outline" data-device-action="diagnostics-modem-signal" onclick={() => action((value) => diagnosticsResult = value, "/modem?action=signal")}>{t("modemSignal")}</Button><Button variant="outline" data-device-action="diagnostics-operator" onclick={() => action((value) => diagnosticsResult = value, "/modem?action=operator")}>{t("operator")}</Button><Button variant="outline" data-device-action="diagnostics-imei" onclick={() => action((value) => diagnosticsResult = value, "/modem?action=imei")}>{t("imei")}</Button></div><ActionResult result={diagnosticsResult} title={t("resultTitle")} {locale} /></Accordion.Content></Accordion.Item>
						<Accordion.Item value="network"><Accordion.Trigger>{t("deviceTabNetwork")}</Accordion.Trigger><Accordion.Content class="flex flex-col gap-4"><div class="flex flex-wrap gap-2"><Button variant="outline" data-device-action="diagnostics-network" onclick={() => action((value) => networkResult = value, "/query?type=network")}>{t("networkState")}</Button><Button variant="outline" data-device-action="diagnostics-wifi" onclick={() => action((value) => networkResult = value, "/query?type=wifi")}>{t("wifiState")}</Button><Button variant="outline" data-device-action="diagnostics-flight" onclick={() => action((value) => networkResult = value, "/flight?action=query")}>{t("flightQuery")}</Button></div><ActionResult result={networkResult} title={t("resultTitle")} {locale} /></Accordion.Content></Accordion.Item>
							</section>
							<section class="device-tool-group" data-tool-group="history" aria-labelledby="device-group-history">
								<div class="device-tool-group-heading"><h2 id="device-group-history">{t("deviceHistoryTitle")}</h2><p>{t("deviceHistoryDescription")}</p></div>
								<div class="device-tool-content"><Field.Field orientation="horizontal"><Field.Label for="auto-refresh">{t("autoRefresh")}</Field.Label><Switch id="auto-refresh" size="sm" bind:checked={autoRefresh} /></Field.Field>{#if logs.length === 0}<Empty.Root><Empty.Header><Empty.Title>{t("emptyLog")}</Empty.Title></Empty.Header></Empty.Root>{:else}<pre class="max-h-[28rem] overflow-auto rounded-lg bg-muted p-4 text-xs whitespace-pre-wrap break-words">{logs.join("\n")}</pre>{/if}<div class="flex justify-end"><Button variant="outline" data-device-action="diagnostics-logs-refresh" onclick={refreshLogs}>{t("refresh")}</Button></div><ActionResult result={logsResult} title={t("resultTitle")} {locale} /></div>
							</section>
						</div>
						{:else if deviceSubpage === "advanced"}
						<div class="device-subpage" data-device-subpage="advanced">
							<section class="device-tool-group device-tool-group-danger" data-tool-group="danger" aria-labelledby="device-group-danger">
							<div class="device-tool-group-heading"><div><h2 id="device-group-danger" class="text-sm font-semibold">{t("deviceGroupDanger")}</h2><p class="mt-1 text-xs text-muted-foreground">{t("deviceGroupDangerDescription")}</p></div></div>
								<Accordion.Item value="control"><Accordion.Trigger>{t("deviceTabControl")}</Accordion.Trigger><Accordion.Content class="flex flex-col gap-4"><Alert.Root><Alert.Title>{t("controlWarning")}</Alert.Title></Alert.Root><div class="flex flex-wrap gap-2"><Button variant="outline" data-device-action="advanced-wifi-restart" onclick={() => action((value) => controlResult = value, "/wifi?action=restart", t("confirmWifi"))}>{t("restartWifi")}</Button><Button variant="outline" data-device-action="advanced-flight-toggle" onclick={() => action((value) => controlResult = value, "/flight?action=toggle", t("confirmFlight"))}>{t("flightToggle")}</Button><Button variant="outline" data-device-action="advanced-modem-restart" onclick={() => action((value) => controlResult = value, "/modem?action=restart")}>{t("modemSoftReset")}</Button><Button variant="destructive" data-device-action="advanced-modem-hard-reset" onclick={() => action((value) => controlResult = value, "/modem?action=hardreset", t("confirmHardReset"))}>{t("modemHardReset")}</Button></div><ActionResult result={controlResult} title={t("resultTitle")} {locale} /></Accordion.Content></Accordion.Item>
						<Accordion.Item value="terminal"><Accordion.Trigger>{t("deviceTabTerminal")}</Accordion.Trigger><Accordion.Content class="flex flex-col gap-3"><p class="text-muted-foreground">{t("atDescription")}</p><form data-device-action="advanced-at-terminal" onsubmit={(event) => { event.preventDefault(); sendAtCommand(); }}><InputGroup.Root><InputGroup.Input aria-label={t("atTitle")} placeholder={t("atPlaceholder")} required bind:value={command} /><InputGroup.Addon align="inline-end"><InputGroup.Button type="submit" variant="default">{t("atSend")}</InputGroup.Button></InputGroup.Addon></InputGroup.Root></form><ActionResult result={terminalResult} title={t("resultTitle")} {locale} /></Accordion.Content></Accordion.Item>
							</section>
						</div>
						{:else}
						<div class="device-subpage" data-device-subpage="maintenance">
							<section class="device-tool-group" data-tool-group="maintenance" aria-labelledby="device-group-maintenance">
							<div class="device-tool-group-heading"><h2 id="device-group-maintenance" class="text-sm font-semibold">{t("deviceGroupMaintenance")}</h2></div>
								<Accordion.Item value="config-backup"><Accordion.Trigger>{t("configBackupTitle")}</Accordion.Trigger><Accordion.Content class="flex flex-col gap-4"><p class="text-muted-foreground">{t("configFileDescription")}</p>{#if demoMode}<Alert.Root><Alert.Title>{t("demoDisabledTitle")}</Alert.Title><Alert.Description>{t("demoDisabledBody")}</Alert.Description></Alert.Root>{/if}<Field.Group class="grid gap-5 md:grid-cols-2"><Field.Field data-disabled={demoMode}><Field.Label for="backup-passphrase">{t("backupPassphrase")}</Field.Label><Input id="backup-passphrase" type="password" minlength={12} autocomplete="new-password" disabled={demoMode} bind:value={backupPassphrase} /><Field.Description>{t("passphraseHint")}</Field.Description></Field.Field><Field.Field data-disabled={demoMode}><Field.Label for="backup-confirmation">{t("backupConfirmation")}</Field.Label><Input id="backup-confirmation" type="password" minlength={12} autocomplete="new-password" disabled={demoMode} bind:value={backupConfirmation} /></Field.Field></Field.Group><div class="flex justify-end"><Button data-device-action="maintenance-backup" disabled={demoMode || configFileResult.state === "loading"} onclick={backupConfig}>{t("backupDownload")}</Button></div><ActionResult result={configFileResult} title={t("resultTitle")} {locale} /></Accordion.Content></Accordion.Item>
							<Accordion.Item value="config-restore"><Accordion.Trigger>{t("configRestoreTitle")}</Accordion.Trigger><Accordion.Content class="flex flex-col gap-4"><p class="text-muted-foreground">{t("configFileDescription")}</p>{#if demoMode}<Alert.Root><Alert.Title>{t("demoDisabledTitle")}</Alert.Title><Alert.Description>{t("demoDisabledBody")}</Alert.Description></Alert.Root>{/if}<Field.Group class="grid gap-5 md:grid-cols-2"><Field.Field data-disabled={demoMode}><Field.Label for="restore-file">{t("restoreFile")}</Field.Label><Input id="restore-file" type="file" accept=".smscfg,application/vnd.sms-forwarding.config" disabled={demoMode} onchange={(event) => { const file = event.currentTarget.files?.[0] ?? null; restoreFile = file && file.size <= BACKUP_ENVELOPE.maxEncryptedBytes ? file : null; if (file && !restoreFile) configFileResult = { state: "error", code: "ACTION_BACKUP_TOO_LARGE", data: {}, detail: "" }; }} /></Field.Field><Field.Field data-disabled={demoMode}><Field.Label for="restore-passphrase">{t("backupPassphrase")}</Field.Label><Input id="restore-passphrase" type="password" minlength={12} autocomplete="current-password" disabled={demoMode} bind:value={restorePassphrase} /></Field.Field></Field.Group><div class="flex justify-end"><Button variant="outline" data-device-action="maintenance-restore" disabled={demoMode || !restoreFile || configFileResult.state === "loading"} onclick={restoreConfig}>{t("restoreStart")}</Button></div><ActionResult result={configFileResult} title={t("resultTitle")} {locale} /></Accordion.Content></Accordion.Item>
							<Accordion.Item value="ota"><Accordion.Trigger>{t("otaTitle")}</Accordion.Trigger><Accordion.Content class="flex flex-col gap-4"><p class="text-muted-foreground">{t("otaDescription")}</p>{#if demoMode}<Alert.Root><Alert.Title>{t("demoDisabledTitle")}</Alert.Title><Alert.Description>{t("demoDisabledBody")}</Alert.Description></Alert.Root>{/if}<Field.Field data-disabled={demoMode}><Field.Label for="ota-file">{t("otaPackage")}</Field.Label><Input id="ota-file" type="file" accept=".smsota,application/octet-stream" disabled={demoMode} onchange={(event) => otaFile = event.currentTarget.files?.[0] ?? null} /></Field.Field><Button data-device-action="maintenance-ota" disabled={demoMode || !otaFile || otaResult.state === "loading"} onclick={installOta}>{t("otaInstall")}</Button><ActionResult result={otaResult} title={t("resultTitle")} {locale} /></Accordion.Content></Accordion.Item>
							</section>
						</div>
						{/if}
						</Accordion.Root>
						{#if deviceSubpage === "diagnostics" && hasMoreLogs}<div class="flex justify-center"><Button variant="outline" data-device-action="diagnostics-logs-load-more" onclick={loadMoreLogs}>{t("loadMoreLogs")}</Button></div>{/if}
				</section>
				{:else}
					<section class="flex flex-col gap-6">
					<div><h1 class="text-2xl font-semibold tracking-tight">{t("securityTitle")}</h1><p class="mt-1 text-sm text-muted-foreground">{t("securityDescription")}</p></div>
					<Alert.Root><Alert.Title>{t("securityWarningTitle")}</Alert.Title><Alert.Description>{t("securityWarningBody")}</Alert.Description></Alert.Root>
					<section class="flex flex-col gap-5"><div><h2 class="font-semibold">{t("accountTitle")}</h2><p class="text-sm text-muted-foreground">{t("accountDescription")}</p></div><form id="security-form" onsubmit={(event) => { event.preventDefault(); void save((value) => securityResult = value, accountValues()); }}><Accordion.Root type="single" value="0">{#each snapshot.config.webAccounts as account, index (index)}<Accordion.Item value={String(index)}><Accordion.Trigger><span class="flex min-w-0 flex-1 items-center gap-3"><span class="shrink-0">{t("account")} {index + 1}</span><span class="min-w-0 flex-1 truncate text-sm font-normal text-muted-foreground">{account.username || t("commonDisabled")}</span><Badge variant={account.username ? "default" : "outline"}>{account.username ? t("commonEnabled") : t("commonDisabled")}</Badge></span></Accordion.Trigger><Accordion.Content class="pt-3"><Field.Group><Field.Field><Field.Label for={`account-user-${index}`}>{t("username")}</Field.Label><Input id={`account-user-${index}`} autocomplete="username" bind:value={account.username} /></Field.Field><Field.Field><Field.Label for={`account-pass-${index}`}>{t("password")}</Field.Label><Input id={`account-pass-${index}`} type="password" autocomplete="new-password" bind:value={account.password} /><Field.Description>{t("passwordHint")}</Field.Description></Field.Field></Field.Group></Accordion.Content></Accordion.Item>{/each}</Accordion.Root></form><div class="flex justify-end"><Button type="submit" form="security-form" disabled={securityResult.state === "loading"}>{securityResult.state === "loading" ? t("commonSaving") : t("commonSave")}</Button></div><ActionResult result={securityResult} title={t("resultTitle")} {locale} /></section>
				</section>
			{/if}
		</div>
		</div>
	{/if}
</main>

<dialog bind:this={deleteDialog} class="confirm-dialog" aria-labelledby="esim-delete-title" aria-describedby="esim-delete-description" onclick={(event) => { if (event.target === deleteDialog) closeDeleteDialog(); }} onclose={clearDeleteDialog}>
	<div class="flex flex-col gap-4">
		<div><h2 id="esim-delete-title" class="text-lg font-semibold">{t("esimDeleteTitle")}</h2><p id="esim-delete-description" class="mt-1 text-sm text-muted-foreground">{t("esimDeleteDescription")}</p></div>
		<div class="flex justify-end gap-2"><Button variant="outline" onclick={cancelDelete}>{t("esimDeleteCancel")}</Button><Button variant="destructive" onclick={confirmDelete}>{t("esimDeleteConfirm")}</Button></div>
	</div>
</dialog>

{#if snapshot}
	<footer class="px-4 py-6 text-center text-xs text-muted-foreground" aria-label="Firmware version">
		{snapshot.status.firmwareVersion}
	</footer>
{/if}
