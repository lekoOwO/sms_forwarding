<script lang="ts">
	import { onMount } from "svelte";
	import MoonIcon from "@lucide/svelte/icons/moon";
	import SunIcon from "@lucide/svelte/icons/sun";
	import ActionResult from "$lib/components/ActionResult.svelte";
	import * as Accordion from "$lib/components/ui/accordion";
	import * as Alert from "$lib/components/ui/alert";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import * as Empty from "$lib/components/ui/empty";
	import * as Field from "$lib/components/ui/field";
	import { Input } from "$lib/components/ui/input";
	import * as InputGroup from "$lib/components/ui/input-group";
	import * as NativeSelect from "$lib/components/ui/native-select";
	import * as NavigationMenu from "$lib/components/ui/navigation-menu";
	import { Separator } from "$lib/components/ui/separator";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { Switch } from "$lib/components/ui/switch";
	import * as Tabs from "$lib/components/ui/tabs";
	import { Textarea } from "$lib/components/ui/textarea";
	import { loadLogs, loadSnapshot, postForm, runAction } from "$lib/api";
	import { detectLocale, translate, type TranslationKey } from "$lib/i18n";
	import type { DeviceSnapshot, Locale, UiResult } from "$lib/types";

	type MainTab = "overview" | "notifications" | "messaging" | "device" | "security";
	type Theme = "light" | "dark";

	const idle = (): UiResult => ({ state: "idle", code: "", data: {}, detail: "" });
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
		"Telegram"
	];
	const navigation: { value: MainTab; label: TranslationKey }[] = [
		{ value: "overview", label: "navOverview" },
		{ value: "notifications", label: "navNotifications" },
		{ value: "messaging", label: "navMessaging" },
		{ value: "device", label: "navDevice" },
		{ value: "security", label: "navSecurity" }
	];

	let locale = $state<Locale>("zh-TW");
	let mainTab = $state<MainTab>("overview");
	let pushTab = $state("0");
	let theme = $state<Theme>("light");
	let snapshot = $state<DeviceSnapshot | null>(null);
	let loading = $state(true);
	let loadError = $state("");
	let emailResult = $state(idle());
	let pushResult = $state(idle());
	let routingResult = $state(idle());
	let securityResult = $state(idle());
	let smsResult = $state(idle());
	let overviewResult = $state(idle());
	let diagnosticsResult = $state(idle());
	let networkResult = $state(idle());
	let controlResult = $state(idle());
	let terminalResult = $state(idle());
	let logsResult = $state(idle());
	let phone = $state("");
	let message = $state("");
	let command = $state("");
	let logs = $state<string[]>([]);
	let autoRefresh = $state(false);

	const t = (key: TranslationKey) => translate(locale, key);

	onMount(() => {
		const saved = localStorage.getItem("locale") as Locale | null;
		locale = saved && ["zh-TW", "zh-CN", "en"].includes(saved) ? saved : detectLocale(navigator.language);
		const savedTheme = localStorage.getItem("theme") as Theme | null;
		theme = savedTheme && ["light", "dark"].includes(savedTheme)
			? savedTheme
			: matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
		document.documentElement.classList.toggle("dark", theme === "dark");
		void refreshSnapshot();
	});

	$effect(() => {
		if (typeof document === "undefined") return;
		document.documentElement.lang = locale;
		localStorage.setItem("locale", locale);
	});

	$effect(() => {
		if (!autoRefresh || mainTab !== "device") return;
		const timer = window.setInterval(refreshLogs, 2000);
		return () => window.clearInterval(timer);
	});

	async function refreshSnapshot() {
		loading = true;
		loadError = "";
		try {
			snapshot = await loadSnapshot();
		} catch (error) {
			loadError = error instanceof Error ? error.message : String(error);
		} finally {
			loading = false;
		}
	}

	async function save(setResult: (value: UiResult) => void, values: Record<string, string | number | boolean>) {
		setResult({ state: "loading", code: "commonSaving", data: {}, detail: "" });
		try {
			const response = await postForm("/save", values);
			setResult({ state: response.success ? "success" : "error", code: response.code, data: response.data, detail: response.detail });
			if (response.success) await refreshSnapshot();
		} catch (error) {
			setResult({ state: "error", code: "ACTION_REQUEST_FAILED", data: {}, detail: error instanceof Error ? error.message : String(error) });
		}
	}

	async function action(setResult: (value: UiResult) => void, path: string, confirmText?: string, init?: RequestInit) {
		if (confirmText && !window.confirm(confirmText)) return;
		setResult({ state: "loading", code: "commonRunning", data: {}, detail: "" });
		try {
			const response = await runAction(path, init);
			setResult({ state: response.success ? "success" : "error", code: response.code, data: response.data, detail: response.detail });
		} catch (error) {
			setResult({ state: "error", code: "ACTION_REQUEST_FAILED", data: {}, detail: error instanceof Error ? error.message : String(error) });
		}
	}

	async function sendSms() {
		smsResult = { state: "loading", code: "sending", data: {}, detail: "" };
		try {
			const response = await postForm("/sendsms", { phone, content: message });
			smsResult = { state: response.success ? "success" : "error", code: response.code, data: response.data, detail: response.detail };
			if (response.success) message = "";
		} catch (error) {
			smsResult = { state: "error", code: "ACTION_REQUEST_FAILED", data: {}, detail: error instanceof Error ? error.message : String(error) };
		}
	}

	async function refreshLogs() {
		try {
			logs = await loadLogs();
			logsResult = idle();
		} catch (error) {
			logsResult = { state: "error", code: "ACTION_LOGS_FAILED", data: {}, detail: error instanceof Error ? error.message : String(error) };
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

	function keyLabels(type: number): [string, string] {
		if (type === 4 || type === 8) return [t("keySecret"), t("providerParam2")];
		if (type === 5) return [t("keyToken"), t("keyChannel")];
		if (type === 6) return [t("keySendKey"), t("providerParam2")];
		if (type === 9) return [t("keyToken"), t("providerParam2")];
		if (type === 10) return [t("keyChatId"), t("keyBotToken")];
		return [t("providerParam1"), t("providerParam2")];
	}

	function pushValues() {
		const values: Record<string, string | number | boolean> = {};
		snapshot?.config.pushChannels.forEach((channel, index) => {
			values[`push${index}en`] = channel.enabled;
			values[`push${index}type`] = channel.type;
			values[`push${index}name`] = channel.name;
			values[`push${index}url`] = channel.url;
			values[`push${index}key1`] = channel.key1;
			values[`push${index}key2`] = channel.key2;
			values[`push${index}body`] = channel.customBody;
		});
		return values;
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
	<title>{t("appName")}</title>
	<meta name="description" content={t("appSubtitle")} />
</svelte:head>

<header class="border-b bg-background/95 supports-[backdrop-filter]:bg-background/80 sticky top-0 z-20 backdrop-blur">
	<div class="mx-auto flex h-20 max-w-6xl items-center justify-between gap-4 px-4 sm:px-6">
		<div class="min-w-0">
			<p class="truncate text-lg font-semibold tracking-tight sm:text-2xl">{t("appName")}</p>
			<p class="truncate text-sm text-muted-foreground">{t("appSubtitle")}</p>
		</div>
		<div class="flex items-center gap-2">
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

<main class="mx-auto max-w-6xl px-4 py-6 sm:px-6 sm:py-10">
	{#if loading}
		<div class="flex flex-col gap-6" aria-live="polite">
			<div class="flex flex-col gap-2">
				<Skeleton class="h-7 w-52" />
				<Skeleton class="h-4 w-80 max-w-full" />
			</div>
			<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
				{#each Array(4) as _}<Skeleton class="h-28" />{/each}
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
		<div class="flex flex-col gap-8">
			<div class="overflow-x-auto pb-1">
				<NavigationMenu.Root viewport={false} class="max-w-none">
					<NavigationMenu.List class="w-max justify-start">
						{#each navigation as item}
							<NavigationMenu.Item>
								<NavigationMenu.Link
									href={`#${item.value}`}
									data-active={mainTab === item.value ? "" : undefined}
									aria-current={mainTab === item.value ? "page" : undefined}
									onclick={(event) => { event.preventDefault(); mainTab = item.value; }}
								>{t(item.label)}</NavigationMenu.Link>
							</NavigationMenu.Item>
						{/each}
					</NavigationMenu.List>
				</NavigationMenu.Root>
			</div>

			{#if mainTab === "overview"}
				<section class="flex flex-col gap-6">
					<div><h1 class="text-2xl font-semibold tracking-tight">{t("overviewTitle")}</h1><p class="mt-1 text-sm text-muted-foreground">{t("overviewDescription")}</p></div>
					<dl class="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
						{#each [
							[t("overviewIp"), snapshot.status.ip],
							[t("overviewWifi"), snapshot.status.wifiSsid || t("commonUnknown")],
							[t("overviewHeap"), `${snapshot.status.freeHeapKb} KB`],
							[t("overviewUptime"), formatUptime(snapshot.status.uptimeSeconds)]
						] as item}
							<div class="min-w-0 border-l-2 pl-4">
								<dt class="text-sm text-muted-foreground">{item[0]}</dt>
								<dd class="mt-1 truncate text-lg font-semibold tabular-nums" title={item[1]}>{item[1]}</dd>
							</div>
						{/each}
					</dl>
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
					<Accordion.Root type="single" value="email">
						<Accordion.Item value="email"><Accordion.Trigger>{t("emailTitle")}<Badge variant={snapshot.status.emailConfigured ? "default" : "outline"}>{snapshot.status.emailConfigured ? t("commonConfigured") : t("commonNotConfigured")}</Badge></Accordion.Trigger><Accordion.Content class="flex flex-col gap-5"><p class="text-muted-foreground">{t("emailDescription")}</p><form id="email-form" onsubmit={(event) => { event.preventDefault(); const c = snapshot!.config; void save((v) => emailResult = v, { smtpServer: c.smtpServer, smtpPort: c.smtpPort, smtpUser: c.smtpUser, ...(c.smtpPass ? { smtpPass: c.smtpPass } : {}), smtpSendTo: c.smtpSendTo }); }}><Field.Group class="grid gap-5 md:grid-cols-2"><Field.Field><Field.Label for="smtp-server">{t("smtpServer")}</Field.Label><Input id="smtp-server" bind:value={snapshot.config.smtpServer} /></Field.Field><Field.Field><Field.Label for="smtp-port">{t("smtpPort")}</Field.Label><Input id="smtp-port" type="number" min="1" max="65535" bind:value={snapshot.config.smtpPort} /></Field.Field><Field.Field><Field.Label for="smtp-user">{t("smtpUser")}</Field.Label><Input id="smtp-user" type="email" bind:value={snapshot.config.smtpUser} /></Field.Field><Field.Field><Field.Label for="smtp-pass">{t("smtpPassword")}</Field.Label><Input id="smtp-pass" type="password" autocomplete="new-password" bind:value={snapshot.config.smtpPass} /><Field.Description>{t("smtpPasswordHint")}</Field.Description></Field.Field><Field.Field class="md:col-span-2"><Field.Label for="smtp-to">{t("smtpRecipient")}</Field.Label><Input id="smtp-to" type="email" bind:value={snapshot.config.smtpSendTo} /></Field.Field></Field.Group></form><div class="flex items-center justify-between gap-4"><div class="min-w-0 flex-1"><ActionResult result={emailResult} title={t("resultTitle")} {locale} /></div><Button type="submit" form="email-form" disabled={emailResult.state === "loading"}>{emailResult.state === "loading" ? t("commonSaving") : t("commonSave")}</Button></div></Accordion.Content></Accordion.Item>
						<Accordion.Item value="push"><Accordion.Trigger>{t("pushTitle")}<Badge variant={snapshot.status.enabledPushChannels > 0 ? "default" : "outline"}>{snapshot.status.enabledPushChannels} / 5</Badge></Accordion.Trigger><Accordion.Content class="flex flex-col gap-5"><p class="text-muted-foreground">{t("pushDescription")}</p><Tabs.Root bind:value={pushTab} class="flex flex-col gap-6"><div class="overflow-x-auto pb-1"><Tabs.List class="min-w-max">{#each snapshot.config.pushChannels as channel, index}<Tabs.Trigger value={String(index)} class={channel.enabled ? "bg-primary text-primary-foreground data-[state=active]:bg-primary data-[state=active]:text-primary-foreground" : ""}>{channel.name || `${t("pushChannel")} ${index + 1}`}<Badge variant={channel.enabled ? "secondary" : "outline"}>{channel.enabled ? t("commonEnabled") : t("commonDisabled")}</Badge></Tabs.Trigger>{/each}</Tabs.List></div>{#each snapshot.config.pushChannels as channel, index}<Tabs.Content value={String(index)}><Field.Group class="grid gap-5 md:grid-cols-2"><Field.Field orientation="horizontal" class="md:col-span-2"><Field.Label for={`push-enabled-${index}`}>{t("channelEnabled")}</Field.Label><Switch id={`push-enabled-${index}`} bind:checked={channel.enabled} /></Field.Field><Field.Field><Field.Label for={`push-name-${index}`}>{t("channelName")}</Field.Label><Input id={`push-name-${index}`} bind:value={channel.name} /></Field.Field><Field.Field><Field.Label for={`push-type-${index}`}>{t("providerType")}</Field.Label><NativeSelect.Root id={`push-type-${index}`} class="w-full" bind:value={channel.type}>{#each providers as provider, providerIndex}<NativeSelect.Option value={providerIndex + 1}>{provider}</NativeSelect.Option>{/each}</NativeSelect.Root><Field.Description>{providerHint(channel.type)}</Field.Description></Field.Field><Field.Field class="md:col-span-2"><Field.Label for={`push-url-${index}`}>{t("endpoint")}</Field.Label><Input id={`push-url-${index}`} type="url" bind:value={channel.url} /></Field.Field>{#if [4, 5, 6, 8, 9, 10].includes(channel.type)}<Field.Field><Field.Label for={`push-key1-${index}`}>{keyLabels(channel.type)[0]}</Field.Label><Input id={`push-key1-${index}`} bind:value={channel.key1} /></Field.Field><Field.Field><Field.Label for={`push-key2-${index}`}>{keyLabels(channel.type)[1]}</Field.Label><Input id={`push-key2-${index}`} bind:value={channel.key2} /></Field.Field>{/if}{#if channel.type === 7}<Field.Field class="md:col-span-2"><Field.Label for={`push-body-${index}`}>{t("customBody")}</Field.Label><Textarea id={`push-body-${index}`} rows={5} class="font-mono" bind:value={channel.customBody} /><Field.Description>{t("customBodyHint")}</Field.Description></Field.Field>{/if}</Field.Group></Tabs.Content>{/each}</Tabs.Root><div class="flex items-center justify-between gap-4"><div class="min-w-0 flex-1"><ActionResult result={pushResult} title={t("resultTitle")} {locale} /></div><Button onclick={() => save((v) => pushResult = v, pushValues())} disabled={pushResult.state === "loading"}>{pushResult.state === "loading" ? t("commonSaving") : t("commonSave")}</Button></div></Accordion.Content></Accordion.Item>
					</Accordion.Root>
				</section>
			{:else if mainTab === "messaging"}
				<section class="flex flex-col gap-6">
					<div><h1 class="text-2xl font-semibold tracking-tight">{t("messagingTitle")}</h1><p class="mt-1 text-sm text-muted-foreground">{t("messagingDescription")}</p></div>
					<Accordion.Root type="single" value="sms">
						<Accordion.Item value="sms"><Accordion.Trigger>{t("sendSmsTitle")}</Accordion.Trigger><Accordion.Content class="flex flex-col gap-5"><p class="text-muted-foreground">{t("sendSmsDescription")}</p><form id="sms-form" onsubmit={(event) => { event.preventDefault(); void sendSms(); }}><Field.Group><Field.Field><Field.Label for="sms-phone">{t("targetPhone")}</Field.Label><Input id="sms-phone" type="tel" required bind:value={phone} /></Field.Field><Field.Field><Field.Label for="sms-message">{t("smsContent")}</Field.Label><Textarea id="sms-message" rows={8} required bind:value={message} /></Field.Field></Field.Group></form><div class="flex items-center justify-between gap-4"><div class="min-w-0 flex-1"><ActionResult result={smsResult} title={t("resultTitle")} {locale} /></div><Button type="submit" form="sms-form" disabled={smsResult.state === "loading"}>{smsResult.state === "loading" ? t("sending") : t("send")}</Button></div></Accordion.Content></Accordion.Item>
						<Accordion.Item value="routing"><Accordion.Trigger>{t("routingTitle")}</Accordion.Trigger><Accordion.Content class="flex flex-col gap-5"><p class="text-muted-foreground">{t("routingDescription")}</p><form id="routing-form" onsubmit={(event) => { event.preventDefault(); const c = snapshot!.config; void save((v) => routingResult = v, { adminPhone: c.adminPhone, numberBlackList: c.numberBlackList }); }}><Field.Group><Field.Field><Field.Label for="admin-phone">{t("adminPhone")}</Field.Label><Input id="admin-phone" type="tel" bind:value={snapshot.config.adminPhone} /><Field.Description>{t("adminPhoneHint")}</Field.Description></Field.Field><Field.Field><Field.Label for="blocklist">{t("blacklist")}</Field.Label><Textarea id="blocklist" rows={6} bind:value={snapshot.config.numberBlackList} /><Field.Description>{t("blacklistHint")}</Field.Description></Field.Field></Field.Group></form><div class="flex items-center justify-between gap-4"><div class="min-w-0 flex-1"><ActionResult result={routingResult} title={t("resultTitle")} {locale} /></div><Button type="submit" form="routing-form" disabled={routingResult.state === "loading"}>{routingResult.state === "loading" ? t("commonSaving") : t("commonSave")}</Button></div></Accordion.Content></Accordion.Item>
					</Accordion.Root>
				</section>
			{:else if mainTab === "device"}
				<section class="flex flex-col gap-6">
					<div><h1 class="text-2xl font-semibold tracking-tight">{t("deviceTitle")}</h1><p class="mt-1 text-sm text-muted-foreground">{t("deviceDescription")}</p></div>
					<Accordion.Root type="single" value="diagnostics">
						<Accordion.Item value="diagnostics"><Accordion.Trigger>{t("deviceTabDiagnostics")}</Accordion.Trigger><Accordion.Content class="flex flex-col gap-4"><div class="flex flex-wrap gap-2"><Button variant="outline" onclick={() => action((value) => diagnosticsResult = value, "/query?type=ati")}>{t("modemInfo")}</Button><Button variant="outline" onclick={() => action((value) => diagnosticsResult = value, "/query?type=signal")}>{t("signal")}</Button><Button variant="outline" onclick={() => action((value) => diagnosticsResult = value, "/query?type=siminfo")}>{t("simInfo")}</Button><Button variant="outline" onclick={() => action((value) => diagnosticsResult = value, "/modem?action=signal")}>{t("modemSignal")}</Button><Button variant="outline" onclick={() => action((value) => diagnosticsResult = value, "/modem?action=operator")}>{t("operator")}</Button><Button variant="outline" onclick={() => action((value) => diagnosticsResult = value, "/modem?action=imei")}>{t("imei")}</Button></div><ActionResult result={diagnosticsResult} title={t("resultTitle")} {locale} /></Accordion.Content></Accordion.Item>
						<Accordion.Item value="network"><Accordion.Trigger>{t("deviceTabNetwork")}</Accordion.Trigger><Accordion.Content class="flex flex-col gap-4"><div class="flex flex-wrap gap-2"><Button variant="outline" onclick={() => action((value) => networkResult = value, "/query?type=network")}>{t("networkState")}</Button><Button variant="outline" onclick={() => action((value) => networkResult = value, "/query?type=wifi")}>{t("wifiState")}</Button><Button variant="outline" onclick={() => action((value) => networkResult = value, "/flight?action=query")}>{t("flightQuery")}</Button><Button onclick={() => action((value) => networkResult = value, "/ping", t("confirmPing"), { method: "POST" })}>{t("ping")}</Button></div><ActionResult result={networkResult} title={t("resultTitle")} {locale} /></Accordion.Content></Accordion.Item>
						<Accordion.Item value="control"><Accordion.Trigger>{t("deviceTabControl")}</Accordion.Trigger><Accordion.Content class="flex flex-col gap-4"><Alert.Root><Alert.Title>{t("controlWarning")}</Alert.Title></Alert.Root><div class="flex flex-wrap gap-2"><Button variant="outline" onclick={() => action((value) => controlResult = value, "/wifi?action=restart", t("confirmWifi"))}>{t("restartWifi")}</Button><Button variant="outline" onclick={() => action((value) => controlResult = value, "/flight?action=toggle", t("confirmFlight"))}>{t("flightToggle")}</Button><Button variant="outline" onclick={() => action((value) => controlResult = value, "/modem?action=restart")}>{t("modemSoftReset")}</Button><Button variant="destructive" onclick={() => action((value) => controlResult = value, "/modem?action=hardreset", t("confirmHardReset"))}>{t("modemHardReset")}</Button></div><ActionResult result={controlResult} title={t("resultTitle")} {locale} /></Accordion.Content></Accordion.Item>
						<Accordion.Item value="terminal"><Accordion.Trigger>{t("deviceTabTerminal")}</Accordion.Trigger><Accordion.Content class="flex flex-col gap-3"><p class="text-muted-foreground">{t("atDescription")}</p><form onsubmit={(event) => { event.preventDefault(); void action((value) => terminalResult = value, `/at?cmd=${encodeURIComponent(command)}`); }}><InputGroup.Root><InputGroup.Input aria-label={t("atTitle")} placeholder={t("atPlaceholder")} required bind:value={command} /><InputGroup.Addon align="inline-end"><InputGroup.Button type="submit" variant="default">{t("atSend")}</InputGroup.Button></InputGroup.Addon></InputGroup.Root></form><ActionResult result={terminalResult} title={t("resultTitle")} {locale} /></Accordion.Content></Accordion.Item>
						<Accordion.Item value="logs"><Accordion.Trigger onclick={refreshLogs}>{t("deviceTabLogs")}</Accordion.Trigger><Accordion.Content class="flex flex-col gap-4"><Field.Field orientation="horizontal"><Field.Label for="auto-refresh">{t("autoRefresh")}</Field.Label><Switch id="auto-refresh" size="sm" bind:checked={autoRefresh} /></Field.Field>{#if logs.length === 0}<Empty.Root><Empty.Header><Empty.Title>{t("emptyLog")}</Empty.Title></Empty.Header><Empty.Content><Button variant="outline" onclick={refreshLogs}>{t("refresh")}</Button></Empty.Content></Empty.Root>{:else}<pre class="max-h-[28rem] overflow-auto rounded-lg bg-muted p-4 text-xs whitespace-pre-wrap break-words">{logs.join("\n")}</pre><div class="flex justify-end"><Button variant="outline" onclick={refreshLogs}>{t("refresh")}</Button></div>{/if}<ActionResult result={logsResult} title={t("resultTitle")} {locale} /></Accordion.Content></Accordion.Item>
					</Accordion.Root>
				</section>
			{:else}
				<section class="flex flex-col gap-6">
					<div><h1 class="text-2xl font-semibold tracking-tight">{t("securityTitle")}</h1><p class="mt-1 text-sm text-muted-foreground">{t("securityDescription")}</p></div>
					<Alert.Root><Alert.Title>{t("securityWarningTitle")}</Alert.Title><Alert.Description>{t("securityWarningBody")}</Alert.Description></Alert.Root>
					<section class="flex flex-col gap-5"><div><h2 class="font-semibold">{t("accountTitle")}</h2><p class="text-sm text-muted-foreground">{t("accountDescription")}</p></div><form id="security-form" onsubmit={(event) => { event.preventDefault(); void save((value) => securityResult = value, accountValues()); }}><Accordion.Root type="single" value="0">{#each snapshot.config.webAccounts as account, index}<Accordion.Item value={String(index)}><Accordion.Trigger><span class="flex min-w-0 flex-1 items-center gap-3"><span class="shrink-0">{t("account")} {index + 1}</span><span class="min-w-0 flex-1 truncate text-sm font-normal text-muted-foreground">{account.username || t("commonDisabled")}</span><Badge variant={account.username ? "default" : "outline"}>{account.username ? t("commonEnabled") : t("commonDisabled")}</Badge></span></Accordion.Trigger><Accordion.Content class="pt-3"><Field.Group><Field.Field><Field.Label for={`account-user-${index}`}>{t("username")}</Field.Label><Input id={`account-user-${index}`} autocomplete="username" bind:value={account.username} /></Field.Field><Field.Field><Field.Label for={`account-pass-${index}`}>{t("password")}</Field.Label><Input id={`account-pass-${index}`} type="password" autocomplete="new-password" bind:value={account.password} /><Field.Description>{t("passwordHint")}</Field.Description></Field.Field></Field.Group></Accordion.Content></Accordion.Item>{/each}</Accordion.Root></form><div class="flex items-center justify-between gap-4"><div class="min-w-0 flex-1"><ActionResult result={securityResult} title={t("resultTitle")} {locale} /></div><Button type="submit" form="security-form" disabled={securityResult.state === "loading"}>{securityResult.state === "loading" ? t("commonSaving") : t("commonSave")}</Button></div></section>
				</section>
			{/if}
		</div>
	{/if}
</main>
