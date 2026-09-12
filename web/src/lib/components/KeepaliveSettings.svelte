<script lang="ts">
	import { onMount } from "svelte";
	import * as Field from "$lib/components/ui/field";
	import { Button } from "$lib/components/ui/button";
	import { Spinner } from "$lib/components/ui/spinner";
	import { Input } from "$lib/components/ui/input";
	import { Textarea } from "$lib/components/ui/textarea";
	import { Switch } from "$lib/components/ui/switch";
	import ActionResult from "$lib/components/ActionResult.svelte";
	import { JobResultUnknownError, loadKeepalive, saveKeepalive, provisionKeepaliveCa, runKeepaliveAction, type KeepaliveStatus } from "$lib/api";
	import { translate, type TranslationKey } from "$lib/i18n";
	import type { Locale, UiResult } from "$lib/types";
	import { validKeepaliveUrl } from "$lib/keepalive-url.js";

	let { locale }: { locale: Locale } = $props();
	const t = (key: TranslationKey) => translate(locale, key);
	let status = $state<KeepaliveStatus | null>(null);
	let enabled = $state(false);
	let interval = $state(175);
	let traffic = $state(1);
	let url = $state("");
	type Operation = "save" | "provision" | "run" | "cancel" | "reset" | "refresh";
	const idle = (): UiResult => ({ state: "idle", code: "", data: {}, detail: "" });
	const loading = (): UiResult => ({ ...idle(), state: "loading" });
	let busyOperation = $state<Operation | null>(null);
	let busy = $derived(busyOperation !== null);
	let polling: Promise<void> | null = null;
	let results = $state<Record<Operation, UiResult>>({ save: idle(), provision: idle(), run: idle(), cancel: idle(), reset: idle(), refresh: idle() });
	const pending = (operation: Operation) => busyOperation === operation && results[operation].state === "loading";
	let dirty = $derived(status !== null && (enabled !== status.enabled || interval !== status.intervalDays || traffic !== status.trafficKB || url !== status.url));
	let active = $derived(Boolean(status?.jobQueued || status?.jobRunning));
	let urlInvalid = $derived(status?.action === 1 && !validKeepaliveUrl(url));
	let usesHttps = $derived(url.startsWith("https://"));

	async function refresh(draft = false) {
		if (polling) await polling;
		if (busyOperation === "refresh") results.refresh = loading();
		const pending = (async () => {
			try {
				status = await loadKeepalive();
				if (draft) { enabled = status.enabled; interval = status.intervalDays; traffic = status.trafficKB; url = status.url; }
				results.refresh = idle();
			} catch (error) { failed("refresh", error); }
		})();
		polling = pending;
		await pending;
		if (polling === pending) polling = null;
	}

	function failed(operation: Operation, error: unknown) {
		results[operation] = { state: "error", code: error instanceof JobResultUnknownError ? "ACTION_JOB_RESULT_UNKNOWN" : "ACTION_REQUEST_FAILED", data: {}, detail: "" };
	}

	async function reload() {
		if (busy) return;
		busyOperation = "refresh";
		results.refresh = loading();
		try { await refresh(status === null); }
		finally { busyOperation = null; }
	}

	async function save() {
		if (busy) return;
		busyOperation = "save";
		results.save = loading();
		try {
			const response = await saveKeepalive(enabled, interval, traffic, url);
			results.save = { ...response, state: response.success ? "success" : "error" };
			if (response.success) await refresh(true);
		} catch (error) { failed("save", error); }
		finally { busyOperation = null; }
	}

	async function provision() {
		if (busy) return;
		busyOperation = "provision";
		results.provision = loading();
		try {
			const response = await provisionKeepaliveCa();
			results.provision = { ...response, state: response.success ? "success" : "error" };
			await refresh();
		} catch (error) { failed("provision", error); }
		finally { busyOperation = null; }
	}

	async function action(name: "run" | "cancel" | "reset") {
		if (busy) return;
		busyOperation = name;
		results[name] = loading();
		try {
			const response = await runKeepaliveAction(name);
			results[name] = { state: response.success ? "success" : "error", code: response.success ? "ACTION_KEEPALIVE_ACCEPTED" : "ACTION_KEEPALIVE_FAILED", data: {}, detail: response.message };
			await refresh();
		} catch (error) { failed(name, error); }
		finally { busyOperation = null; }
	}

	onMount(() => {
		void reload();
		const timer = setInterval(() => { if (active && !busy && !polling) void refresh(); }, 2000);
		return () => clearInterval(timer);
	});
</script>

<div class="flex flex-col gap-5">
	<p class="text-sm text-muted-foreground">{t("keepaliveSafety")}</p>
	{#if status}
		<form data-device-action="keepalive-save" onsubmit={(event) => { event.preventDefault(); void save(); }}>
			<Field.Group>
				<Field.Field orientation="horizontal">
					<Field.Label for="keepalive-enabled">{t("keepaliveSchedule")}</Field.Label>
					<Switch id="keepalive-enabled" bind:checked={enabled} disabled={busy} />
				</Field.Field>
				<Field.Field>
					<Field.Label for="keepalive-days">{t("keepaliveIntervalDays")}</Field.Label>
					<Input id="keepalive-days" type="number" min={1} max={3650} required bind:value={interval} disabled={busy} />
				</Field.Field>
				{#if status.action === 1}
					<Field.Field data-invalid={urlInvalid}>
						<Field.Label for="keepalive-url">{t("keepaliveUrl")}</Field.Label>
						<Input id="keepalive-url" type="url" maxlength={256} bind:value={url} aria-invalid={urlInvalid} disabled={busy} />
						<Field.Description>{t("keepaliveUrlHint")}</Field.Description>
						{#if urlInvalid}<Field.Error>{t("keepaliveHttpsRequired")}</Field.Error>{/if}
					</Field.Field>
					<Field.Field>
						<Field.Label for="keepalive-traffic">{t("keepaliveTrafficTarget")}</Field.Label>
						<Input id="keepalive-traffic" type="number" min={1} max={enabled ? 512 : 10000} required bind:value={traffic} disabled={busy} />
						<Field.Description>{t("keepaliveBudget")}</Field.Description>
					</Field.Field>
				{:else}
					<p class="text-sm text-muted-foreground">{t("keepaliveExistingAction").replace("{value}", String(status.action))}</p>
				{/if}
				<div class="grid gap-3 sm:grid-cols-2">
					<div class="flex min-w-0 flex-col gap-2" data-keepalive-operation="save">
						{#if results.save.state !== "loading"}<ActionResult result={results.save} title={t("commonSave")} {locale} />{/if}
						<Button class="self-end" type="submit" aria-busy={pending("save")} disabled={busy || (enabled && status.action === 1 && urlInvalid)}>{#if pending("save")}<Spinner data-icon="inline-start" aria-hidden="true" />{/if}{pending("save") ? t("commonSaving") : t("commonSave")}</Button>
					</div>
					{#if status.action === 1 && usesHttps}
						<div class="flex min-w-0 flex-col gap-2" data-keepalive-operation="provision">
							{#if results.provision.state !== "loading"}<ActionResult result={results.provision} title={t("keepaliveCaSetup")} {locale} />{/if}
							<Button class="self-end" variant="outline" aria-busy={pending("provision")} disabled={busy || active || dirty || urlInvalid} onclick={() => void provision()}>{#if pending("provision")}<Spinner data-icon="inline-start" aria-hidden="true" />{/if}{t("keepaliveCaSetup")}</Button>
						</div>
					{/if}
				</div>
			</Field.Group>
		</form>
		{#if status.action === 1}<p class="text-sm text-muted-foreground">{t(usesHttps ? "keepaliveCaHint" : "keepaliveHttpHint")}</p>{/if}
		<div role="status" aria-live="polite" class="flex flex-col gap-2 text-sm">
			<p>{active ? status.cancelRequested ? t("keepaliveCancelling") : t("keepaliveRunning") : status.jobDone ? status.jobSuccess ? t("keepaliveSucceeded") : t("keepaliveFailed") : status.ready ? t("keepaliveReady") : t("keepaliveNotReady")}</p>
			<p>{t("keepaliveProgress").replace("{bytes}", String(status.bodyBytes)).replace("{requests}", String(status.requests))}</p>
			<p>{t("keepaliveLastRun")}: {status.lastTimeLocal || t("commonNotAvailable")}</p>
			{#if status.jobMessage || status.readinessMessage}<details><summary class="cursor-pointer">{t("keepaliveDetails")}</summary><Textarea readonly aria-label={t("keepaliveDetails")} class="mt-2 field-sizing-fixed h-48 max-h-[60dvh] font-mono" value={status.jobMessage || status.readinessMessage} /></details>{/if}
		</div>
		<div class="grid gap-3 sm:grid-cols-3">
			<div class="flex min-w-0 flex-col gap-2" data-keepalive-operation="reset">
				{#if results.reset.state !== "loading"}<ActionResult result={results.reset} title={t("keepaliveReset")} {locale} />{/if}
				<Button class="self-end" variant="outline" aria-busy={pending("reset")} disabled={busy || active || !status.timeValid} onclick={() => void action("reset")}>{#if pending("reset")}<Spinner data-icon="inline-start" aria-hidden="true" />{/if}{t("keepaliveReset")}</Button>
			</div>
			<div class="flex min-w-0 flex-col gap-2" data-keepalive-operation="run">
				{#if results.run.state !== "loading"}<ActionResult result={results.run} title={t("keepaliveRun")} {locale} />{/if}
				<Button class="self-end" aria-busy={pending("run")} disabled={busy || active || dirty || !status.ready} onclick={() => void action("run")}>{#if pending("run")}<Spinner data-icon="inline-start" aria-hidden="true" />{/if}{t("keepaliveRun")}</Button>
			</div>
			{#if status.action === 1 && (active || busyOperation === "cancel" || results.cancel.state !== "idle")}
				<div class="flex min-w-0 flex-col gap-2" data-keepalive-operation="cancel">
					{#if results.cancel.state !== "loading"}<ActionResult result={results.cancel} title={t("keepaliveCancel")} {locale} />{/if}
					<Button class="self-end" variant="destructive" aria-busy={pending("cancel")} disabled={busy || !active || status.cancelRequested} onclick={() => void action("cancel")}>{#if pending("cancel")}<Spinner data-icon="inline-start" aria-hidden="true" />{/if}{t("keepaliveCancel")}</Button>
				</div>
			{/if}
		</div>
	{/if}
	<div class="flex min-w-0 flex-col gap-2" data-keepalive-operation="refresh">
		{#if results.refresh.state !== "loading"}<ActionResult result={results.refresh} title={t("keepaliveRefresh")} {locale} />{/if}
		<Button class="self-end" variant="outline" aria-busy={pending("refresh")} disabled={busy} onclick={() => void reload()}>{#if pending("refresh")}<Spinner data-icon="inline-start" aria-hidden="true" />{/if}{results.refresh.state === "error" ? t("retry") : t("keepaliveRefresh")}</Button>
	</div>
</div>
