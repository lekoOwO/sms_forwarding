<script lang="ts">
	import { onMount } from "svelte";
	import * as Field from "$lib/components/ui/field";
	import { Button } from "$lib/components/ui/button";
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
	let busy = $state(false);
	let polling = false;
	let result = $state<UiResult>({ state: "idle", code: "", data: {}, detail: "" });
	let dirty = $derived(status !== null && (enabled !== status.enabled || interval !== status.intervalDays || traffic !== status.trafficKB || url !== status.url));
	let active = $derived(Boolean(status?.jobQueued || status?.jobRunning));
	let urlInvalid = $derived(status?.action === 1 && !validKeepaliveUrl(url));
	let usesHttps = $derived(url.startsWith("https://"));

	async function refresh(draft = false) {
		if (polling) return;
		polling = true;
		try {
			status = await loadKeepalive();
			if (draft) { enabled = status.enabled; interval = status.intervalDays; traffic = status.trafficKB; url = status.url; }
		} finally { polling = false; }
	}

	function failed(error: unknown) {
		result = { state: "error", code: error instanceof JobResultUnknownError ? "ACTION_JOB_RESULT_UNKNOWN" : "ACTION_REQUEST_FAILED", data: {}, detail: "" };
	}

	async function save() {
		busy = true;
		result = { state: "loading", code: "ACTION_JOB_ACCEPTED", data: {}, detail: "" };
		try {
			const response = await saveKeepalive(enabled, interval, traffic, url);
			result = { ...response, state: response.success ? "success" : "error" };
			if (response.success) await refresh(true);
		} catch (error) { failed(error); }
		finally { busy = false; }
	}

	async function provision() {
		busy = true;
		result = { state: "loading", code: "ACTION_JOB_ACCEPTED", data: {}, detail: "" };
		try {
			const response = await provisionKeepaliveCa();
			result = { ...response, state: response.success ? "success" : "error" };
			await refresh();
		} catch (error) { failed(error); }
		finally { busy = false; }
	}

	async function action(name: "run" | "cancel" | "reset") {
		busy = true;
		try {
			const response = await runKeepaliveAction(name);
			result = { state: response.success ? "success" : "error", code: response.success ? "ACTION_KEEPALIVE_ACCEPTED" : "ACTION_KEEPALIVE_FAILED", data: {}, detail: response.message };
			await refresh();
		} catch (error) { failed(error); }
		finally { busy = false; }
	}

	onMount(() => {
		void refresh(true).catch(failed);
		const timer = setInterval(() => { if (active && !busy) void refresh().catch(failed); }, 2000);
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
				<ActionResult {result} title={t("resultTitle")} {locale} />
				<div class="flex flex-wrap justify-end gap-2">
					<Button type="submit" disabled={busy || (enabled && status.action === 1 && urlInvalid)}>{busy ? t("commonSaving") : t("commonSave")}</Button>
					{#if status.action === 1 && usesHttps}<Button variant="outline" disabled={busy || active || dirty || urlInvalid} onclick={() => void provision()}>{t("keepaliveCaSetup")}</Button>{/if}
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
		<div class="flex flex-wrap justify-end gap-2">
			<Button variant="outline" disabled={busy || active || !status.timeValid} onclick={() => void action("reset")}>{t("keepaliveReset")}</Button>
			<Button variant="outline" disabled={busy} onclick={() => void refresh().catch(failed)}>{t("keepaliveRefresh")}</Button>
			{#if active && status.action === 1}
				<Button variant="destructive" disabled={busy || status.cancelRequested} onclick={() => void action("cancel")}>{t("keepaliveCancel")}</Button>
			{:else}
				<Button disabled={busy || active || dirty || !status.ready} onclick={() => void action("run")}>{t("keepaliveRun")}</Button>
			{/if}
		</div>
	{/if}
</div>
