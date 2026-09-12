<script lang="ts">
	import InfoIcon from "@lucide/svelte/icons/info";
	import * as Field from "$lib/components/ui/field";
	import * as NativeSelect from "$lib/components/ui/native-select";
	import * as Alert from "$lib/components/ui/alert";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Textarea } from "$lib/components/ui/textarea";
	import { Switch } from "$lib/components/ui/switch";
	import { CSV_PREFIX, migrateRules, parseRules, serializeRules } from "$lib/forward-rules.js";
	import { demoMode, postForm, waitForAccepted } from "$lib/api";
	import { translate, translateResult, type TranslationKey } from "$lib/i18n";
	import type { ActionResult, Locale } from "$lib/types";

	let { value = $bindable(""), locale, invalid = $bindable() }: { value: string; locale: Locale; invalid: boolean } = $props();
	let parsed = $derived(parseRules(value));
	let legacy = $derived(Boolean(value.trim()) && !parsed.csv);
	let csvText = $derived(parsed.csv ? value.slice(CSV_PREFIX.length) : value);
	let sender = $state("");
	let message = $state("");
	let busy = $state(false);
	let result = $state<ActionResult | null>(null);
	let checkedInput = $state("");
	let requestError = $state("");
	let inputKey = $derived(JSON.stringify([value, sender, message]));
	let currentResult = $derived(checkedInput === inputKey ? result : null);
	let localError = $derived(new TextEncoder().encode(value).length > 2048 ? "size" : parsed.error);
	$effect(() => { invalid = Boolean(localError || (currentResult && !currentResult.success)); });
	const t = (key: TranslationKey) => translate(locale, key);
	function errorText(error: string) {
		const key = `ruleError${error.charAt(0).toUpperCase()}${error.slice(1)}` as TranslationKey;
		return t(key);
	}
	function update(index: number, field: "type" | "pattern" | "action" | "enabled", next: string) {
		value = serializeRules(parsed.rows.map((row, at) => at === index ? { ...row, [field]: next } : row));
	}
	function move(index: number, direction: number) {
		const rows = [...parsed.rows];
		[rows[index], rows[index + direction]] = [rows[index + direction], rows[index]];
		value = serializeRules(rows);
	}
	async function preview() {
		if (busy || localError) return;
		busy = true; requestError = ""; result = null;
		const key = inputKey;
		checkedInput = key;
		try {
			const next = await waitForAccepted(await postForm("/api/rules/preview", { rules: value, sender, text: message }));
			result = next; checkedInput = key;
		} catch { requestError = t("ACTION_REQUEST_FAILED"); }
		finally { busy = false; }
	}
</script>

<Field.Group>
	{#if legacy}
		<Alert.Root variant="info">
			<InfoIcon aria-hidden="true" />
			<Alert.Title>{t("ruleLegacyTitle")}</Alert.Title>
			<Alert.Description>{t("ruleLegacyDescription")}</Alert.Description>
		</Alert.Root>
		<Button type="button" variant="outline" disabled={migrateRules(value) === null} onclick={() => { value = migrateRules(value) ?? value; }}>{t("ruleConvert")}</Button>
		{#if migrateRules(value) === null}<p class="text-sm text-muted-foreground">{t("ruleLegacyBlocked")}</p>{/if}
	{:else if !parsed.error || parsed.rows.length > 0}
		{#each parsed.rows as row, index (index)}
			<Field.Set class="min-w-0" aria-label={`${t("ruleRow")} ${index + 1}`}>
				<Field.Legend>{t("ruleRow")} {index + 1}</Field.Legend>
				<Field.Group>
					<Field.Field>
						<Field.Label for={`rule-type-${index}`}>{t("ruleType")}</Field.Label>
						<NativeSelect.Root id={`rule-type-${index}`} value={row.type} onchange={(event) => update(index, "type", event.currentTarget.value)}>
							<NativeSelect.Option value="kw">{t("ruleKeyword")}</NativeSelect.Option>
							<NativeSelect.Option value="from">{t("ruleSender")}</NativeSelect.Option>
							<NativeSelect.Option value="re">{t("ruleRegex")}</NativeSelect.Option>
						</NativeSelect.Root>
					</Field.Field>
					<Field.Field><Field.Label for={`rule-pattern-${index}`}>{t("rulePattern")}</Field.Label><Textarea id={`rule-pattern-${index}`} rows={2} spellcheck={false} value={row.pattern} oninput={(event) => update(index, "pattern", event.currentTarget.value)} /></Field.Field>
					<Field.Field><Field.Label for={`rule-actions-${index}`}>{t("ruleActions")}</Field.Label><Input id={`rule-actions-${index}`} value={row.action} oninput={(event) => update(index, "action", event.currentTarget.value)} /><Field.Description>{t("forwardRulesActions")}</Field.Description></Field.Field>
					<Field.Field orientation="horizontal"><Switch id={`rule-enabled-${index}`} checked={row.enabled !== "0"} onCheckedChange={(checked) => update(index, "enabled", checked ? "1" : "0")} /><Field.Label for={`rule-enabled-${index}`}>{t("commonEnabled")}</Field.Label></Field.Field>
					<div class="flex flex-wrap gap-2">
						<Button type="button" variant="outline" disabled={index === 0} onclick={() => move(index, -1)}>{t("ruleMoveUp")}</Button>
						<Button type="button" variant="outline" disabled={index === parsed.rows.length - 1} onclick={() => move(index, 1)}>{t("ruleMoveDown")}</Button>
						<Button type="button" variant="outline" onclick={() => { value = serializeRules(parsed.rows.filter((_, at) => at !== index)); }}>{t("ruleRemove")}</Button>
					</div>
				</Field.Group>
			</Field.Set>
		{/each}
		<Button type="button" variant="outline" onclick={() => { value = serializeRules([...parsed.rows, { type: "kw", pattern: "", action: "email", enabled: "1" }]); }}>{t("ruleAdd")}</Button>
	{/if}
	<Field.Field data-invalid={invalid}>
		<Field.Label for="forward-rules">{legacy ? t("ruleLegacyText") : t("ruleCsvText")}</Field.Label>
		<Textarea id="forward-rules" rows={6} spellcheck={false} aria-invalid={invalid} aria-describedby="forward-rules-hint" value={csvText} oninput={(event) => { value = (legacy ? "" : CSV_PREFIX) + event.currentTarget.value; }} />
		<Field.Description id="forward-rules-hint">{legacy ? t("ruleLegacyDescription") : t("forwardRulesHint")}</Field.Description>
		{#if localError}<Field.Error>{parsed.line ? `${t("ruleLine")} ${parsed.line}: ` : ""}{errorText(localError)}</Field.Error>{/if}
	</Field.Field>
	<Field.Set>
		<Field.Legend>{t("ruleTestTitle")}</Field.Legend>
		<Field.Description>{demoMode || currentResult?.data.previewEngine === "mock" ? t("ruleDemoPreview") : t("ruleTestDescription")}</Field.Description>
		<Field.Group>
			<Field.Field><Field.Label for="rule-test-sender">{t("ruleTestSender")}</Field.Label><Input id="rule-test-sender" bind:value={sender} maxlength={32} /></Field.Field>
			<Field.Field><Field.Label for="rule-test-message">{t("ruleTestMessage")}</Field.Label><Textarea id="rule-test-message" rows={3} bind:value={message} /></Field.Field>
			{#if requestError && checkedInput === inputKey}<p role="alert">{requestError}</p>{/if}
			{#if currentResult}
				<div id="rule-preview-result" role={currentResult.success ? "status" : "alert"} class="flex flex-col gap-2 text-sm">
					{#if !currentResult.success}
						<p>{translateResult(locale, currentResult.code)}</p>
						{#if /^\d+:[a-z]+$/.test(currentResult.detail)}<p>{t("ruleLine")} {currentResult.detail.split(":")[0]}: {errorText(currentResult.detail.split(":")[1])}</p>{/if}
					{:else}
						<p>{currentResult.data.matched ? `${t("ruleFirstMatch")} ${currentResult.data.line}` : t("ruleDefault")}</p>
						{#if currentResult.data.matched}
							<div><p>{t("ruleActions")}</p><ul data-rule-actions class="list-inside list-disc">
								{#if currentResult.data.drop}<li>{t("ruleActionDrop")}</li>
								{:else}
									{#if currentResult.data.email}<li>{t("emailTitle")}</li>{/if}
									{#each [1, 2, 3, 4, 5].filter((channel) => Number(currentResult.data.channelMask) & (1 << (channel - 1))) as channel (channel)}<li>{t("ruleActionPush").replace("{channel}", String(channel))}</li>{/each}
									{#if !currentResult.data.email && !Number(currentResult.data.channelMask)}<li>{t("ruleNoTargets")}</li>{/if}
								{/if}
							</ul></div>
						{/if}
						<ul class="list-inside list-disc">
							{#each parsed.rows as row (row.line)}<li>{t("ruleLine")} {row.line}: {currentResult.data.matched && row.line > Number(currentResult.data.line) ? t("ruleNotEvaluated") : row.enabled === "0" || !row.pattern ? t("ruleSkipped") : row.line === Number(currentResult.data.line) ? t("ruleMatched") : t("ruleNotMatched")}</li>{/each}
						</ul>
						<p class="text-muted-foreground">{t("ruleTargetsNote")}</p>
					{/if}
				</div>
			{/if}
			<Button id="rule-test" type="button" variant="outline" aria-busy={busy} disabled={busy || Boolean(localError)} onclick={preview}>{busy ? t("commonRunning") : t("ruleTest")}</Button>
		</Field.Group>
	</Field.Set>
</Field.Group>
