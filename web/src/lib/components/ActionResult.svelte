<script lang="ts">
	import { translate, translateResult, type TranslationKey } from "$lib/i18n";
	import { cn } from "$lib/utils";
	import type { Locale, UiResult } from "$lib/types";
	import { diagnosticValue } from "$lib/diagnostic-values.js";
	import { Button } from "$lib/components/ui/button";
	import { Textarea } from "$lib/components/ui/textarea";

	let { result, title, locale }: { result: UiResult; title: string; locale: Locale } = $props();
	let entries = $derived(Object.entries(result.data));
	let rawDialog = $state<HTMLDialogElement>();
	const rawTitleId = $props.id();

	const fields: Record<string, { label: TranslationKey; unit?: string }> = {
		manufacturer: { label: "resultFieldManufacturer" }, model: { label: "resultFieldModel" }, revision: { label: "resultFieldRevision" },
		rsrpDbm: { label: "resultFieldRsrp", unit: "dBm" }, rsrqDb: { label: "resultFieldRsrq", unit: "dB" }, cesq: { label: "resultFieldCesq" },
		imsi: { label: "resultFieldImsi" }, iccid: { label: "resultFieldIccid" }, msisdn: { label: "resultFieldMsisdn" },
		registration: { label: "resultFieldRegistration" }, operator: { label: "resultFieldOperator" }, pdpActive: { label: "resultFieldPdp" }, apn: { label: "resultFieldApn" },
		wifiStatus: { label: "resultFieldWifiStatus" }, ssid: { label: "resultFieldSsid" }, rssiDbm: { label: "resultFieldRssi", unit: "dBm" },
		ip: { label: "resultFieldIp" }, gateway: { label: "resultFieldGateway" }, netmask: { label: "resultFieldNetmask" }, dns: { label: "resultFieldDns" },
		mac: { label: "resultFieldMac" }, bssid: { label: "resultFieldBssid" }, channel: { label: "resultFieldChannel" }, mode: { label: "resultFieldMode" },
		raw: { label: "resultFieldRaw" }, latencyMs: { label: "resultFieldLatency", unit: "ms" }, ttl: { label: "resultFieldTtl" },
		signalDbm: { label: "resultFieldSignal", unit: "dBm" }, rssi: { label: "resultFieldRssiCode" }, ber: { label: "resultFieldBer" }, imei: { label: "resultFieldImei" }
	};

	function formatValue(value: string | number | boolean | null, unit?: string) {
		if (value === null || (typeof value === "string" && !value.trim())) return translate(locale, "commonNotAvailable");
		if (typeof value === "boolean") return translate(locale, value ? "commonEnabled" : "commonDisabled");
		return unit ? `${value} ${unit}` : String(value);
	}

	function displayValue(key: string, value: string | number | boolean | null): string {
		const diagnostic = diagnosticValue(key, value);
		return diagnostic
			? translate(locale, diagnostic.key as TranslationKey).replace("{value}", diagnostic.value ?? "")
			: formatValue(value, fields[key]?.unit);
	}
</script>

{#if result.state !== "idle"}
	<div
		class={cn("flex flex-col gap-1 border-l-2 pl-3", result.state === "error" && "border-destructive")}
		role={result.state === "error" ? "alert" : "status"}
		aria-live="polite"
	>
		<p class="text-sm font-semibold">{title}</p>
		<p class={cn("text-sm text-muted-foreground", result.state === "error" && "text-destructive")}>{translateResult(locale, result.code)}</p>
		{#if entries.length > 0}
			<dl class="divide-y text-sm">
				{#each entries as [key, value] (key)}
					<div class="grid grid-cols-[minmax(7rem,0.35fr)_1fr] gap-4 py-2">
						<dt class="text-muted-foreground">{fields[key] ? translate(locale, fields[key].label) : key}</dt>
						<dd class="min-w-0 break-words">
							{#if key === "cesq" && typeof value === "string" && /^-?\d+,-?\d+,-?\d+$/.test(value)}
								<dl class="flex flex-col gap-2" title={`${key}: ${JSON.stringify(value)}`}>
									{#each value.split(",") as part, index (index)}
										<div data-signal-metric class="flex flex-col gap-1"><dt>{["RSRP", "RSRQ", "CSQ"][index]}</dt><dd>{displayValue(["rsrpDbm", "rsrqDb", "rssi"][index], Number(part))}</dd></div>
									{/each}
								</dl>
							{:else}
								<span title={`${key}: ${JSON.stringify(value)}`}>{displayValue(key, value)}</span>
							{/if}
						</dd>
					</div>
				{/each}
			</dl>
			<div><Button variant="ghost" size="sm" data-result-raw-trigger aria-haspopup="dialog" onclick={() => rawDialog?.showModal()}>{translate(locale, "diagnosticRawData")}</Button></div>
			<dialog bind:this={rawDialog} class="confirm-dialog" data-result-raw aria-labelledby={rawTitleId}>
				<div class="flex flex-col gap-4">
					<h2 id={rawTitleId} class="text-lg font-semibold">{translate(locale, "diagnosticRawData")}</h2>
					<Textarea readonly aria-label={translate(locale, "diagnosticRawData")} class="field-sizing-fixed h-64 max-h-[60dvh] font-mono" value={entries.map(([key, value]) => `${key}: ${JSON.stringify(value)}`).join("\n")} />
					<div class="flex justify-end"><Button variant="outline" onclick={() => rawDialog?.close()}>{translate(locale, "commonClose")}</Button></div>
				</div>
			</dialog>
		{/if}
		{#if Object.hasOwn(result.data, "registration")}
			<p class="text-xs text-muted-foreground">{translate(locale, "diagnosticRegistrationNote")}</p>
		{/if}
		{#if result.detail}<pre class={cn("max-h-64 overflow-auto whitespace-pre-wrap break-words font-mono text-xs text-muted-foreground", result.state === "error" && "text-destructive")}>{result.detail}</pre>{/if}
	</div>
{/if}
