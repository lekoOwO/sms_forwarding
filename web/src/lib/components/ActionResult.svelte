<script lang="ts">
	import { translate, translateResult, type TranslationKey } from "$lib/i18n";
	import { cn } from "$lib/utils";
	import type { Locale, UiResult } from "$lib/types";

	let { result, title, locale }: { result: UiResult; title: string; locale: Locale } = $props();
	let entries = $derived(Object.entries(result.data));

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
				{#each entries as [key, value]}
					<div class="grid grid-cols-[minmax(7rem,0.35fr)_1fr] gap-4 py-2">
						<dt class="text-muted-foreground">{fields[key] ? translate(locale, fields[key].label) : key}</dt>
						<dd class={cn("min-w-0 break-words font-mono", key === "raw" && "whitespace-pre-wrap")}>{formatValue(value, fields[key]?.unit)}</dd>
					</div>
				{/each}
			</dl>
		{/if}
		{#if result.detail}<pre class={cn("overflow-auto whitespace-pre-wrap break-words text-xs text-muted-foreground", result.state === "error" && "text-destructive")}>{result.detail}</pre>{/if}
	</div>
{/if}
