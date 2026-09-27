<script lang="ts">
	import ActionResult from "$lib/components/ActionResult.svelte";
	import type { Locale, PushCaStatus, UiResult } from "$lib/types";

	let { status, saveResult, result, title, saveTitle, ready, notReady, locale }: {
		status: PushCaStatus | null;
		saveResult: UiResult;
		result: UiResult;
		title: string;
		saveTitle: string;
		ready: string;
		notReady: string;
		locale: Locale;
	} = $props();
</script>

<div class="flex flex-col gap-3">
	<div>
		<p class="text-sm font-medium">{title}</p>
		<p class="text-sm text-muted-foreground" role="status" aria-live="polite">
			{status?.configured ? ready : notReady}
		</p>
	</div>
	<ActionResult result={saveResult} title={saveTitle} {locale} />
	<ActionResult {result} {title} {locale} />
</div>
