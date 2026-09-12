import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";

test("alerts distinguish routine notices from urgent failures and preserve caller semantics", async () => {
	const previousCwd = process.cwd();
	let server;
	try {
		process.chdir(fileURLToPath(new URL("..", import.meta.url)));
		const { createServer } = await import("vite");
		server = await createServer({ server: { middlewareMode: true }, appType: "custom", logLevel: "silent" });
		const [{ render }, { createRawSnippet }, { default: Alert }] = await Promise.all([
			server.ssrLoadModule("svelte/server"), server.ssrLoadModule("svelte"),
			server.ssrLoadModule("/src/lib/components/ui/alert/alert.svelte")
		]);
		const children = createRawSnippet(() => ({ render: () => '<span>Device notice</span>' }));
		for (const variant of ["default", "info", "warning", "destructive"]) {
			const { body } = render(Alert, { props: { variant, children, id: "notice", "aria-label": "Device condition" } });
			assert.match(body, new RegExp(`role="${variant === "destructive" ? "alert" : "status"}"`), `${variant} announcement urgency`);
			assert.match(body, /id="notice"/);
			assert.match(body, /aria-label="Device condition"/);
			assert.match(body, /Device notice/);
			if (variant !== "default") {
				assert.match(body, new RegExp(`bg-alert-${variant}`), `${variant} has its semantic surface`);
				assert.match(body, new RegExp(`text-alert-${variant}-foreground`), `${variant} has readable foreground`);
			}
		}
		const { body } = render(Alert, { props: { variant: "warning", role: "region", "aria-live": "off", children } });
		assert.match(body, /role="region"/);
		assert.match(body, /aria-live="off"/);
		assert.doesNotMatch(body, /role="(?:alert|status)"/);
	} finally {
		try { await server?.close(); } finally { process.chdir(previousCwd); }
	}
});
