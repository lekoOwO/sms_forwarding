import tailwindcss from '@tailwindcss/vite';
import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig, loadEnv } from 'vite';

const clientHashRoutes = new Set([
	'overview', 'notifications', 'messaging', 'cellular', 'device', 'security',
	'device/connection', 'device/diagnostics', 'device/maintenance', 'device/advanced'
]);

export default defineConfig(({ mode }) => {
	const deviceUrl = loadEnv(mode, '.', '').DEVICE_URL;
	const deviceRoutes = ['/api', '/save', '/sendsms', '/ping', '/query', '/flight', '/at', '/log', '/modem', '/wifi'];

	return {
		plugins: [
			tailwindcss(),
			sveltekit({
				prerender: {
					handleMissingId: ({ path, id, message }) => {
						if (path === '/' && clientHashRoutes.has(id)) return;
						throw new Error(message);
					}
				},
				compilerOptions: {
					// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
					runes: ({ filename }) =>
						filename.split(/[/\\]/).includes('node_modules') ? undefined : true
				},
				adapter: adapter(),
				version: { name: 'sms-forwarding' },
				output: {
					bundleStrategy: 'inline'
				}
			})
		],
		build: {
			assetsInlineLimit: Number.MAX_SAFE_INTEGER
		},
		server: {
			host: '0.0.0.0',
			proxy: deviceUrl
				? Object.fromEntries(deviceRoutes.map((route) => [route, { target: deviceUrl, changeOrigin: true }]))
				: undefined
		}
	};
});
