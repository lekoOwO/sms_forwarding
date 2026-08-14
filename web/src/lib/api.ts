import type { ActionResult, DeviceSnapshot } from "$lib/types";

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
	const response = await fetch(path, {
		...init,
		headers: {
			Accept: "application/json",
			...init?.headers
		}
	});
	if (!response.ok) throw new Error(`HTTP ${response.status}`);
	return response.json() as Promise<T>;
}

export function loadSnapshot(): Promise<DeviceSnapshot> {
	return requestJson<DeviceSnapshot>("/api/config");
}

export function runAction(path: string, init?: RequestInit): Promise<ActionResult> {
	return requestJson<ActionResult>(path, init);
}

export function postForm(path: string, values: Record<string, string | number | boolean>) {
	const body = new URLSearchParams();
	for (const [key, value] of Object.entries(values)) {
		if (typeof value === "boolean") {
			if (value) body.set(key, "on");
		} else {
			body.set(key, String(value));
		}
	}
	return runAction(path, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
		body
	});
}

export async function loadLogs(): Promise<string[]> {
	return requestJson<string[]>("/log");
}
