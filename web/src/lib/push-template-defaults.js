/**
 * @param {import("./types").PushChannel} channel
 * @param {number} type
 * @param {string} titleTemplate
 * @param {string} bodyTemplate
 */
export function applyProviderTemplateDefaults(channel, type, titleTemplate, bodyTemplate) {
	channel.type = type;
	if (type === 7) {
		channel.titleTemplate = "";
		channel.bodyTemplate = "";
		channel.customBody = '{"device":"{device}","sender":"{sender}","timestamp":"{timestamp}","message":"{message}"}';
		return;
	}
	channel.titleTemplate = titleTemplate;
	channel.bodyTemplate = bodyTemplate;
	channel.customBody = "";
}

/**
 * @param {import("./types").PushChannel} channel
 * @param {Record<number, object>} drafts
 * @param {number} previousType
 * @param {number} nextType
 * @param {string} titleTemplate
 * @param {string} bodyTemplate
 */
export function switchProviderDraft(channel, drafts, previousType, nextType, titleTemplate, bodyTemplate) {
	if (previousType === nextType) return;
	drafts[previousType] = {
		url: channel.url,
		urlSet: channel.urlSet,
		key1: channel.key1,
		key1Set: channel.key1Set,
		key2: channel.key2,
		key2Set: channel.key2Set,
		customBody: channel.customBody,
		customBodySet: channel.customBodySet,
		titleTemplate: channel.titleTemplate,
		bodyTemplate: channel.bodyTemplate
	};
	channel.type = nextType;
	const draft = drafts[nextType];
	if (draft) {
		Object.assign(channel, draft);
		return;
	}
	channel.url = "";
	channel.urlSet = false;
	channel.key1 = "";
	channel.key1Set = false;
	channel.key2 = "";
	channel.key2Set = false;
	channel.customBody = "";
	channel.customBodySet = false;
	applyProviderTemplateDefaults(channel, nextType, titleTemplate, bodyTemplate);
}

/** @type {Record<number, Array<"key1" | "key2">>} */
const providerKeyFields = {
	1: [],
	2: [],
	3: [],
	4: ["key1"],
	5: ["key1", "key2"],
	6: ["key1"],
	7: [],
	8: ["key1"],
	9: ["key1"],
	10: ["key1", "key2"],
	11: [],
	12: []
};

/**
 * Return only the credential fields consumed by a provider transport.
 * @param {number} type
 * @returns {Array<"key1" | "key2">}
 */
export function pushProviderKeyFields(type) {
	return providerKeyFields[type] ?? [];
}

/**
 * @param {import("./types").PushChannel} channel
 * @param {"url" | "key1" | "key2" | "customBody"} field
 */
export function pushSecretRequired(channel, field) {
	if (!channel.enabled) return false;
	if (field === "url") return [1, 2, 3, 4, 7, 8, 9, 11, 12].includes(channel.type) && !channel.urlSet;
	if (field === "key1") return [5, 6, 9, 10].includes(channel.type) && !channel.key1Set;
	if (field === "key2") return channel.type === 10 && !channel.key2Set;
	return channel.type === 7 && !channel.customBodySet;
}
