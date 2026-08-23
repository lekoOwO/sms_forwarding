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
 * @param {"url" | "key1" | "key2" | "customBody"} field
 */
export function pushSecretRequired(channel, field) {
	if (!channel.enabled) return false;
	if (field === "url") return [1, 2, 3, 4, 7, 8, 9, 11, 12].includes(channel.type) && !channel.urlSet;
	if (field === "key1") return [5, 6, 9, 10].includes(channel.type) && !channel.key1Set;
	if (field === "key2") return channel.type === 10 && !channel.key2Set;
	return channel.type === 7 && !channel.customBodySet;
}
