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
