import en from "$lib/locales/en.json";
import zhCN from "$lib/locales/zh-CN.json";
import zhTW from "$lib/locales/zh-TW.json";
import type { Locale } from "$lib/types";

export type TranslationKey = keyof typeof zhTW;

const messages: Record<Locale, Record<TranslationKey, string>> = {
	"zh-TW": zhTW,
	"zh-CN": zhCN,
	en
};

export function translate(locale: Locale, key: TranslationKey): string {
	return messages[locale][key];
}

export function translateResult(locale: Locale, code: string): string {
	return Object.hasOwn(messages[locale], code)
		? messages[locale][code as TranslationKey]
		: messages[locale].ACTION_UNKNOWN;
}

export function detectLocale(language: string): Locale {
	const normalized = language.toLowerCase();
	if (normalized === "zh-cn" || normalized.startsWith("zh-hans")) return "zh-CN";
	if (normalized.startsWith("zh")) return "zh-TW";
	return "en";
}
