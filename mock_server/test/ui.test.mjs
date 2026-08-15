import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import puppeteer from "puppeteer-core";
import { createApp } from "../server.mjs";

test("the production UI works with the mock API", async () => {
	const server = createApp({ authRequired: false }).listen(0, "127.0.0.1");
	await new Promise((resolve) => server.once("listening", resolve));
	const browser = await puppeteer.launch({
		executablePath: process.env.PUPPETEER_EXECUTABLE_PATH,
		headless: true,
		args: ["--no-sandbox", "--disable-dev-shm-usage"]
	});

	try {
		const page = await browser.newPage();
		page.setDefaultTimeout(60_000);
		const browserErrors = [];
		page.on("pageerror", (error) => browserErrors.push(error.message));
		page.on("requestfailed", (request) => browserErrors.push(`${request.url()}: ${request.failure()?.errorText ?? "request failed"}`));
		const baseUrl = `http://127.0.0.1:${server.address().port}`;
		const html = await readFile(process.env.WEB_ROOT + "/index.html", "utf8");
		await page.setRequestInterception(true);
		page.on("request", (request) => void (async () => {
			try {
				const url = new URL(request.url());
				if (url.pathname === "/") {
					await request.respond({ status: 200, contentType: "text/html", body: html });
					return;
				}
				const upstream = await fetch(`${baseUrl}${url.pathname}${url.search}`, {
					method: request.method(),
					headers: {
						"content-type": request.headers()["content-type"] ?? "application/json",
						"x-csrf-token": request.headers()["x-csrf-token"] ?? ""
					},
					body: request.postData()
				});
				await request.respond({
					status: upstream.status,
					headers: Object.fromEntries(upstream.headers),
					body: Buffer.from(await upstream.arrayBuffer())
				});
			} catch {
				await request.abort();
			}
		})());
		await page.goto("http://sms-forwarding.test/", { waitUntil: "domcontentloaded", timeout: 90_000 });
		try {
			await page.waitForSelector("h1");
		} catch (error) {
			throw new Error(`${error.message}; browser errors: ${browserErrors.join(" | ") || "none"}`);
		}
		assert.equal(await page.$eval("h1", (node) => node.textContent), "Device overview");
		assert.equal(await page.title(), await page.$eval("header p", (node) => node.textContent));
		assert.equal(await page.$$eval("table", (nodes) => nodes.length), 0);
		assert.ok(await page.$$eval("dl", (nodes) => nodes.length) >= 2);
		assert.ok(await page.$eval("header p", (node) => Number.parseFloat(getComputedStyle(node).fontSize)) >= 18);
		await page.locator('::-p-aria(Dark mode)').click();
		await page.waitForFunction(() => document.documentElement.classList.contains("dark"));
		await page.locator('::-p-aria(Day mode)').wait();

		await page.select("#locale", "zh-TW");
		await page.waitForFunction(() => document.querySelector("h1")?.textContent === "裝置概覽");
		await page.select("#locale", "en");

		await page.locator('::-p-aria(Notifications)').click();
		await page.waitForFunction(() => document.body.textContent?.includes("Disabled"));
		assert.ok(await page.$$eval('button[data-slot="accordion-trigger"]', (nodes) => nodes.every((node) => node.getAttribute("aria-expanded") === "false")));
		await page.locator('::-p-xpath(//button[@data-slot="accordion-trigger" and starts-with(normalize-space(.),"Push channels")])').click();
		await page.select("#push-type-0", "7");
		assert.match(await page.$eval("#push-body-0", (node) => node.value), /\{message\}/);
		await page.select("#push-type-0", "2");
		assert.equal(await page.$eval("#push-title-template-0", (node) => node.value), "SMS from {sender}");
		assert.match(await page.$eval("#push-body-template-0", (node) => node.value), /Device: \{device\}/);
		await page.locator("#push-enabled-0").click();
		assert.doesNotMatch(await page.$eval('button[data-slot="tabs-trigger"]', (node) => node.className), /bg-primary/);
		await page.locator("#push-enabled-0").click();
		await page.locator('::-p-xpath(//button[@data-slot="accordion-trigger" and starts-with(normalize-space(.),"Email")])').click();
		await page.locator("#smtp-server").fill("smtp.example.com");
		await page.locator("#smtp-user").fill("sender@example.com");
		await page.locator("#smtp-pass").fill("secret");
		await page.locator("#smtp-to").fill("recipient@example.com");
		await page.locator('button[form="email-form"]').click();
		await page.waitForFunction(() => document.body.textContent?.includes("Configuration saved."));

		await page.locator('::-p-aria(Messaging)').click();
		await page.locator('::-p-aria(Send SMS)').click();
		await page.locator("#sms-phone").fill("+886900000000");
		await page.locator("#sms-message").fill("Mock message");
		await page.locator('button[form="sms-form"]').click();
		await page.waitForFunction(() => document.body.textContent?.includes("SMS sent."));

		await page.locator('::-p-aria(Device)').click();
		assert.equal(await page.$$eval('button[data-slot="accordion-trigger"][aria-expanded="true"]', (nodes) => nodes.length), 0);
		await page.locator('::-p-aria(Diagnostics)').click();
		await page.locator('::-p-aria(Modem information)').click();
		await page.waitForFunction(() => document.body.textContent?.includes("Mock LTE-C3"));
		assert.ok(await page.$eval('[role="status"] dl', (node) => ["Manufacturer", "Model", "Revision"].every((label) => node.textContent?.includes(label))));
		assert.ok(await page.$eval('button[data-slot="accordion-trigger"][aria-expanded="true"]', (node) => node.closest('[data-slot="accordion-item"]')?.querySelector('[data-slot="accordion-content"]')?.textContent?.includes("Query completed.")));
		await page.select("#locale", "zh-TW");
		await page.waitForFunction(() => document.body.textContent?.includes("查詢已完成。"));
		await page.select("#locale", "en");
		await page.waitForFunction(() => document.documentElement.lang === "en");
		await page.locator('::-p-aria(Logs)').click();
		await page.waitForFunction(() => document.body.textContent?.includes("Mock device started"));
		await page.waitForFunction(() => [...document.querySelectorAll('[role="status"]')].some((node) =>
			node.textContent?.includes("Query completed.") && node.closest('[data-slot="accordion-content"]')?.getBoundingClientRect().height === 0));

		await page.$eval('a[href="#security"]', (node) => node.click());
		await new Promise((resolve) => setTimeout(resolve, 300));
		assert.equal(await page.$eval("h1", (node) => node.textContent), "Account security");
		assert.equal(await page.$$eval('button[data-slot="tabs-trigger"]', (nodes) => nodes.length), 0);
		await page.locator('::-p-xpath(//button[@data-slot="accordion-trigger" and starts-with(normalize-space(.),"Account 2")])').click();
		await page.locator("#account-user-1").fill("operator");
		await page.locator("#account-pass-1").fill("secret");
		await page.locator('button[form="security-form"]').click();
		await page.waitForFunction(() => document.body.textContent?.includes("Configuration saved."));
	} finally {
		await browser.close();
		await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
	}
});
