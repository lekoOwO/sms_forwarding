export function buildOperatorNames(rows) {
	if (!Array.isArray(rows)) throw new Error("MCC/MNC source must be a JSON array");

	const namesByCode = new Map();
	for (const row of rows) {
		const mcc = typeof row?.mcc === "string" ? row.mcc : "";
		const mnc = typeof row?.mnc === "string" ? row.mnc : "";
		if (!/^\d{3}$/.test(mcc) || !/^\d{2,3}$/.test(mnc)) continue;
		const code = `${mcc}${mnc}`;

		const brand = typeof row.brand === "string" ? row.brand.trim() : "";
		const operator = typeof row.operator === "string" ? row.operator.trim() : "";
		const name = brand || operator;
		if (!name) continue;

		const names = namesByCode.get(code) ?? { brands: [], operators: [] };
		const values = brand ? names.brands : names.operators;
		if (!values.includes(name)) values.push(name);
		namesByCode.set(code, names);
	}

	return Object.fromEntries([...namesByCode]
		.sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
		.map(([code, values]) => [code, (values.brands.length ? values.brands : values.operators).join(" / ")]));
}
