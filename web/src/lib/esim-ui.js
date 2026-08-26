/**
 * @param {() => Promise<import("./types").EsimStatus>} loadEsim
 * @param {import("./types").EsimStatus} status
 * @returns {Promise<import("./types").EsimStatus>}
 */
export async function refreshEsimAfterTerminal(loadEsim, status) {
	if (!status?.job || !["succeeded", "failed"].includes(status.job.state)) return status;
	return loadEsim();
}

/**
 * @param {{ handle: string, originId: string }} state
 * @returns {{ handle: string, originId: string, focusId: string }}
 */
export function closeEsimDeleteDialog(state) {
	return { handle: "", originId: "", focusId: state.originId || "" };
}
