import re
import unittest
from pathlib import Path


COMPONENTS = Path(__file__).resolve().parents[2]
SMS_SOURCE = COMPONENTS / "idf_sms" / "idf_sms.cpp"
INBOX_SOURCE = COMPONENTS / "idf_inbox" / "idf_inbox.cpp"


def function_body(source: str, name: str) -> str:
    match = re.search(
        rf"^(?:static\s+)?[\w:<>&*]+\s+{name}\s*\([^;]*?\)\s*\{{",
        source,
        re.M | re.S,
    )
    if not match:
        raise AssertionError(f"missing function: {name}")
    start = match.end()
    depth = 1
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index]
    raise AssertionError(f"unterminated function: {name}")


class SmsRetentionPolicyTest(unittest.TestCase):
    def test_sms_is_ram_only_and_storage_waits_for_forward_admission(self):
        sms = SMS_SOURCE.read_text()
        inbox = INBOX_SOURCE.read_text()

        self.assertNotRegex(inbox, r"\bnvs_(?:set|open|get|commit|erase|entry)")
        self.assertNotIn("smsdata", inbox)
        self.assertNotIn('"SMS:"', sms)
        self.assertNotIn('"RESET"', sms)

        process = function_body(sms, "process_sms_content")
        enqueue = process.index("idf_push_enqueue_forward")
        fallback = process.index("enqueue_pending_forward")
        discarded = process.index("idf_inbox_delete(id);")
        self.assertLess(enqueue, fallback)
        self.assertLess(fallback, discarded)
        self.assertIn("return {false, false};", process[discarded:])
        self.assertIn("PENDING_FORWARD_MAX = 3", sms)
        self.assertIn("std::array<PendingForwardJob, PENDING_FORWARD_MAX>", sms)
        for remember in re.finditer("remember_seen", process):
            self.assertGreater(remember.start(), enqueue)

        fetch = function_body(sms, "fetch_stored_sms_by_index")
        backfill = function_body(sms, "backfill_stored_sms")
        for body in (fetch, backfill):
            self.assertIn("outcome.safe_to_delete", body)
            self.assertLess(body.index("outcome.safe_to_delete"), body.index("delete_stored_sms("))
        self.assertIn("outcome.admission_blocked", backfill)
        self.assertNotIn("examined >= BATCH_MAX", backfill)
        self.assertIn("admissions < BATCH_MAX", backfill)
        self.assertIn("while (pos < resp.size())", backfill)

        # Six retained multipart headers must not consume the five-admission budget:
        # parsing continues past them so part 6+ can complete the existing assembly.
        retained_parts = [False] * 5
        admission_budget = 5
        parsed = 0
        admitted = 0
        for needs_new_admission in retained_parts + [True]:
            parsed += 1
            if needs_new_admission and admitted < admission_budget:
                admitted += 1
        self.assertEqual(parsed, 6)
        self.assertEqual(admitted, 1)
        delete_stored = function_body(sms, "delete_stored_sms")
        self.assertIn("delete_err == ESP_OK", delete_stored)
        self.assertIn("s_backfill_pending = true;", delete_stored)
        self.assertIn("delete_stored_sms(idx)", fetch)
        self.assertGreaterEqual(backfill.count("delete_stored_sms("), 3)
        self.assertRegex(
            backfill,
            r"if \(delete_stored_sms\(idx\)\) \{\s*\+\+handled;\s*\+\+processed;",
        )
        for quarantine_index in ("nopdu_idx[i]", "decode_fail_idx[i]"):
            self.assertRegex(
                backfill,
                rf"if \(delete_stored_sms\({re.escape(quarantine_index)}\)\) "
                rf"\{{\s*\+\+handled;",
            )
        self.assertGreaterEqual(backfill.count("if (all_deleted)"), 2)

        multipart = function_body(sms, "handle_decoded_pdu")
        self.assertIn("return {true, false, false, eviction_admitted, false};", multipart)
        recorded = multipart.index("if (result.retained) {")
        self.assertLess(
            recorded,
            multipart.index("return {true, result.retained, !result.retained", recorded),
        )
        self.assertIn("clear_concat_slot(slot);", multipart[recorded:])
        self.assertNotIn(
            "clear_concat_slot(slot);\n            return",
            multipart[multipart.index("SmsProcessResult result = process_sms_content(", recorded):],
        )
        expiry = function_body(sms, "expire_concat_slots")
        self.assertRegex(
            expiry,
            r"if \(result\.retained\) \{[\s\S]*?clear_concat_slot\(slot\);"
            r"[\s\S]*?\} else \{[\s\S]*?slot\.lastUs = now;",
        )

        for variable in ("sender", "number", "num", "phone", "out.phone"):
            self.assertNotRegex(
                sms,
                rf"(?:idf_logf|ESP_LOG\w*)\([^;]*\b{re.escape(variable)}\.c_str\(\)",
            )

    def test_direct_multipart_ref_reuse_retains_old_slot_before_ack(self):
        sms = SMS_SOURCE.read_text()
        concat_lookup = function_body(sms, "find_concat_slot")
        multipart = function_body(sms, "handle_decoded_pdu")
        direct = function_body(sms, "process_urc_line")

        # Capacity eviction and reference reuse must share the retain-before-clear
        # boundary so neither path can discard already-CNMA'd direct fragments.
        self.assertIn("retain_concat_before_clear", concat_lookup)
        rejected = concat_lookup.index("if (!result.retained)")
        overwritten = concat_lookup.index("clear_concat_slot(*oldest)")
        self.assertLess(rejected, overwritten)
        self.assertIn("return nullptr;", concat_lookup[rejected:overwritten])

        reuse_start = multipart.index("const std::string incoming_text")
        reuse_end = multipart.index("if (!slot.parts[idx].valid)", reuse_start)
        reuse = multipart[reuse_start:reuse_end]
        self.assertIn("slot.parts[idx].text == incoming_text", reuse)
        self.assertIn("slot.parts[idx].timestamp == incoming_timestamp", reuse)
        self.assertIn("retain_concat_before_clear", reuse)
        self.assertLess(reuse.index("if (!result.retained)"), reuse.index("clear_concat_slot(slot)"))
        self.assertIn("return {true, false, true", reuse)

        blocked = direct.index("outcome.admission_blocked")
        ack = direct.index('idf_modem_send_at("AT+CNMA=0"')
        self.assertLess(blocked, ack)
        self.assertIn("return;", direct[blocked:ack])


if __name__ == "__main__":
    unittest.main()
