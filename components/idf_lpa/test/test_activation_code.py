import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


COMPONENT = Path(__file__).resolve().parents[1]
HEADER = COMPONENT / "include" / "idf_lpa_activation_code.h"
SOURCE = COMPONENT / "idf_lpa_activation_code.cpp"


HOST_CPP = r'''
#include "idf_lpa_activation_code.h"

#include <cassert>
#include <cstddef>
#include <new>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

using ActivationCode = LpaActivationCode;
using ActivationCodeParseError = LpaActivationCodeParseError;

static_assert(!std::is_copy_constructible<ActivationCode>::value);
static_assert(!std::is_copy_assignable<ActivationCode>::value);
static_assert(std::is_nothrow_move_constructible<ActivationCode>::value);
static_assert(std::is_nothrow_move_assignable<ActivationCode>::value);
static_assert(sizeof(ActivationCode) < 1024U);

static void expect_ok(std::string_view input,
                      std::string_view host,
                      std::string_view matching)
{
    ActivationCode value;
    ActivationCodeParseError error = ActivationCodeParseError::unknown;
    assert(idf_lpa_parse_activation_code(input, value, &error));
    assert(error == ActivationCodeParseError::none);
    assert(value.smdp_host() == host);
    assert(value.matching_id() == matching);
}

static void expect_bad(std::string_view input, ActivationCodeParseError expected)
{
    ActivationCode value;
    ActivationCodeParseError error = ActivationCodeParseError::none;
    assert(!idf_lpa_parse_activation_code(input, value, &error));
    assert(error == expected);
    assert(value.smdp_host().empty());
    assert(value.matching_id().empty());
    assert(LpaActivationCode::test_storage_is_zero(&value));
}

int main()
{
    expect_ok("LPA:1$edge.example$ABC123", "edge.example", "ABC123");
    expect_ok("1$edge.example$ABC123", "edge.example", "ABC123");
    expect_ok("  LPA:1$edge.example$ABC123  ", "edge.example", "ABC123");
    expect_ok("1$edge.example$ABC123$cc$provider$label$extra",
              "edge.example", "ABC123");
    expect_ok("1$edge.123$ID:123", "edge.123", "ID:123");

    const std::string long_label_host =
        "a." + std::string(60U, 'a') + "." + std::string(58U, 'a');
    const std::string max_matching(128U, 'A');
    const std::string max_optional(64U, 'x');
    const std::string max_core = "1$" + long_label_host + "$" + max_matching + "$" +
                                 max_optional + "$" + max_optional + "$" + max_optional +
                                 "$" + max_optional;
    assert(long_label_host.size() == 121U);
    assert(max_core.size() == 512U);
    expect_ok(max_core, long_label_host, max_matching);
    expect_ok("LPA:" + max_core, long_label_host, max_matching);

    expect_bad("", ActivationCodeParseError::empty);
    expect_bad("LPA:2$edge.example$ABC123", ActivationCodeParseError::version);
    expect_bad("0$edge.example$ABC123", ActivationCodeParseError::version);
    expect_bad("LPA:1edge.example$ABC123", ActivationCodeParseError::version);
    expect_bad("1$edge.example", ActivationCodeParseError::fields);
    expect_bad("1$edge.example$ABC123$a$b$c$d$e",
                ActivationCodeParseError::too_many_fields);
    expect_bad("1$edge.example$ABC123$", ActivationCodeParseError::optional_field);
    expect_bad("1$edge.example$ABC123$" + std::string(65U, 'x'),
                ActivationCodeParseError::optional_field);
    expect_bad("1$edge.example$A B", ActivationCodeParseError::matching_id);
    expect_bad("1$edge.example$ABC\n123", ActivationCodeParseError::non_printable);
    expect_bad("\t1$edge.example$ABC123", ActivationCodeParseError::non_printable);
    expect_bad(std::string("1$edge.example$ABC\x00", 19U),
                ActivationCodeParseError::non_printable);
    expect_bad("1$https://edge.example$ABC123", ActivationCodeParseError::host);
    expect_bad("1$edge.example:443$ABC123", ActivationCodeParseError::host);
    expect_bad("1$192.0.2.1$ABC123", ActivationCodeParseError::host);
    expect_bad("1$edge..example$ABC123", ActivationCodeParseError::host);
    expect_bad("1$-edge.example$ABC123", ActivationCodeParseError::host);
    expect_bad("1$edge-.example$ABC123", ActivationCodeParseError::host);
    expect_bad("1$edge_example$ABC123", ActivationCodeParseError::host);
    expect_bad("1$edge$ABC123", ActivationCodeParseError::host);
    expect_bad("1$" + std::string(64U, 'a') + ".example$ABC123",
                ActivationCodeParseError::host);

    const std::string oversized_core = "1$edge.example$" + std::string(500U, 'A');
    assert(oversized_core.size() == 515U);
    expect_bad(oversized_core, ActivationCodeParseError::core_too_long);
    expect_bad(std::string(517U, 'x'), ActivationCodeParseError::input_too_long);

    ActivationCode moved_from;
    ActivationCodeParseError error = ActivationCodeParseError::unknown;
    assert(idf_lpa_parse_activation_code(
        "1$edge.example$ABC123$private", moved_from, &error));
    ActivationCode moved_to(std::move(moved_from));
    assert(moved_from.smdp_host().empty());
    assert(moved_from.matching_id().empty());
    assert(LpaActivationCode::test_storage_is_zero(&moved_from));
    ActivationCode assigned;
    assigned = std::move(moved_to);
    assert(moved_to.smdp_host().empty());
    assert(moved_to.matching_id().empty());
    assert(LpaActivationCode::test_storage_is_zero(&moved_to));
    assert(assigned.smdp_host() == "edge.example");
    assert(assigned.matching_id() == "ABC123");
    assigned.clear_sensitive();
    assert(assigned.smdp_host().empty());
    assert(assigned.matching_id().empty());
    assert(LpaActivationCode::test_storage_is_zero(&assigned));

    LpaActivationCode reused;
    assert(idf_lpa_parse_activation_code("1$edge.example$ABC123", reused, &error));
    assert(!idf_lpa_parse_activation_code("1$edge.example$ABC\n123", reused, &error));
    assert(reused.smdp_host().empty());
    assert(reused.matching_id().empty());
    assert(LpaActivationCode::test_storage_is_zero(&reused));

    alignas(LpaActivationCode) unsigned char destroyed_storage[sizeof(LpaActivationCode)] = {};
    LpaActivationCode* destroyed = new (destroyed_storage) LpaActivationCode();
    assert(idf_lpa_parse_activation_code("1$edge.example$ABC123", *destroyed, &error));
    destroyed->~LpaActivationCode();
    assert(LpaActivationCode::test_storage_is_zero(destroyed_storage));

    assert(std::string(idf_lpa_activation_code_error_name(
               ActivationCodeParseError::host)) == "host");
    return 0;
}
'''


class ActivationCodeTest(unittest.TestCase):
    def test_activation_code_contract(self):
        compiler = shutil.which("g++")
        self.assertIsNotNone(compiler, "g++ is required for the activation-code host check")
        self.assertTrue(HEADER.exists(), "missing activation-code public header")
        self.assertTrue(SOURCE.exists(), "missing activation-code implementation")

        with tempfile.TemporaryDirectory(prefix="idf-lpa-activation-") as temp_dir:
            temp = Path(temp_dir)
            harness = temp / "activation_code_fixture.cpp"
            binary = temp / "activation_code_fixture"
            harness.write_text(HOST_CPP, encoding="utf-8")
            compile_result = subprocess.run(
                [
                    compiler,
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-pedantic",
                    "-DIDF_LPA_ACTIVATION_CODE_TESTING",
                    "-I",
                    str(COMPONENT / "include"),
                    str(SOURCE),
                    str(harness),
                    "-o",
                    str(binary),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                [str(binary)], check=False, capture_output=True, text=True
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)

        source_text = SOURCE.read_text(encoding="utf-8")
        header_text = HEADER.read_text(encoding="utf-8")
        self.assertIn("volatile", source_text)
        self.assertIn("clear_sensitive", source_text)
        self.assertNotIn("std::vector", header_text)
        self.assertNotIn("std::string", header_text.replace("std::string_view", ""))


if __name__ == "__main__":
    unittest.main()
