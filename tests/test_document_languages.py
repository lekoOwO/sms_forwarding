import json
import re
import subprocess
import unittest
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "dev_doc" / "document-languages.json"
DOCUMENT_SUFFIXES = {".adoc", ".markdown", ".md", ".rst", ".txt"}
DOCUMENT_BASENAMES = {
    "AUTHORS",
    "CHANGELOG",
    "CODE_OF_CONDUCT",
    "CONTRIBUTING",
    "LICENSE",
    "NOTICE",
    "README",
    "SECURITY",
}
ALLOWED_LANGUAGES = {"en", "zh-CN", "zh-TW"}
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
HTML_IMAGE = re.compile(r'<img\s+[^>]*src="([^"]+)"')


def repository_document_paths():
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    paths = {path for path in result.stdout.decode("utf-8").split("\0") if path}
    return {
        path
        for path in paths
        if (ROOT / path).is_file()
        and PurePosixPath(path).name != "CMakeLists.txt"
        and (
            PurePosixPath(path).suffix.lower() in DOCUMENT_SUFFIXES
            or PurePosixPath(path).name in DOCUMENT_BASENAMES
        )
    }


def load_manifest():
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def validate_manifest(manifest, repository_paths):
    errors = []
    if manifest.get("version") != 1:
        errors.append("manifest version must be 1")

    documents = manifest.get("documents")
    excluded = manifest.get("excluded")
    if not isinstance(documents, list):
        errors.append("documents must be a list")
        documents = []
    if not isinstance(excluded, list):
        errors.append("excluded must be a list")
        excluded = []

    entries_by_path = {}
    excluded_paths = set()

    for entry in documents:
        if not isinstance(entry, dict):
            errors.append("each document entry must be an object")
            continue
        path = entry.get("path")
        language = entry.get("language")
        if not isinstance(path, str) or not path:
            errors.append("each document entry must have a non-empty path")
            continue
        parsed_path = PurePosixPath(path)
        if parsed_path.is_absolute() or ".." in parsed_path.parts or str(parsed_path) != path:
            errors.append(f"document path must be normalized and repository-relative: {path}")
        if path in entries_by_path:
            errors.append(f"document is listed more than once: {path}")
        entries_by_path[path] = entry
        if language not in ALLOWED_LANGUAGES:
            errors.append(f"unsupported language for {path}: {language}")

    for entry in excluded:
        if not isinstance(entry, dict):
            errors.append("each excluded entry must be an object")
            continue
        path = entry.get("path")
        reason = entry.get("reason")
        if not isinstance(path, str) or not path:
            errors.append("each excluded entry must have a non-empty path")
            continue
        if path in excluded_paths:
            errors.append(f"document is excluded more than once: {path}")
        excluded_paths.add(path)
        if not isinstance(reason, str) or not reason.strip():
            errors.append(f"excluded document needs a reason: {path}")

    for path in sorted(set(entries_by_path) & excluded_paths):
        errors.append(f"document cannot be both classified and excluded: {path}")

    declared_paths = set(entries_by_path) | excluded_paths
    for path in sorted(repository_paths - declared_paths):
        errors.append(f"repository document is not classified: {path}")
    for path in sorted(declared_paths - repository_paths):
        errors.append(f"manifest path is not a repository document: {path}")

    groups = {}
    for path, entry in entries_by_path.items():
        group = entry.get("equivalenceGroup")
        if group:
            groups.setdefault(group, {}).setdefault(entry.get("language"), []).append(path)
        if entry.get("language") == "zh-CN" and not group:
            errors.append(f"Simplified Chinese document needs an equivalence group: {path}")

    for path, entry in entries_by_path.items():
        if entry.get("language") != "zh-CN" or not entry.get("equivalenceGroup"):
            continue
        languages = set(groups[entry["equivalenceGroup"]])
        if languages != ALLOWED_LANGUAGES:
            errors.append(
                f"Simplified Chinese document needs zh-TW and en equivalents: {path}"
            )

    return errors


class DocumentLanguageManifestTests(unittest.TestCase):
    def test_repository_documents_match_language_manifest(self):
        errors = validate_manifest(load_manifest(), repository_document_paths())
        self.assertEqual([], errors, "\n".join(errors))

    def test_simplified_chinese_requires_both_equivalents(self):
        manifest = {
            "version": 1,
            "documents": [
                {
                    "path": "guide.zh-CN.md",
                    "language": "zh-CN",
                    "equivalenceGroup": "guide",
                },
                {
                    "path": "guide.en.md",
                    "language": "en",
                    "equivalenceGroup": "guide",
                },
            ],
            "excluded": [],
        }

        errors = validate_manifest(manifest, {"guide.zh-CN.md", "guide.en.md"})

        self.assertIn(
            "Simplified Chinese document needs zh-TW and en equivalents: guide.zh-CN.md",
            errors,
        )

    def test_local_document_links_exist(self):
        errors = []
        for relative_path in sorted(repository_document_paths()):
            if PurePosixPath(relative_path).suffix.lower() not in {".md", ".markdown"}:
                continue
            path = ROOT / relative_path
            text = path.read_text(encoding="utf-8")
            targets = MARKDOWN_LINK.findall(text) + HTML_IMAGE.findall(text)
            for target in targets:
                target = target.strip().split("#", 1)[0]
                if not target or re.match(r"^[a-z]+:", target):
                    continue
                if not (path.parent / target).exists():
                    errors.append(f"{relative_path}: missing local link {target}")
        self.assertEqual([], errors, "\n".join(errors))


if __name__ == "__main__":
    unittest.main()
