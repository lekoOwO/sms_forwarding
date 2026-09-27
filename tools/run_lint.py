#!/usr/bin/env python3
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IGNORED_PARTS = {".git", ".secrets", ".svelte-kit", "__pycache__", "build", "node_modules"}
GENERATED_NAMES = {"config_schema_generated.h", "firmware_version_generated.h"}
WEB_SUFFIXES = {".cjs", ".js", ".mjs", ".svelte", ".ts"}
CPP_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp"}


def discover_sources(root: Path) -> dict[str, list[str]]:
    sources: dict[str, list[str]] = {"web": [], "python": [], "shell": [], "cpp": []}
    try:
        result = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={root}",
                "-C",
                str(root),
                "ls-files",
                "--cached",
                "-z",
            ],
            check=True,
            capture_output=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as error:
        if (root / ".git").exists():
            raise RuntimeError("lint source discovery requires Git metadata") from error
        paths = [path for path in root.rglob("*") if path.is_file()]
    else:
        paths = [
            root / relative
            for relative in result.stdout.decode("utf-8").split("\0")
            if relative
        ]

    for path in paths:
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        parts = relative.parts
        if any(part in IGNORED_PARTS for part in parts):
            continue
        name = relative.as_posix()
        suffix = path.suffix.lower()
        if parts[0] in {"mock_server", "web"} and suffix in WEB_SUFFIXES and ".generated." not in path.name:
            sources["web"].append(name)
        if suffix == ".py":
            sources["python"].append(name)
        if suffix == ".sh":
            sources["shell"].append(name)
        if (
            suffix in CPP_SUFFIXES
            and parts[0] in {"components", "main"}
            and path.name not in GENERATED_NAMES
            and parts[:2] != ("components", "idf_pdu")
        ):
            sources["cpp"].append(name)
    for values in sources.values():
        values.sort()
    return sources


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> None:
    sources = discover_sources(ROOT)
    run(["npm", "--prefix", "web", "run", "lint"])
    run(["ruff", "check", "--no-cache", "--config", "ruff.toml", *sources["python"]])
    run(["shellcheck", *sources["shell"]])
    run([
        "cppcheck", "--quiet", "--error-exitcode=1",
        "--enable=warning,style,performance,portability", "--check-level=exhaustive",
        "--std=c++17", "--language=c++", "--inline-suppr",
        "--suppress=missingInclude", "--suppress=missingIncludeSystem",
        "--suppressions-list=cppcheck-suppressions.txt", *sources["cpp"],
    ])


if __name__ == "__main__":
    main()
