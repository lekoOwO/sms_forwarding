import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "demo.yml"

ACTION_PINS = {
    "actions/checkout": "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
    "actions/setup-node": "48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
    "actions/download-artifact": "d3f86a106a0bac45b974a628896c90dbdf5c8093",
}


def job(text: str, name: str) -> str:
    match = re.search(rf"(?ms)^  {name}:\n(.*?)(?=^  [a-z][\w-]*:\n|\Z)", text)
    if not match:
        raise AssertionError(f"missing job: {name}")
    return match.group(1)


class DemoWorkflowTests(unittest.TestCase):
    def test_demo_build_and_publish_boundaries(self):
        self.assertTrue(WORKFLOW.is_file(), "demo workflow must exist")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        build = job(workflow, "build")
        publish = job(workflow, "publish")

        self.assertRegex(
            workflow,
            r"(?m)^on:\n  push:\n    branches: \[develop\]\n  workflow_dispatch:\s*$",
        )
        self.assertRegex(workflow, r"(?m)^permissions:\n  contents: read$")
        self.assertRegex(build, r"(?m)^    permissions:\n      contents: read$")
        self.assertNotIn("secrets.", build)
        self.assertNotIn("contents: write", build)
        self.assertIn("persist-credentials: false", build)
        self.assertIn("node-version: '24.14.0'", build)
        self.assertIn("npm ci --prefix web", build)
        self.assertIn("npm --prefix web run check", build)
        self.assertRegex(build, r"(?m)^          VITE_DEMO_MODE: '1'$")
        self.assertRegex(
            build,
            r"(?ms)- name: Build demo site\n        working-directory: web\n"
            r"        env:\n          VITE_DEMO_MODE: '1'\n"
            r"        run: \|\n          npm exec -- vite build\n          touch build/\.nojekyll",
        )
        self.assertNotRegex(build, r"(?m)^\s*npm\b[^\n]*\brun build\b")
        self.assertNotIn("package.mjs", build)
        self.assertRegex(
            build,
            r"(?ms)name: demo-site\n          path: web/build\n"
            r"          if-no-files-found: error\n          include-hidden-files: true",
        )
        self.assertNotRegex(build, r"(?m)^          path: (?:web|\.)/?$")

        self.assertRegex(
            publish,
            r"(?m)^    if: github\.event_name == 'push' && github\.ref == 'refs/heads/develop'$",
        )
        self.assertRegex(publish, r"(?m)^    needs: build$")
        self.assertRegex(
            publish,
            r"(?m)^    permissions:\n      contents: write\n      actions: read$",
        )
        self.assertRegex(publish, r"(?ms)name: demo-site\n          path: site")
        self.assertIn("test ! -e site/.git", publish)
        self.assertIn("test ! -e site/src", publish)
        self.assertIn("test ! -e site/node_modules", publish)
        self.assertIn('test -z "$(find site -type l -print -quit)"', publish)
        self.assertIn("git init --initial-branch=gh-pages published", publish)
        self.assertIn('git commit -m "Publish demo site from $GITHUB_SHA"', publish)
        pushes = [line.strip() for line in publish.splitlines() if "git push" in line]
        self.assertEqual(
            ['git push --force "https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" HEAD:refs/heads/gh-pages'],
            pushes,
        )
        self.assertNotRegex(workflow, r"(?i)(peaceiris|deploy-pages|pages-action)")

        reference = (ROOT / ".github" / "workflows" / "build.yml").read_text(encoding="utf-8")
        for action, sha in ACTION_PINS.items():
            uses = re.findall(rf"uses: {re.escape(action)}@([^\s]+)", workflow)
            self.assertTrue(uses, f"missing action: {action}")
            self.assertEqual({sha}, set(uses))
            self.assertIn(f"{action}@{sha}", reference)

        api = (ROOT / "web" / "src" / "lib" / "api.ts").read_text(encoding="utf-8")
        request = api[api.index("async function requestJson"):api.index("export async function loadSnapshot")]
        self.assertLess(request.index("if (demoMode) return demoResponse"), request.index("fetch(path"))


if __name__ == "__main__":
    unittest.main()
