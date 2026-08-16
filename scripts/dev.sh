#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(dirname "$script_dir")"
cd "$repo_root"

usage() {
	cat <<'EOF'
Usage:
  scripts/dev.sh start mock-server
  scripts/dev.sh stop mock-server
  scripts/dev.sh restart mock-server
  scripts/dev.sh build frontend
  scripts/dev.sh build firmware
  scripts/dev.sh lint all
EOF
}

build_frontend() {
	docker compose up -d dev
	docker compose exec -T dev sh -lc 'cd web && npm ci && npm run check && npm run build'
}

build_firmware() {
	python3 scripts/generate-firmware-version.py --check
	docker compose up -d dev
	docker compose exec -T dev scripts/apply-esp32-webserver-3.3.10-patch.sh
	docker compose exec -T dev arduino-cli compile --fqbn esp32:esp32:esp32c3:PartitionScheme=min_spiffs ./code
}

lint_all() {
	docker compose up -d --build dev
	docker compose exec -T dev python3 tests/lint_gate_smoke.py
	docker compose exec -T dev npm run lint --prefix web
	docker compose exec -T dev ruff check --config ruff.toml scripts tests
	docker compose exec -T dev sh -lc "git ls-files -z '*.sh' | xargs -0 shellcheck"
	docker compose exec -T dev sh -lc "git ls-files -z -- 'code/*.ino' 'code/*.cpp' 'code/*.h' \
		':!code/src/pdulib/**' ':!code/web_bundle.h' ':!code/config_schema_generated.h' \
		':!code/firmware_version_generated.h' | xargs -0 cppcheck --quiet --error-exitcode=1 \
		--enable=warning,style,performance,portability --check-level=exhaustive \
		--std=c++11 --language=c++ --inline-suppr --suppress=missingIncludeSystem \
		--suppressions-list=cppcheck-suppressions.txt"
}

verb="${1:-}"
target="${2:-}"
if [ "$#" -ne 2 ]; then
	usage
	exit 2
fi

case "$verb:$target" in
	build:frontend)
		build_frontend
		;;
	build:firmware)
		build_firmware
		;;
	lint:all)
		lint_all
		;;
	start:mock-server)
		build_frontend
		docker compose up -d --build mock-server
		;;
	restart:mock-server)
		build_frontend
		docker compose up -d --build --force-recreate mock-server
		;;
	stop:mock-server)
		docker compose stop mock-server
		;;
	*)
		usage
		exit 2
		;;
esac
