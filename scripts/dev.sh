#!/bin/sh
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
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
EOF
}

build_frontend() {
	docker compose up -d dev
	docker compose exec -T dev sh -lc 'cd web && npm ci && npm run check && npm run build'
}

build_firmware() {
	docker compose up -d dev
	docker compose exec -T dev scripts/apply-esp32-webserver-3.3.10-patch.sh
	docker compose exec -T dev arduino-cli compile --fqbn esp32:esp32:esp32c3:PartitionScheme=no_ota ./code
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
