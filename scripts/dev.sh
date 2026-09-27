#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(dirname "$script_dir")"
cd "$repo_root"

usage() {
	cat <<'EOF'
Usage: scripts/dev.sh COMMAND

Commands:
  dev-start        Start the persistent ESP-IDF container
  dev-shell        Open an ESP-IDF shell
  dev-stop         Stop the ESP-IDF container
  dev-logs         Follow ESP-IDF container logs
  web-install      Install the locked Web dependencies
  web-check        Run the Web type and source checks
  web-build        Build the current Web assets
  firmware-build   Build firmware in the ESP-IDF container
  lint             Run the repository lint entry point
  mock-start       Build and start the mock server
  mock-stop        Stop the mock server
  mock-logs        Follow mock server logs
  mock-test        Run the in-process mock API tests
EOF
}

if [ "$#" -ne 1 ]; then
	usage
	exit 2
fi

case "$1" in
	dev-start) exec docker compose up -d dev ;;
	dev-shell)
		docker compose up -d dev
		exec docker compose exec dev bash -lc '. "$IDF_PATH/export.sh" >/dev/null && exec bash -i'
		;;
	dev-stop) exec docker compose stop dev ;;
	dev-logs) exec docker compose logs --follow dev ;;
	web-install) exec npm ci --prefix web ;;
	web-check) exec npm --prefix web run check ;;
	web-build) exec npm --prefix web run build ;;
	firmware-build)
		docker compose up -d dev
		exec docker compose exec dev python3 tools/device.py build
		;;
	lint) exec python3 tools/run_lint.py ;;
	mock-start) exec docker compose up -d --build mock-server ;;
	mock-stop) exec docker compose stop mock-server ;;
	mock-logs) exec docker compose logs --follow mock-server ;;
	mock-test) exec npm --prefix mock_server test ;;
	*) usage; exit 2 ;;
esac
