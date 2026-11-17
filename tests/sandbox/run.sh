#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
export COMPOSE_PROJECT_NAME="nftguard-test-$$"
report_dir="$(pwd)/coverage-report"
coverage_data=$(mktemp -d "${TMPDIR:-/tmp}/nftguard-coverage.XXXXXX")
mkdir -p "$report_dir"
for old_report in coverage.txt coverage.xml coverage.json; do
    if [ -f "$report_dir/$old_report" ]; then rm "$report_dir/$old_report"; fi
done
if [ -d "$report_dir/html" ]; then rm -r "$report_dir/html"; fi
compose() { docker compose -f tests/sandbox/compose.yaml "$@"; }
cleanup() {
    compose down --volumes --remove-orphans
    rm -r "$coverage_data"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
python3 tests/check_compose.py
compose build
compose run --rm --no-deps -v "$coverage_data:/coverage-data" -e COVERAGE_FILE=/coverage-data/.coverage test \
    coverage run --parallel-mode -m unittest discover -s tests -p 'test_*.py'
compose run --rm --no-deps test python tests/installer_integration.py
compose run --rm --no-deps test python tests/uninstaller_integration.py
compose run --rm --no-deps test python tests/sandbox/boot_delay.py
compose up -d peer
compose run --rm --no-deps -v "$coverage_data:/coverage-data" -e COVERAGE_FILE=/coverage-data/.coverage test \
    coverage run --parallel-mode tests/sandbox/traffic.py
compose run --rm --no-deps -v "$coverage_data:/coverage-data" -v "$report_dir:/coverage-report" \
    -e COVERAGE_FILE=/coverage-data/.coverage test sh -c '
        coverage combine /coverage-data
        coverage html -d /coverage-report/html
        coverage xml -o /coverage-report/coverage.xml
        coverage json -o /coverage-report/coverage.json
        coverage report -m --fail-under=95 > /coverage-report/coverage.txt || status=$?
        cat /coverage-report/coverage.txt
        exit "${status:-0}"
    '
