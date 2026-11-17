"""Render a coverage.py JSON report as a GitHub Actions summary."""
import json
from pathlib import Path

report_path = Path('coverage-report/coverage.json')
print('## Test coverage\n')
if not report_path.exists():
    print('Coverage report was not generated; see the test step logs.')
else:
    report = json.loads(report_path.read_text())
    print('Combined line coverage of application Python code from unit and sandbox traffic tests.\n')
    print('| File | Lines | Covered | Missing | Coverage |')
    print('| --- | ---: | ---: | ---: | ---: |')
    for name, entry in sorted(report['files'].items()):
        summary = entry['summary']
        print(f"| `{name}` | {summary['num_statements']} | {summary['covered_lines']} | "
              f"{summary['missing_lines']} | {summary['percent_covered']:.1f}% |")
    total = report['totals']
    print(f"| **Total** | **{total['num_statements']}** | **{total['covered_lines']}** | "
          f"**{total['missing_lines']}** | **{total['percent_covered']:.1f}%** |")
    print('\nRequired coverage: **95%**. Detailed HTML, XML and JSON reports are in the '
          '**coverage-report** artifact. Shell scripts are tested separately and excluded from this metric.')
