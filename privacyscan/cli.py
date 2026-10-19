import argparse
import sys

from . import __version__
from .report import to_html, to_json, to_table
from .scanner import ORDER, scan_path


def main(argv=None):
    p = argparse.ArgumentParser(prog="privacyscan",
                                description="Scan source code for GDPR/privacy risks.")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--format", choices=["table", "json", "html"], default="table")
    p.add_argument("-o", "--output")
    p.add_argument("--fail-on", choices=["high", "medium", "low", "none"], default="none",
                   help="exit with code 2 if a finding of this severity or higher exists (for CI)")
    p.add_argument("--version", action="version", version=__version__)
    a = p.parse_args(argv)
    findings, files = scan_path(a.path)
    if a.format == "json":
        out = to_json(findings, files)
    elif a.format == "html":
        out = to_html(findings, files, a.path)
    else:
        out = to_table(findings, files)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"Report written to {a.output}")
    else:
        print(out)
    if a.fail_on != "none" and any(ORDER[f.severity] >= ORDER[a.fail_on] for f in findings):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
