import argparse
from collections import Counter
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re


@dataclass
class CertReportItem:
    domain: str
    issuer: str
    days_left: int
    status: str
    signature_alg: str


def analyze_certificates(
    certs_file: Path, days_warning: int = 30
) -> tuple[list[CertReportItem], Counter]:
    with open(certs_file, "r", encoding="utf-8") as f:
        certs_data = json.load(f)

    report_items = []
    issuer_counter = Counter()
    now = datetime.now(timezone.utc).date()

    for cert in certs_data:
        domain = cert["domain"]
        issuer = cert["issuer"]
        valid_to = datetime.strptime(cert["validTo"], "%Y-%m-%d").date()
        sig_alg = cert["signatureAlgorithm"]

        issuer_counter[issuer] += 1
        days_left = (valid_to - now).days

        if days_left < 0:
            status = "EXPIRED"
        elif days_left <= days_warning:
            status = "WARNING"
        else:
            status = "OK"

        if re.search(r"(sha1|md5)", sig_alg, re.IGNORECASE):
            status += " (WEAK ALG)"

        report_items.append(
            CertReportItem(
                domain=domain,
                issuer=issuer,
                days_left=days_left,
                status=status,
                signature_alg=sig_alg,
            )
        )

    return report_items, issuer_counter


def save_report(
    items: list[CertReportItem], output_file: Path, fmt: str
) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "csv":
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["Domain", "Issuer", "Days Left", "Status", "Signature Alg"]
            )
            for item in items:
                writer.writerow(
                    [
                        item.domain,
                        item.issuer,
                        item.days_left,
                        item.status,
                        item.signature_alg,
                    ]
                )
    else:
        with open(output_file, "w", encoding="utf-8") as f:
            data = [
                {
                    "domain": item.domain,
                    "issuer": item.issuer,
                    "days_left": item.days_left,
                    "status": item.status,
                    "signature_alg": item.signature_alg,
                }
                for item in items
            ]
            json.dump(data, f, indent=2)


def run_cli():
    parser = argparse.ArgumentParser(
        description="SSL Certificate Expiry Monitor"
    )
    parser.add_argument(
        "--certs-data",
        type=Path,
        required=True,
        help="Path to JSON file with certs",
    )
    parser.add_argument(
        "--days-warning",
        type=int,
        default=30,
        help="Days threshold for warning",
    )
    parser.add_argument(
        "--output-report",
        type=Path,
        required=True,
        help="Output report file path",
    )
    parser.add_argument(
        "--format",
        choices=["csv", "json"],
        default="csv",
        help="Report format",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO, format="[%(levelname)s] %(message)s"
    )
    logging.info(f"Loading SSL certificates data from {args.certs_data}...")

    items, issuers = analyze_certificates(args.certs_data, args.days_warning)

    print("\n=== Certificate Expiry & Safety Status ===")
    print(
        f"{'Domain':<30} {'Issuer':<15} {'Days Left':<12} {'Status':<18} {'Signature Alg'}"
    )
    print("-" * 90)
    for item in items:
        print(
            f"{item.domain:<30} {item.issuer:<15} {item.days_left:<12} {item.status:<18} {item.signature_alg}"
        )

    print("\n=== Issuer Statistics ===")
    for issuer, count in issuers.items():
        print(f"{issuer:<20} : {count}")

    save_report(items, args.output_report, args.format)
    logging.info(f"Report saved to {args.output_report}")


if __name__ == "__main__":
    current_dir = Path(__file__).parent
    certs_path = current_dir / "data" / "certificates.json"

    if certs_path.exists():
        items, issuers = analyze_certificates(certs_path)
        print("=== Результати аналізу сертифікатів ===")
        for item in items:
            print(f"{item.domain:<30} | {item.status:<18} | Дні: {item.days_left}")
        print("\nСтатистика видавців:", dict(issuers))
    else:
        run_cli()