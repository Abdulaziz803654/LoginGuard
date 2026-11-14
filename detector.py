
#!/usr/bin/env python3
"""Detect repeated failed SSH login attempts."""

import argparse
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

DEFAULT_THRESHOLD = 5

# Common SSH failed-login formats.
FAILED_PATTERNS = [
    re.compile(
        r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
        r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    ),
    re.compile(
        r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    ),
    re.compile(
        r"authentication failure;.*rhost=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
        r"(?:.*user=(?P<user>\S+))?"
    ),
]


def parse_line(line):
    """Extract the IP and username from a failed login."""
    for pattern in FAILED_PATTERNS:
        match = pattern.search(line)
        if match:
            user = match.groupdict().get("user") or "unknown"
            return match.group("ip"), user
    return None


def analyze(log_path):
    """Count failed logins for each IP and username."""
    failed_counts = Counter()
    users_by_ip = defaultdict(Counter)
    total_lines = 0

    with open(log_path, "r", errors="replace") as log:
        for line in log:
            total_lines += 1
            result = parse_line(line)

            if result:
                ip, user = result
                failed_counts[ip] += 1
                users_by_ip[ip][user] += 1

    return total_lines, failed_counts, users_by_ip


def build_report(log_path, threshold, total_lines, failed_counts, users_by_ip):
    """Create the security report."""
    flagged = {
        ip: count
        for ip, count in failed_counts.items()
        if count >= threshold
    }

    total_failed = sum(failed_counts.values())
    separator = "=" * 60

    report = [
        separator,
        "FAILED LOGIN SECURITY REPORT",
        separator,
        f"Generated:         {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"Log file:          {log_path}",
        f"Lines scanned:     {total_lines}",
        f"Failed attempts:   {total_failed}",
        f"Unique IPs:        {len(failed_counts)}",
        f"Threshold:         {threshold} or more attempts",
        f"Flagged IPs:       {len(flagged)}",
        "",
    ]

    if flagged:
        report.append("!! FLAGGED IP ADDRESSES (possible brute-force) !!")
        report.append("-" * 60)

        for ip, count in sorted(flagged.items(), key=lambda x: -x[1]):
            targets = ", ".join(
                f"{user} ({number})"
                for user, number in users_by_ip[ip].most_common(3)
            )
            report.append(
                f"{ip:<16} {count:>5} attempts   targets: {targets}"
            )

        report.extend([
            "",
            "Recommended actions:",
            "  - Block flagged IPs using a firewall or fail2ban",
            "  - Use SSH key-based login instead of passwords",
            "  - Check for successful logins from flagged IPs",
        ])

    else:
        report.append("No IP addresses exceeded the threshold.")

    report.extend([
        "",
        "ALL FAILED ATTEMPTS BY IP",
        "-" * 60,
    ])

    if failed_counts:
        for ip, count in failed_counts.most_common():
            status = "  [FLAGGED]" if ip in flagged else ""
            report.append(f"{ip:<16} {count:>5}{status}")
    else:
        report.append("None found.")

    report.append(separator)

    return "\n".join(report)


def main():
    parser = argparse.ArgumentParser(
        description="Detect repeated failed SSH login attempts."
    )

    parser.add_argument("logfile", help="Path to the authentication log")
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        help=f"Attempts needed to flag an IP (default: {DEFAULT_THRESHOLD})"
    )
    parser.add_argument(
        "-o", "--output",
        help="Save the report to a file"
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("Threshold must be at least 1.")

    try:
        total, counts, users = analyze(args.logfile)

    except FileNotFoundError:
        sys.exit(f"Error: File not found: {args.logfile}")

    except PermissionError:
        sys.exit(f"Error: Permission denied: {args.logfile}")

    report = build_report(
        args.logfile, args.threshold, total, counts, users
    )

    print(report)

    if args.output:
        with open(args.output, "w") as file:
            file.write(report + "\n")

        print(f"\nReport saved to {args.output}")

    # Return 1 if suspicious activity is found.
    sys.exit(
        1 if any(count >= args.threshold for count in counts.values()) else 0
    )


if __name__ == "__main__":
    main()
