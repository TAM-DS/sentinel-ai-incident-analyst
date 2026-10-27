"""Read and normalize Linux journal events without elevated privileges."""

import json
import subprocess
from datetime import datetime, timezone


def collect_events(limit: int = 50) -> list[dict]:
    """Collect recent journal records using the current user's permissions."""
    if not 1 <= limit <= 1000:
        raise ValueError("limit must be between 1 and 1000")

    result = subprocess.run(
        ["journalctl", "--no-pager", "-o", "json", "-n", str(limit)],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )

    events = []

    for line in result.stdout.splitlines():
        if not line.strip():
            continue

        record = json.loads(line)
        timestamp = record.get("__REALTIME_TIMESTAMP")

        try:
            observed_at = datetime.fromtimestamp(
                int(timestamp) / 1_000_000,
                tz=timezone.utc,
            ).isoformat()
        except (TypeError, ValueError, OverflowError, OSError):
            observed_at = None

        events.append({
            "timestamp": observed_at,
            "source": record.get("_SYSTEMD_UNIT")
                or record.get("SYSLOG_IDENTIFIER")
                or record.get("_TRANSPORT")
                or "unknown",
            "priority": str(record.get("PRIORITY", "unknown")),
            "message": str(record.get("MESSAGE", ""))[:1000],
        })

    return events


if __name__ == "__main__":
    records = collect_events(10)
    print(json.dumps(records, indent=2))
    print(f"\nCollected {len(records)} journal events.")
