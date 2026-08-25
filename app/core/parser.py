from dataclasses import dataclass
from datetime import datetime


@dataclass
class SecurityEvent:
    timestamp: datetime
    event_type: str
    username: str
    ip: str


def parse_log_line(line: str) -> SecurityEvent | None:
    parts = line.strip().split()

    if len(parts) < 5:
        return None

    try:
        timestamp = datetime.strptime(
            f"{parts[0]} {parts[1]}",
            "%Y-%m-%d %H:%M:%S"
        )

        event_type = parts[2]
        username = parts[3].split("=", 1)[1]
        ip = parts[4].split("=", 1)[1]

        return SecurityEvent(
            timestamp=timestamp,
            event_type=event_type,
            username=username,
            ip=ip,
        )

    except (ValueError, IndexError):
        return None