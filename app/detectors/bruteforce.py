from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from app.core.parser import SecurityEvent


@dataclass
class Alert:
    timestamp: datetime
    severity: str
    rule: str
    ip: str
    username: str
    attempts: int


def detect_bruteforce(
    events: list[SecurityEvent],
    threshold: int = 3,
) -> list[Alert]:

    failures = defaultdict(int)
    alerts = []

    for event in events:
        if event.event_type != "LOGIN_FAILED":
            continue

        key = (event.ip, event.username)
        failures[key] += 1

        if failures[key] == threshold:
            alerts.append(
                Alert(
                    timestamp=event.timestamp,
                    severity="HIGH",
                    rule="BRUTE_FORCE_LOGIN",
                    ip=event.ip,
                    username=event.username,
                    attempts=failures[key],
                )
            )

    return alerts