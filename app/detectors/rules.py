from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from app.core.parser import SecurityEvent
from app.core.risk import calculate_risk, risk_level


@dataclass
class Alert:
    timestamp: datetime
    severity: str
    rule: str
    ip: str
    username: str
    attempts: int
    description: str
    risk_score: int
    risk_level: str


def create_alert(
    event: SecurityEvent,
    severity: str,
    rule: str,
    attempts: int,
    description: str,
) -> Alert:

    score = calculate_risk(
        severity,
        attempts,
        rule,
    )

    return Alert(
        timestamp=event.timestamp,
        severity=severity,
        rule=rule,
        ip=event.ip,
        username=event.username,
        attempts=attempts,
        description=description,
        risk_score=score,
        risk_level=risk_level(score),
    )


def detect_rules(events: list[SecurityEvent]) -> list[Alert]:

    alerts = []

    failures_by_ip = defaultdict(int)
    users_by_ip = defaultdict(set)

    for event in events:

        if event.event_type == "LOGIN_FAILED":

            failures_by_ip[event.ip] += 1
            users_by_ip[event.ip].add(event.username)

            # Brute-force detection
            if failures_by_ip[event.ip] == 3:

                alerts.append(
                    create_alert(
                        event=event,
                        severity="HIGH",
                        rule="BRUTE_FORCE_LOGIN",
                        attempts=failures_by_ip[event.ip],
                        description="Multiple failed login attempts detected",
                    )
                )

            # Password spraying detection
            if len(users_by_ip[event.ip]) == 3:

                alerts.append(
                    create_alert(
                        event=event,
                        severity="HIGH",
                        rule="PASSWORD_SPRAYING",
                        attempts=failures_by_ip[event.ip],
                        description="Multiple accounts targeted from one IP",
                    )
                )

        # Privileged account login
        if (
            event.event_type == "LOGIN_SUCCESS"
            and event.username in {"admin", "root"}
        ):

            alerts.append(
                create_alert(
                    event=event,
                    severity="MEDIUM",
                    rule="PRIVILEGED_LOGIN",
                    attempts=1,
                    description="Privileged account login detected",
                )
            )

    return alerts