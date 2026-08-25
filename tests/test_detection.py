from datetime import datetime

from app.core.parser import SecurityEvent
from app.detectors.bruteforce import detect_bruteforce
from app.detectors.rules import detect_rules


def make_event(event_type, ip="192.168.1.20", username="admin"):
    return SecurityEvent(
        timestamp=datetime.now(),
        event_type=event_type,
        ip=ip,
        username=username,
    )


def test_bruteforce_detection():
    events = [
        make_event("LOGIN_FAILED"),
        make_event("LOGIN_FAILED"),
        make_event("LOGIN_FAILED"),
    ]

    alerts = detect_bruteforce(events)

    assert len(alerts) == 1
    assert alerts[0].rule == "BRUTE_FORCE_LOGIN"
    assert alerts[0].severity == "HIGH"
    assert alerts[0].attempts == 3


def test_password_spraying_detection():
    events = [
        make_event("LOGIN_FAILED", username="admin"),
        make_event("LOGIN_FAILED", username="user1"),
        make_event("LOGIN_FAILED", username="user2"),
    ]

    alerts = detect_rules(events)

    spraying_alerts = [
        alert
        for alert in alerts
        if alert.rule == "PASSWORD_SPRAYING"
    ]

    assert len(spraying_alerts) == 1
    assert spraying_alerts[0].severity == "HIGH"


def test_privileged_login_detection():
    events = [
        make_event(
            "LOGIN_SUCCESS",
            username="admin",
        )
    ]

    alerts = detect_rules(events)

    privileged_alerts = [
        alert
        for alert in alerts
        if alert.rule == "PRIVILEGED_LOGIN"
    ]

    assert len(privileged_alerts) == 1
    assert privileged_alerts[0].severity == "MEDIUM"


def test_normal_login_creates_no_alert():
    events = [
        make_event(
            "LOGIN_SUCCESS",
            username="fazal",
        )
    ]

    alerts = detect_rules(events)

    assert alerts == []