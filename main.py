from app.core.parser import parse_log_line
from app.detectors.rules import detect_rules
from app.storage.database import (
    initialize_database,
    save_alert,
    get_alerts,
)


def load_events(filename: str):
    events = []

    with open(filename, "r", encoding="utf-8") as file:

        for line in file:

            event = parse_log_line(line)

            if event:
                events.append(event)

    return events


def main():

    initialize_database()

    events = load_events("logs.txt")
    alerts = detect_rules(events)

    new_alerts = 0

    for alert in alerts:

        if save_alert(alert):
            new_alerts += 1

    print("\n========================================")
    print("          SENTINELSOC")
    print("       SECURITY MONITORING")
    print("========================================")

    print(f"\nEvents processed: {len(events)}")
    print(f"Detected alerts: {len(alerts)}")
    print(f"New alerts stored: {new_alerts}")

    print("\nRecent alerts:")

    for alert in get_alerts()[:10]:

        print(
            f"[{alert['severity']}] "
            f"{alert['rule']} | "
            f"{alert['ip']} | "
            f"{alert['username']} | "
            f"attempts={alert['attempts']} | "
            f"risk={alert['risk_score']}"
        )


if __name__ == "__main__":
    main()