import argparse
import json
import os
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

USERS = {"alice": "10.0.1.11", "bruno": "10.0.1.12", "carla": "10.0.1.13", "diego": "10.0.1.14"}
ACTIONS = ["ConsoleLogin", "GetObject", "PutObject", "ListBuckets", "DescribeInstances"]
SENSITIVE = ["StopLogging", "DeleteTrail", "AttachUserPolicy"]
ATTACKER_IP = "203.0.113.50"
START = datetime(2026, 1, 5, tzinfo=UTC)


def _event(when: datetime, user: str, ip: str, action: str, success: bool, anomaly: bool) -> dict:
    return {
        "timestamp": when.isoformat(),
        "user": user,
        "source_ip": ip,
        "action": action,
        "success": success,
        "is_anomaly": anomaly,
    }


def generate(events: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    logs = []
    for _ in range(events):
        user = rng.choice(list(USERS))
        when = START + timedelta(
            days=rng.randrange(7), hours=rng.randrange(9, 18), seconds=rng.randrange(3600)
        )
        logs.append(_event(when, user, USERS[user], rng.choice(ACTIONS), True, False))

    burst = START + timedelta(days=rng.randrange(7), hours=rng.randrange(9, 18))
    victim = rng.choice(list(USERS))
    for i in range(20):
        logs.append(
            _event(
                burst + timedelta(seconds=6 * i), victim, ATTACKER_IP, "ConsoleLogin", False, True
            )
        )

    for action in SENSITIVE:
        user = rng.choice(list(USERS))
        when = START + timedelta(days=rng.randrange(7), hours=3, seconds=rng.randrange(3600))
        logs.append(_event(when, user, USERS[user], action, True, True))

    return sorted(logs, key=lambda log: log["timestamp"])


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Gera logs simulados em JSON Lines.")
    parser.add_argument("--events", type=int, default=1000, help="eventos normais")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    out = Path(os.environ.get("SECOPS_DATA_DIR", "data")) / "logs_simulados.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    logs = generate(args.events, args.seed)
    out.write_text("".join(json.dumps(log) + "\n" for log in logs))
    print(f"{len(logs)} eventos em {out}")


if __name__ == "__main__":
    main()
