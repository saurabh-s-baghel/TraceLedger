"""Original fictional scenarios; no traffic is collected or transmitted."""

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path


DEFAULT_START = datetime(2026, 1, 1, 9, tzinfo=timezone.utc)


def generate_events(seed: int = 42, start: datetime = DEFAULT_START):
    """Return auth/network lists with one deliberately qualifying auth burst.

    Seed controls account names, source addresses, and ordinary-event timing.
    The known scenarios stay structurally stable so expectations are explicit.
    This is controlled scenario variation, not a realistic traffic simulation.
    """
    if start.tzinfo is None or start.utcoffset() is None:
        raise ValueError("start must include a timezone")
    start = start.astimezone(timezone.utc)
    rng = random.Random(seed)
    hosts = rng.sample(range(10, 200), 3)
    names = rng.sample(["alex", "blair", "casey", "devon", "ellis", "frankie"], 3)
    auth, network = [], []

    def add(group, seconds, outcome):
        number = len(auth) + 1
        timestamp = (start + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
        source = f"192.0.2.{hosts[group]}"
        destination = "198.51.100.20"
        auth.append(dict(event_id=f"generated-auth-{number:03d}", timestamp=timestamp,
                         account=f"lab-{names[group]}", source_ip=source,
                         destination_ip=destination, outcome=outcome))
        network.append(dict(event_id=f"generated-net-{number:03d}", timestamp=timestamp,
                            source_ip=source, destination_ip=destination,
                            destination_port=443, protocol="TCP", action="allow"))

    # Five failures over four minutes; a later success is context only.
    for seconds in (0, 60, 120, 180, 240):
        add(0, seconds, "failure")
    add(0, 300, "success")
    # Same account/source, but six minutes between failures: no finding.
    for seconds in (3600, 3960, 4320, 4680, 5040):
        add(1, seconds, "failure")
    for seconds in sorted(rng.sample(range(7200, 10800), 8)):
        add(2, seconds, "success")
    # Paired network records are scripted context, not independent corroboration.
    return auth, network


def write_dataset(output_dir: str | Path, seed: int = 42):
    """Create UTF-8 JSONL examples, refusing existing output paths."""
    directory = Path(output_dir)
    paths = [directory / "generated-auth.jsonl", directory / "generated-network.jsonl"]
    if any(path.exists() for path in paths):
        raise FileExistsError("generated output already exists; choose a fresh output directory")
    auth, network = generate_events(seed)
    directory.mkdir(parents=True, exist_ok=True)
    for path, records in zip(paths, (auth, network)):
        with path.open("x", encoding="utf-8") as file:
            for record in records:
                file.write(json.dumps(record, sort_keys=True) + "\n")
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        paths = write_dataset(args.output_dir, args.seed)
    except OSError as error:
        parser.exit(1, f"Could not write dataset: {error}\n")
    for path in paths:
        print(path)


if __name__ == "__main__":
    main()
