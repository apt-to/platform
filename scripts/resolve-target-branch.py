"""Print the validated package recipe branch for a platform target."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from platform_policy import target_source_branch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="configured target ID")
    args = parser.parse_args()
    try:
        config = json.loads((ROOT / "packages.json").read_text())
        print(target_source_branch(config, args.target))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
