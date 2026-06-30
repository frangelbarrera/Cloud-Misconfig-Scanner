"""Allow ``python -m cms`` to invoke the CLI."""
from cms.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
