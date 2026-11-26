#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
# SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
# SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
# SPDX-License-Identifier: Apache-2.0
"""check-fleet-lists.py — the fleet's service lists must agree.

A platform service is named in three places that have to stay in step:

  1. ``SERVICES`` in the tree-root Makefile — what ``make build`` builds
     (short names; ``captain`` excluded, it comes from ``build-starters``),
  2. ``PLATFORM_SERVICES`` in the tree-root Makefile — what ``make start``
     asks the captain to run (colon identities, ``captain`` included),
  3. ``default_catalog()`` in ``sentin8-captain`` — what turns a service
     type into a binary to exec.

(1) and (2) can disagree harmlessly. (3) cannot: a service present in the
Makefile lists but absent from the catalog cannot be resolved by binary name,
so the captain falls through to the catalog's last-resort
``<root>/target/release/<binary>`` guess.

That is exactly how ``sentin8:push`` broke. It was in ``SERVICES`` and in
``PLATFORM_SERVICES`` — ``make build`` built it, ``make start`` asked for it —
but it was missing from ``default_catalog()``, so it alone ran a stale release
binary while the other 19 services ran ``target/debug``. Its health probe
failed three times, the captain killed it, and it restarted on a loop. It was
invisible: nothing errored, the build succeeded, the start list was right.

This check makes that divergence fail loudly.

Exit 0 = the lists agree, 1 = they do not (or a source is unreadable).
"""

import pathlib
import re
import sys

TREE_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
MAKEFILE = TREE_ROOT / "Makefile"
CAPTAIN_CATALOG = TREE_ROOT / "sentin8-captain" / "src" / "config.rs"

# `captain` is built by `build-starters`, so it is absent from `SERVICES`
# while every other platform service appears there in short-name form.
CAPTAIN = "sentin8:captain"


def read(path: pathlib.Path) -> str:
    try:
        return path.read_text()
    except OSError as e:
        sys.exit(f"cannot read {path}: {e}")


def makefile_var(name: str) -> list[str]:
    """The comma- or space-separated value of a `NAME := ...` assignment."""
    m = re.search(rf"^{name}\s*:=\s*(.+)$", read(MAKEFILE), re.M)
    if not m:
        sys.exit(f"{MAKEFILE}: no `{name} :=` assignment")
    return [t for t in re.split(r"[,\s]+", m.group(1).strip()) if t]


def captain_catalog() -> set[str]:
    """Service types in `default_catalog()`.

    Scoped to the function body so no other string in the file (tests, docs,
    constants) can satisfy the check.
    """
    src = read(CAPTAIN_CATALOG)
    if "pub fn default_catalog" not in src:
        sys.exit(f"{CAPTAIN_CATALOG}: no `pub fn default_catalog`")
    body = src.split("pub fn default_catalog", 1)[1]
    body = re.split(r"\n#\[cfg\(test\)\]|\npub fn |\nfn ", body, maxsplit=1)[0]
    return set(re.findall(r'"(sentin8:[a-z0-9-]+)"', body))


def main() -> int:
    built = {f"sentin8:{s}" for s in makefile_var("SERVICES")} | {CAPTAIN}
    started = set(makefile_var("PLATFORM_SERVICES"))
    catalogued = captain_catalog()

    lists = {
        "Makefile SERVICES (build)": built,
        "Makefile PLATFORM_SERVICES (start)": started,
        "captain default_catalog()": catalogued,
    }

    bad = 0
    for svc in sorted(set().union(*lists.values())):
        missing = [name for name, entries in lists.items() if svc not in entries]
        if missing:
            bad += 1
            print(f"MISSING {svc}: absent from {'; '.join(missing)}")

    if bad:
        print(
            f"\n{bad} service(s) declared in one list but not the others.\n"
            "A platform service missing from the captain catalog cannot be "
            "resolved by binary name: the captain falls back to a guessed "
            "build profile and runs a different binary than the rest of the "
            "fleet. Add the entry to `default_catalog()`."
        )
        return 1

    print(f"fleet lists agree ({len(catalogued)} services)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
