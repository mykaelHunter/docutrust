"""
Typosquatting risk check for DocuTrust's direct dependencies.

For each real dependency, generates plausible typosquat variants
(missing char, adjacent-char swap, extra trailing char), checks which
of those variants exist as real published packages on the public npm
registry, then confirms none of them are actually present in
DocuTrust's package-lock.json.

Usage: python3 scripts/typosquat-check.py
"""
import json
import urllib.request

DEPS = ["express", "lodash", "pg", "zod", "dotenv"]


def variants(name):
    v = set()
    for i in range(len(name)):
        v.add(name[:i] + name[i + 1:])                      # missing char
        if i < len(name) - 1:
            v.add(name[:i] + name[i + 1] + name[i] + name[i + 2:])  # adjacent swap
    for c in "abcdefghijklmnopqrstuvwxyz":
        v.add(name + c)                                      # extra trailing char
    v.discard(name)
    return v


def exists_on_npm(pkg_name):
    try:
        req = urllib.request.Request(
            f"https://registry.npmjs.org/{pkg_name}", method="HEAD"
        )
        urllib.request.urlopen(req, timeout=3)
        return True
    except Exception:
        return False


def load_lockfile_names(path="package-lock.json"):
    with open(path) as f:
        lock = json.load(f)
    names = set()
    for pkg_path in lock.get("packages", {}):
        if pkg_path.startswith("node_modules/"):
            names.add(pkg_path.split("node_modules/")[-1])
    return names


def main():
    lock_names = load_lockfile_names()
    report = {}

    for dep in DEPS:
        candidates = variants(dep)
        published = [c for c in candidates if exists_on_npm(c)]
        installed_matches = [c for c in published if c in lock_names]
        report[dep] = {
            "variants_checked": len(candidates),
            "published_lookalikes_found": sorted(published),
            "present_in_our_lockfile": installed_matches,
        }
        print(f"\n{dep}:")
        print(f"  variants checked: {len(candidates)}")
        print(f"  published lookalikes on npm: {sorted(published)}")
        print(f"  any present in our package-lock.json: {installed_matches or 'NONE'}")

    with open("typosquat-report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("\nFull report written to typosquat-report.json")


if __name__ == "__main__":
    main()
