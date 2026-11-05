#!/usr/bin/env python3
"""Module A — Scope and repository discovery.

Builds a factual inventory of a repository: type, languages, frameworks, config
files, dependency manifests, CI/CD, containers, IaC, smart contracts, and whether
git history is available. Read-only.

Usage:
  python3 repository_inventory.py --repo /path/to/repo --out ./out
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import iter_files, language_of, run_cmd, write_json  # noqa: E402

DEPENDENCY_MANIFESTS = {
    "requirements.txt": "python-pip",
    "pyproject.toml": "python-poetry/hatch",
    "Pipfile": "python-pipenv",
    "poetry.lock": "python-poetry",
    "package.json": "node-npm",
    "package-lock.json": "node-npm",
    "yarn.lock": "node-yarn",
    "pnpm-lock.yaml": "node-pnpm",
    "Gemfile": "ruby-bundler",
    "go.mod": "go-modules",
    "Cargo.toml": "rust-cargo",
    "composer.json": "php-composer",
    "pom.xml": "java-maven",
    "build.gradle": "java-gradle",
    "hardhat.config.js": "solidity-hardhat",
    "hardhat.config.ts": "solidity-hardhat",
    "foundry.toml": "solidity-foundry",
    "truffle-config.js": "solidity-truffle",
    "brownie-config.yaml": "solidity-brownie",
}

CONFIG_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.development",
    "config.json", "config.yml", "config.yaml", "settings.py",
    "settings.json", "appsettings.json", "app.config",
    "docker-compose.yml", "docker-compose.yaml",
}

CONTAINER_FILENAMES = {"Dockerfile", "Containerfile"}
IAC_FILENAMES = {
    "main.tf", "variables.tf", "outputs.tf", "serverless.yml",
    "template.yaml", "cloudformation.yml", "ansible.cfg",
}

CI_DIRS = {".github", ".gitlab", ".circleci", ".drone.yml", "Jenkinsfile", ".travis.yml"}


def detect_frameworks(repo: Path, files: list[Path]) -> list[str]:
    frameworks: set[str] = set()
    names = {f.name for f in files}
    if "package.json" in names:
        try:
            pkg = json.loads((repo / "package.json").read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            pkg = {}
        deps = {}
        deps.update(pkg.get("dependencies") or {})
        deps.update(pkg.get("devDependencies") or {})
        for marker, label in (
            ("next", "Next.js"), ("nuxt", "Nuxt"), ("react", "React"), ("vue", "Vue"),
            ("@angular/core", "Angular"), ("svelte", "Svelte"), ("express", "Express"),
            ("fastify", "Fastify"), ("nestjs", "NestJS"), ("gatsby", "Gatsby"),
            ("remix", "Remix"), ("astro", "Astro"),
        ):
            if marker in deps:
                frameworks.add(label)
    if "manage.py" in names:
        frameworks.add("Django")
    if "pyproject.toml" in names or "setup.py" in names:
        try:
            text = (repo / "pyproject.toml").read_text(encoding="utf-8", errors="replace").lower()
            if "flask" in text:
                frameworks.add("Flask")
            if "fastapi" in text:
                frameworks.add("FastAPI")
        except OSError:
            pass
    for marker, label in (
        ("app.py", "Flask"), ("main.py", "Python"), ("Gemfile", "Ruby on Rails"),
        ("go.mod", "Go"), ("Cargo.toml", "Rust"), ("composer.json", "PHP"),
    ):
        if marker in names:
            frameworks.add(label)
    return sorted(frameworks)


def inventory(repo: Path) -> dict:
    files = list(iter_files(repo))
    lang_counter: Counter[str] = Counter()
    for f in files:
        lang = language_of(f)
        if lang:
            lang_counter[lang] += 1

    rels = {str(f.relative_to(repo)) for f in files}
    names = {f.name for f in files}

    dependency_manifests = sorted(
        {name: kind for name, kind in DEPENDENCY_MANIFESTS.items() if name in names}
    )
    env_files = sorted(r for r in rels if Path(r).name.startswith(".env"))
    config_files = sorted(r for r in rels if Path(r).name in CONFIG_FILENAMES)
    container_files = sorted(
        r for r in rels
        if Path(r).name in CONTAINER_FILENAMES
        or bool(__import__("re").search(r"(^|/)docker-compose.*\.ya?ml$", r))
    )
    iac_files = sorted(
        r for r in rels
        if Path(r).name in IAC_FILENAMES
        or r.startswith("k8s/")
        or r.startswith("kubernetes/")
        or r.startswith("terraform/")
    )
    ci_files = sorted(
        r for r in rels
        if r.startswith(tuple(f"{d}/" for d in CI_DIRS)) or Path(r).name in CI_DIRS
    )
    smart_contracts = sorted(r for r in rels if r.endswith(".sol"))

    git_history = (repo / ".git").is_dir()
    commit_count = None
    branches: list[str] = []
    if git_history:
        rc, out, _ = run_cmd(["git", "-C", str(repo), "rev-list", "--all", "--count"])
        if rc == 0 and out.strip().isdigit():
            commit_count = int(out.strip())
        rc, out, _ = run_cmd(
            ["git", "-C", str(repo), "for-each-ref", "--format=%(refname:short)", "refs/heads", "refs/remotes"]
        )
        if rc == 0:
            branches = sorted({x.strip() for x in out.splitlines() if x.strip()})

    total_bytes = sum(f.stat().st_size for f in files if f.is_file())

    return {
        "repository": str(repo),
        "repository_name": repo.name,
        "is_git": git_history,
        "git_commit_count": commit_count,
        "git_branches": branches,
        "file_count": len(files),
        "total_bytes": total_bytes,
        "languages": [
            {"language": lang, "files": count}
            for lang, count in lang_counter.most_common()
        ],
        "frameworks": detect_frameworks(repo, files),
        "dependency_manifests": dependency_manifests,
        "env_files": env_files,
        "config_files": config_files,
        "container_files": container_files,
        "iac_files": iac_files,
        "ci_files": ci_files,
        "smart_contracts": smart_contracts,
        "has_history": git_history,
        "scope_note": (
            "Current files and history are distinct. History must be scanned separately."
            if git_history
            else "No git history available; only current files were inventoried."
        ),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Module A — repository discovery and inventory")
    ap.add_argument("--repo", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    repo: Path = args.repo.resolve()
    if not repo.exists():
        print(f"ERROR: repository not found: {repo}", file=sys.stderr)
        return 2

    data = inventory(repo)
    args.out.mkdir(parents=True, exist_ok=True)
    write_json(args.out / "repository-inventory.json", data)

    print(f"Repository: {data['repository_name']}")
    print(f"  files: {data['file_count']}  ({data['total_bytes']:,} bytes)")
    print(f"  languages: {', '.join(l['language'] for l in data['languages']) or 'none'}")
    print(f"  frameworks: {', '.join(data['frameworks']) or 'none'}")
    print(f"  dependency manifests: {len(data['dependency_manifests'])}")
    print(f"  env files: {len(data['env_files'])}")
    print(f"  config files: {len(data['config_files'])}")
    print(f"  container files: {len(data['container_files'])}")
    print(f"  CI files: {len(data['ci_files'])}")
    print(f"  IaC files: {len(data['iac_files'])}")
    print(f"  smart contracts: {len(data['smart_contracts'])}")
    print(f"  git history: {'yes' if data['is_git'] else 'no'}"
          + (f", {data['git_commit_count']} commits, {len(data['git_branches'])} branches"
             if data['is_git'] else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
