#!/usr/bin/env python3
"""Create per-crate release tags and, with --push, GitHub releases."""

import argparse
import json
import os
from pathlib import PurePosixPath
import re
import shutil
import subprocess
import sys
import tomllib
from urllib.parse import urlsplit


def git(*args, input=None):
    return subprocess.run(
        ["git", *args], input=input, text=True, capture_output=True, check=True
    ).stdout


def resolve_commit(ref):
    return git("rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}").strip()


def gh(*args):
    return subprocess.run(
        ["gh", *args], text=True, capture_output=True, check=True
    ).stdout


def manifest(commit, path):
    return tomllib.loads(git("show", f"{commit}:{path}"))


def package(commit, path, workspace):
    fields = manifest(commit, path).get("package", {}).copy()
    for field in ("version", "publish"):
        value = fields.get(field)
        if isinstance(value, dict) and value.get("workspace"):
            fields[field] = workspace[field]
    return fields


def release_tags(base, commit):
    old_paths = set(git("ls-tree", "-r", "--name-only", "-z", base).split("\0"))
    workspaces = {
        ref: manifest(ref, "Cargo.toml").get("workspace", {}).get("package", {})
        for ref in (base, commit)
    }
    paths = git(
        "diff", "--no-renames", "--name-only", "--diff-filter=AM", "-z",
        base, commit, "--", "Cargo.toml", "**/Cargo.toml",
    ).split("\0")
    if workspaces[base].get("version") != workspaces[commit].get("version"):
        paths = [
            path for path in git("ls-tree", "-r", "--name-only", "-z", commit).split("\0")
            if path == "Cargo.toml" or path.endswith("/Cargo.toml")
        ]
    tags = {}
    for path in filter(None, paths):
        current = package(commit, path, workspaces[commit])
        if not current:
            continue
        publish = current.get("publish")
        if publish is False or (isinstance(publish, list) and "crates-io" not in publish):
            continue
        previous = package(base, path, workspaces[base]) if path in old_paths else {}
        identity = (current["name"], current["version"])
        if identity == (previous.get("name"), previous.get("version")):
            continue
        tag = f"{current['name']}-v{current['version']}"
        git("check-ref-format", f"refs/tags/{tag}")
        if tag in tags:
            raise ValueError("multiple changed packages produce the same release tag")
        tags[tag] = {
            "name": current["name"],
            "version": current["version"],
            "manifest": path,
            "previous_version": previous.get("version") if previous.get("name") == current["name"] else None,
        }
    if not tags:
        raise ValueError("no crates.io package version changes found in the selected range")
    return dict(sorted(tags.items()))


def local_tags():
    refs = {}
    for line in git(
        "for-each-ref", "--format=%(refname) %(objectname) %(*objectname)", "refs/tags/"
    ).splitlines():
        ref, target, *peeled = line.split()
        refs[ref] = peeled[0] if peeled else target
    return refs


def push_destination(remote):
    destinations = set(git("remote", "get-url", "--push", "--all", remote).splitlines())
    if len(destinations) != 1:
        raise ValueError(f"remote {remote} must have exactly one distinct push destination")
    return destinations.pop()


def remote_tags(destination):
    refs = {}
    for line in git("ls-remote", "--tags", "--", destination).splitlines():
        target, ref = line.split()
        refs[ref] = target
    return {ref: refs.get(f"{ref}^{{}}", target) for ref, target in refs.items()}


def github_releases(destination):
    if shutil.which("gh") is None:
        raise ValueError("GitHub CLI 'gh' is required for --push")
    gh("auth", "status")
    repo = json.loads(gh("repo", "view", destination, "--json", "nameWithOwner,url"))
    existing = gh(
        "api", "--hostname", urlsplit(repo["url"]).hostname,
        "--paginate", f"repos/{repo['nameWithOwner']}/releases", "--jq", ".[].tag_name",
    )
    return repo["url"], set(existing.splitlines())


def previous_release_ref(release):
    version = release["previous_version"]
    if version is not None:
        for tag in (f"{release['name']}-v{version}", f"rust-sdk-v{version}"):
            ref = f"refs/tags/{tag}"
            try:
                workspace = manifest(ref, "Cargo.toml").get("workspace", {}).get("package", {})
                previous = package(ref, release["manifest"], workspace)
            except subprocess.CalledProcessError:
                continue
            if (previous.get("name"), previous.get("version")) == (release["name"], version):
                return tag
    return None


def release_notes(repo, tag, release, commit, pr_cache=None):
    """Build crate-scoped notes; share pr_cache across calls to reuse PR lookups."""
    if pr_cache is None:
        pr_cache = {}
    previous = previous_release_ref(release)
    directory = str(PurePosixPath(release["manifest"]).parent)
    history = f"{previous}..{commit}" if previous else commit
    commits = git(
        "-c", "log.showSignature=false", "log", "--format=%H%x00%s", history, "--", directory,
    ).splitlines()
    bullets = []
    seen_prs = set()
    for line in commits:
        sha, subject = line.split("\0", 1)
        match = re.search(r" \(#(\d+)\)$", subject)
        if match is None:
            bullets.append(f"* {subject} in [{sha[:7]}]({repo}/commit/{sha})")
            continue
        number = match.group(1)
        if number in seen_prs:
            continue
        seen_prs.add(number)
        key = (repo, number)
        if key not in pr_cache:
            try:
                pr_cache[key] = json.loads(gh(
                    "pr", "view", number, "--repo", repo, "--json", "title,author",
                ))
            except (subprocess.CalledProcessError, OSError, ValueError):
                pr_cache[key] = None
                print(f"warning: cannot retrieve PR #{number}; using its commit subject without an author", file=sys.stderr)
        pr = pr_cache[key]
        title = pr["title"] if pr else subject[:match.start()]
        author = (pr.get("author") or {}).get("login") if pr else None
        by = f" by @{author}" if author else ""
        bullets.append(f"* {title}{by} in #{number}")
    if not bullets:
        bullets.append(f"* Version updated to `{release['version']}`.")
    changelog = (
        f"{repo}/compare/{previous}...{tag}" if previous
        else f"{repo}/commits/{tag}/{directory}"
    )
    return "## What's Changed\n\n" + "\n".join(bullets) + f"\n\n**Full Changelog**: {changelog}\n"


def create_github_releases(repo, notes, existing, commit):
    created = 0
    updated = 0
    for tag, body in notes.items():
        if tag in existing:
            print(gh("release", "edit", tag, "--repo", repo, "--title", tag, "--notes", body), end="")
            updated += 1
        else:
            print(gh(
                "release", "create", tag, "--repo", repo, "--verify-tag",
                "--target", commit, "--title", tag, "--notes", body, "--latest=false",
            ), end="")
            created += 1
    print(f"Created {created} GitHub releases; updated {updated} release notes.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", default="HEAD", help="release commit (default: HEAD)")
    parser.add_argument("--base", help="comparison commit (default: release commit's first parent)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true", help="create local tags")
    mode.add_argument(
        "--push", action="store_true", help="push tags atomically and create GitHub releases"
    )
    parser.add_argument("--remote", default="origin", help="push remote (default: origin)")
    parser.add_argument(
        "--update-notes", action="store_true", help="refresh existing release titles and notes (requires --push)"
    )
    args = parser.parse_args()
    if args.update_notes and not args.push:
        parser.error("--update-notes requires --push")

    os.chdir(git("rev-parse", "--show-toplevel").strip())
    commit = resolve_commit(args.commit)
    base = resolve_commit(args.base or f"{commit}^")
    git("merge-base", "--is-ancestor", base, commit)
    tags = release_tags(base, commit)
    local = local_tags()
    destination = push_destination(args.remote) if args.push else None
    remote = remote_tags(destination) if args.push else {}
    missing_local = []
    missing_remote = []
    for tag in tags:
        ref = f"refs/tags/{tag}"
        for location, refs in (("local", local), (args.remote, remote)):
            if ref in refs and refs[ref] != commit:
                raise ValueError(f"{location} tag {tag} points to {refs[ref]}, expected {commit}")
        if ref not in local:
            missing_local.append(ref)
        if ref not in remote:
            missing_remote.append(ref)

    if args.push:
        repo, existing_releases = github_releases(destination)
        pr_cache = {}
        notes = {
            tag: release_notes(repo, tag, release, commit, pr_cache)
            for tag, release in tags.items() if args.update_notes or tag not in existing_releases
        }

    print(f"Release commit: {commit}")
    print(f"Comparison: {base}")
    for tag in tags:
        status = "create" if f"refs/tags/{tag}" in missing_local else "exists locally"
        print(f"  {tag} ({status})")
    if not (args.execute or args.push):
        print(f"Dry run: {len(tags)} release tags. Use --execute to create locally or --push to publish tags and GitHub releases.")
        return

    if missing_local:
        commands = ["start", *(f"create {ref} {commit}" for ref in missing_local), "prepare", "commit"]
        git("update-ref", "--stdin", input="\n".join(commands) + "\n")
    print(f"Created {len(missing_local)} local lightweight tags; {len(tags) - len(missing_local)} already existed.")
    if args.push and missing_remote:
        print(git("push", "--atomic", "--no-follow-tags", "--", destination, *(f"{ref}:{ref}" for ref in missing_remote)), end="")
        print(f"Pushed {len(missing_remote)} tags to {args.remote}.")
    elif args.push:
        print(f"The {len(tags)} tags already exist on {args.remote}.")
    if args.push:
        create_github_releases(repo, notes, existing_releases, commit)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        detail = error.stderr.strip() if isinstance(error, subprocess.CalledProcessError) else str(error)
        print(f"error: {detail or str(error)}", file=sys.stderr)
        sys.exit(1)
