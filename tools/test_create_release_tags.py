"""Integration tests use temporary repositories, a bare remote and a mocked gh CLI."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("create-release-tags.py")


class CreateReleaseTagsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "Release test")
        self.git("config", "user.email", "release@example.com")
        self.git("config", "commit.gpgSign", "false")
        self.git("config", "tag.gpgSign", "false")
        self.write_workspace("0.1.0")
        self.write_package("spr-alpha", 'version = "0.1.0"')
        self.write_package("spr-beta", "version.workspace = true")
        self.write_package("spr-stable", 'version = "0.8.0"')
        self.write_package("private", 'version = "0.1.0"\npublish = false')
        self.write_package("other-registry", 'version = "0.1.0"\npublish = ["other"]')
        self.base = self.commit("Before release")
        self.write_workspace("0.2.0")
        self.write_package("spr-alpha", 'version = "0.2.0"')
        self.write_package("spr-new", 'version = "0.2.0"')
        self.write_package("private", 'version = "0.2.0"\npublish = false')
        self.write_package("other-registry", 'version = "0.2.0"\npublish = ["other"]')
        self.release = self.commit("Release")
        self.expected = {
            f"spr-{name}-v0.2.0": self.release for name in ("alpha", "beta", "new")
        }
        self.remote = Path(self.temp.name) / "remote.git"
        self.git("init", "--quiet", "--bare", str(self.remote))
        self.git("remote", "add", "origin", str(self.remote))
        self.gh_state = Path(self.temp.name) / "github.json"
        self.gh_state.write_text(json.dumps({"releases": {}, "calls": []}))
        self.bin = Path(self.temp.name) / "bin"
        self.bin.mkdir()
        self.mock_gh = self.bin / "gh"
        self.mock_gh.write_text(f"#!{sys.executable}\n" + '''
import json
import os
from pathlib import Path
import sys

path = Path(os.environ["MOCK_GH_STATE"])
state = json.loads(path.read_text())
args = sys.argv[1:]
state["calls"].append(args)
path.write_text(json.dumps(state))
if args == ["auth", "status"]:
    if os.environ.get("MOCK_GH_AUTH_ERROR"):
        sys.exit("not authenticated")
elif args[:2] == ["repo", "view"]:
    print(json.dumps({"nameWithOwner": "example/project", "url": "https://github.com/example/project"}))
elif args[0] == "api":
    if os.environ.get("MOCK_GH_LOOKUP_ERROR"):
        sys.exit("gh: release lookup failed (HTTP " + os.environ["MOCK_GH_LOOKUP_ERROR"] + ")")
    for tag in state["releases"]:
        print(tag)
elif args[:2] == ["pr", "view"]:
    if os.environ.get("MOCK_GH_PR_ERROR"):
        sys.exit("PR lookup failed")
    number = args[2]
    print(json.dumps(state.get("prs", {}).get(number, {
        "title": "PR " + number, "author": {"login": "author-" + number},
    })))
elif args[:2] == ["release", "create"]:
    tag = args[2]
    if tag in state["releases"]:
        sys.exit("release already exists")
    state["releases"][tag] = args
    path.write_text(json.dumps(state))
    print("https://github.com/example/project/releases/tag/" + tag)
elif args[:2] == ["release", "edit"]:
    tag = args[2]
    release = state["releases"][tag]
    release["title"] = args[args.index("--title") + 1]
    release["body"] = args[args.index("--notes") + 1]
    path.write_text(json.dumps(state))
else:
    sys.exit("unexpected gh arguments: " + repr(args))
''')
        self.mock_gh.chmod(0o755)

    def git(self, *args):
        return subprocess.run(
            ["git", *args], cwd=self.repo, text=True, capture_output=True, check=True
        ).stdout.strip()

    def write_workspace(self, version):
        (self.repo / "Cargo.toml").write_text(
            f'[workspace]\nmembers = ["sdk-libs/*"]\n[workspace.package]\nversion = "{version}"\n'
        )

    def write_package(self, name, fields):
        directory = self.repo / "sdk-libs" / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "Cargo.toml").write_text(f'[package]\nname = "{name}"\n{fields}\n')

    def commit(self, message):
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", message)
        return self.git("rev-parse", "HEAD")

    def run_script(self, *args, success=True, env=None):
        environment = {
            **os.environ,
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "MOCK_GH_STATE": str(self.gh_state),
            **(env or {}),
        }
        result = subprocess.run(
            [sys.executable, str(SCRIPT), *args], cwd=self.repo,
            text=True, capture_output=True, env=environment,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result

    def github(self):
        return json.loads(self.gh_state.read_text())

    def tags(self):
        return dict(
            line.split() for line in self.git(
                "for-each-ref", "--format=%(refname:strip=2) %(objectname)", "refs/tags/"
            ).splitlines()
        )

    def remote_tags(self, destination="origin"):
        return {
            ref.removeprefix("refs/tags/"): target
            for target, ref in (
                line.split() for line in self.git("ls-remote", "--tags", destination).splitlines()
            )
        }

    def test_dry_run_reads_committed_versions_and_does_not_create_tags(self):
        self.write_package("spr-alpha", 'version = "9.9.9"')
        result = self.run_script()
        for tag in self.expected:
            self.assertIn(tag, result.stdout)
        self.assertNotIn("spr-stable-v", result.stdout)
        self.assertNotIn("private-v", result.stdout)
        self.assertNotIn("other-registry-v", result.stdout)
        self.assertNotIn("9.9.9", result.stdout)
        self.assertEqual(self.tags(), {})
        self.assertEqual(self.remote_tags(), {})
        self.assertEqual(self.github()["calls"], [])

    def test_execute_uses_release_commit_and_is_repeatable(self):
        (self.repo / "later.txt").write_text("After the release\n")
        self.commit("Later changes")
        self.git("config", "tag.gpgSign", "true")
        self.run_script("--commit", self.release, "--execute")
        self.run_script("--commit", self.release, "--execute")
        self.assertEqual(self.tags(), self.expected)
        self.assertEqual(self.remote_tags(), {})
        self.assertEqual(self.github()["calls"], [])

    def test_local_conflict_prevents_creating_other_tags(self):
        self.git("tag", "spr-beta-v0.2.0", self.base)
        result = self.run_script("--execute", success=False)
        self.assertIn("spr-beta-v0.2.0 points to", result.stderr)
        self.assertEqual(self.tags(), {"spr-beta-v0.2.0": self.base})

    def test_push_creates_only_release_tags_and_is_repeatable(self):
        self.git("config", "push.followTags", "true")
        self.git("tag", "-a", "unrelated", self.base, "-m", "Unrelated annotated tag")
        unrelated = self.git("rev-parse", "refs/tags/unrelated")
        self.run_script("--push")
        self.run_script("--push")
        self.assertEqual(self.remote_tags(), self.expected)
        self.assertEqual(self.tags(), {**self.expected, "unrelated": unrelated})
        state = self.github()
        self.assertEqual(set(state["releases"]), set(self.expected))
        creates = [args for args in state["calls"] if args[:2] == ["release", "create"]]
        self.assertEqual(len(creates), len(self.expected))
        for tag, args in state["releases"].items():
            self.assertIn("--verify-tag", args)
            self.assertEqual(args[args.index("--target") + 1], self.release)
            self.assertEqual(args[args.index("--title") + 1], tag)
            self.assertEqual(args[args.index("--repo") + 1], "https://github.com/example/project")
            notes = args[args.index("--notes") + 1]
            crate = tag.removesuffix("-v0.2.0")
            self.assertTrue(notes.startswith("## What's Changed\n\n"))
            subject, sha = ("Before release", self.base) if crate == "spr-beta" else ("Release", self.release)
            self.assertIn(f"* {subject} in [{sha[:7]}]", notes)
            self.assertIn(f"https://github.com/example/project/commit/{sha}", notes)
            self.assertIn(
                f"**Full Changelog**: https://github.com/example/project/commits/{tag}/sdk-libs/{crate}",
                notes,
            )

    def test_remote_conflict_prevents_local_creation(self):
        self.git("tag", "spr-beta-v0.2.0", self.base)
        self.git("push", "origin", "refs/tags/spr-beta-v0.2.0")
        self.git("tag", "-d", "spr-beta-v0.2.0")
        result = self.run_script("--push", success=False)
        self.assertIn("spr-beta-v0.2.0 points to", result.stderr)
        self.assertEqual(self.tags(), {})
        self.assertEqual(self.remote_tags(), {"spr-beta-v0.2.0": self.base})
        self.assertEqual(self.github()["calls"], [])

    def test_distinct_push_destination_conflict_aborts_before_github_operations(self):
        self.run_script("--execute")
        self.git("push", "--atomic", "origin", *(f"refs/tags/{tag}" for tag in self.expected))
        destination = Path(self.temp.name) / "push.git"
        self.git("init", "--quiet", "--bare", str(destination))
        self.git("push", "--atomic", str(destination), *(f"{self.base}:refs/tags/{tag}" for tag in self.expected))
        self.git("tag", "-d", *self.expected)
        self.git("remote", "set-url", "--push", "origin", str(destination))
        result = self.run_script("--push", "--update-notes", success=False)
        self.assertIn("points to", result.stderr)
        self.assertEqual(self.tags(), {})
        self.assertEqual(self.remote_tags(), self.expected)
        self.assertEqual(self.remote_tags(str(destination)), {tag: self.base for tag in self.expected})
        self.assertEqual(self.github()["calls"], [])

    def test_distinct_push_destination_receives_tags_even_when_fetch_destination_has_them(self):
        self.run_script("--execute")
        self.git("push", "--atomic", "origin", *(f"refs/tags/{tag}" for tag in self.expected))
        self.git("tag", "-d", *self.expected)
        destination = Path(self.temp.name) / "push.git"
        self.git("init", "--quiet", "--bare", str(destination))
        self.git("remote", "set-url", "--push", "origin", str(destination))
        self.run_script("--push")
        self.assertEqual(self.tags(), self.expected)
        self.assertEqual(self.remote_tags(), self.expected)
        self.assertEqual(self.remote_tags(str(destination)), self.expected)
        views = [args for args in self.github()["calls"] if args[:2] == ["repo", "view"]]
        self.assertEqual([args[2] for args in views], [str(destination)])

    def test_multiple_distinct_push_destinations_are_rejected_before_mutation(self):
        destination = Path(self.temp.name) / "push.git"
        self.git("init", "--quiet", "--bare", str(destination))
        self.git("remote", "set-url", "--add", "--push", "origin", str(self.remote))
        self.git("remote", "set-url", "--add", "--push", "origin", str(destination))
        result = self.run_script("--push", success=False)
        self.assertIn("exactly one distinct push destination", result.stderr)
        self.assertEqual(self.tags(), {})
        self.assertEqual(self.remote_tags(), {})
        self.assertEqual(self.remote_tags(str(destination)), {})
        self.assertEqual(self.github()["calls"], [])

    def test_duplicate_push_urls_for_one_destination_are_supported(self):
        self.git("remote", "set-url", "--add", "--push", "origin", str(self.remote))
        self.git("remote", "set-url", "--add", "--push", "origin", str(self.remote))
        self.run_script("--push")
        self.assertEqual(self.remote_tags(), self.expected)

    def test_push_creates_only_missing_github_releases(self):
        self.run_script("--execute")
        self.git("push", "--atomic", "origin", *(f"refs/tags/{tag}" for tag in self.expected))
        existing = {"spr-beta-v0.2.0": ["existing notes"], "unrelated-v1.0.0": ["unrelated"]}
        self.gh_state.write_text(json.dumps({"releases": existing, "calls": []}))
        self.run_script("--push")
        state = self.github()
        self.assertEqual(set(state["releases"]), set(self.expected) | set(existing))
        for tag, release in existing.items():
            self.assertEqual(state["releases"][tag], release)
        creates = [args[2] for args in state["calls"] if args[:2] == ["release", "create"]]
        self.assertEqual(set(creates), {"spr-alpha-v0.2.0", "spr-new-v0.2.0"})

    def test_github_lookup_errors_abort_before_creating_tags(self):
        for status in ("403", "404", "500"):
            with self.subTest(status=status):
                result = self.run_script("--push", success=False, env={"MOCK_GH_LOOKUP_ERROR": status})
                self.assertIn(f"HTTP {status}", result.stderr)
                self.assertEqual(self.tags(), {})
                self.assertEqual(self.remote_tags(), {})
                self.assertEqual(self.github()["releases"], {})

    def test_update_notes_requires_push(self):
        for options in ([], ["--execute"]):
            result = self.run_script(*options, "--update-notes", success=False)
            self.assertIn("--update-notes requires --push", result.stderr)
        self.assertEqual(self.tags(), {})
        self.assertEqual(self.github()["calls"], [])

    def test_update_notes_preserves_existing_release_properties(self):
        releases = {
            tag: {
                "title": "Old title", "body": "Old notes", "targetCommitish": self.release,
                "draft": False, "prerelease": False, "latest": False,
            } for tag in self.expected
        }
        unrelated = {"title": "Unrelated title", "body": "Unrelated notes", "latest": True}
        releases["unrelated-v1.0.0"] = unrelated
        self.gh_state.write_text(json.dumps({"releases": releases, "calls": []}))
        self.run_script("--push", "--update-notes")
        state = self.github()
        self.assertEqual(state["releases"]["unrelated-v1.0.0"], unrelated)
        edits = [args for args in state["calls"] if args[:2] == ["release", "edit"]]
        self.assertEqual({args[2] for args in edits}, set(self.expected))
        for args in edits:
            self.assertEqual(set(args[3::2]), {"--repo", "--title", "--notes"})
        for tag in self.expected:
            release = state["releases"][tag]
            self.assertEqual(release["title"], tag)
            self.assertTrue(release["body"].startswith("## What's Changed\n\n"))
            self.assertEqual(
                {key: value for key, value in release.items() if key not in ("title", "body")},
                {"targetCommitish": self.release, "draft": False, "prerelease": False, "latest": False},
            )

    def test_notes_scope_history_deduplicate_prs_cache_metadata_and_bound_commit(self):
        self.git("tag", "rust-sdk-v0.2.0", self.release)
        self.write_source("spr-alpha", "First change")
        first = self.commit("First alpha change (#41)")
        self.git("tag", "spr-alpha-v0.2.0", first)
        self.write_source("private", "Private change")
        self.commit("Unrelated change (#99)")
        for change in ("Second", "Third"):
            self.write_source("spr-alpha", change)
            self.write_source("spr-beta", change)
            self.commit(f"{change} shared change (#41)")
        self.write_workspace("0.3.0")
        self.write_package("spr-alpha", 'version = "0.3.0"')
        release = self.commit("Release crates (#42)")
        self.write_source("spr-alpha", "Future change")
        self.commit("After the selected release (#123)")
        state = self.github()
        state["prs"] = {
            "41": {"title": "Add shared feature", "author": {"login": "alice"}},
            "42": {"title": "Release crates", "author": {"login": "bob"}},
        }
        self.gh_state.write_text(json.dumps(state))
        self.run_script("--commit", release, "--push")
        state = self.github()
        self.assertEqual(set(state["releases"]), {"spr-alpha-v0.3.0", "spr-beta-v0.3.0"})
        for crate, previous in (("alpha", "spr-alpha-v0.2.0"), ("beta", "rust-sdk-v0.2.0")):
            args = state["releases"][f"spr-{crate}-v0.3.0"]
            notes = args[args.index("--notes") + 1]
            self.assertEqual(notes.count("* Add shared feature by @alice in #41"), 1)
            if crate == "alpha":
                self.assertIn("* Release crates by @bob in #42", notes)
            else:
                self.assertNotIn("#42", notes)
            self.assertNotIn("#99", notes)
            self.assertNotIn("#123", notes)
            self.assertIn(f"/compare/{previous}...spr-{crate}-v0.3.0", notes)
        views = [args[2] for args in state["calls"] if args[:2] == ["pr", "view"]]
        self.assertEqual(sorted(views), ["41", "42"])

    def test_mismatched_package_tag_falls_back_to_validated_aggregate(self):
        self.git("tag", "spr-alpha-v0.1.0", self.release)
        self.git("tag", "rust-sdk-v0.1.0", self.base)
        self.run_script("--push")
        args = self.github()["releases"]["spr-alpha-v0.2.0"]
        notes = args[args.index("--notes") + 1]
        self.assertIn("/compare/rust-sdk-v0.1.0...spr-alpha-v0.2.0", notes)
        self.assertNotIn("Before release", notes)

    def test_invalid_aggregate_uses_full_crate_history_for_first_release(self):
        self.git("tag", "rust-sdk-v0.1.0", self.release)
        self.run_script("--push")
        args = self.github()["releases"]["spr-alpha-v0.2.0"]
        notes = args[args.index("--notes") + 1]
        self.assertIn("* Before release in", notes)
        self.assertIn("* Release in", notes)
        self.assertIn("/commits/spr-alpha-v0.2.0/sdk-libs/spr-alpha", notes)
        self.assertNotIn("/compare/", notes)

    def test_pr_lookup_failure_uses_commit_subject_without_inventing_author(self):
        self.write_workspace("0.3.0")
        self.write_package("spr-alpha", 'version = "0.3.0"')
        self.write_source("spr-beta", "Source change in the same PR")
        self.commit("Actual release subject (#77)")
        result = self.run_script("--push", env={"MOCK_GH_PR_ERROR": "1"})
        state = self.github()
        for args in state["releases"].values():
            notes = args[args.index("--notes") + 1]
            self.assertIn("* Actual release subject in #77", notes)
            self.assertNotIn(" by @", notes)
        views = [args for args in state["calls"] if args[:2] == ["pr", "view"]]
        self.assertEqual(len(views), 1)
        self.assertIn("using its commit subject without an author", result.stderr)

    def test_inherited_version_only_bump_has_factual_notes(self):
        self.git("tag", "spr-beta-v0.2.0", self.release)
        self.write_workspace("0.3.0")
        self.commit("Bump the inherited workspace version (#88)")
        self.run_script("--push")
        state = self.github()
        self.assertEqual(set(state["releases"]), {"spr-beta-v0.3.0"})
        args = state["releases"]["spr-beta-v0.3.0"]
        self.assertEqual(args[args.index("--notes") + 1], (
            "## What's Changed\n\n* Version updated to `0.3.0`.\n\n"
            "**Full Changelog**: https://github.com/example/project/compare/spr-beta-v0.2.0...spr-beta-v0.3.0\n"
        ))

    def write_source(self, crate, value):
        path = self.repo / "sdk-libs" / crate / "src" / "lib.rs"
        path.parent.mkdir(exist_ok=True)
        path.write_text(value + "\n")

    def test_github_auth_failure_aborts_before_creating_tags(self):
        result = self.run_script("--push", success=False, env={"MOCK_GH_AUTH_ERROR": "1"})
        self.assertIn("not authenticated", result.stderr)
        self.assertEqual(self.tags(), {})
        self.assertEqual(self.remote_tags(), {})

    def test_missing_gh_aborts_before_creating_tags(self):
        self.mock_gh.unlink()
        (self.bin / "git").symlink_to(shutil.which("git"))
        result = self.run_script("--push", success=False, env={"PATH": str(self.bin)})
        self.assertIn("GitHub CLI 'gh' is required", result.stderr)
        self.assertEqual(self.tags(), {})
        self.assertEqual(self.remote_tags(), {})

    def test_rejected_push_leaves_remote_unchanged_and_local_tags_for_retry(self):
        hook = self.remote / "hooks" / "update"
        hook.write_text('#!/bin/sh\n[ "$1" != "refs/tags/spr-beta-v0.2.0" ]\n')
        hook.chmod(0o755)
        self.git("--git-dir", str(self.remote), "config", "core.hooksPath", str(hook.parent))
        result = self.run_script("--push", success=False)
        self.assertIn("hook declined", result.stderr)
        self.assertEqual(self.remote_tags(), {})
        self.assertEqual(self.tags(), self.expected)
        self.assertEqual(self.github()["releases"], {})

    def test_matching_annotated_tags_are_preserved(self):
        self.git("tag", "-a", "spr-beta-v0.2.0", self.release, "-m", "Existing release")
        tag_object = self.git("rev-parse", "refs/tags/spr-beta-v0.2.0")
        self.run_script("--execute")
        self.assertEqual(self.git("rev-parse", "refs/tags/spr-beta-v0.2.0"), tag_object)
        self.assertEqual(self.git("rev-parse", "spr-beta-v0.2.0^{commit}"), self.release)

    def test_no_version_changes_fail_without_creating_tags(self):
        (self.repo / "later.txt").write_text("After the release\n")
        self.commit("Later changes")
        result = self.run_script("--execute", success=False)
        self.assertIn("no crates.io package version changes", result.stderr)
        self.assertEqual(self.tags(), {})

    def test_explicit_base_compares_release_across_multiple_commits(self):
        (self.repo / "later.txt").write_text("After the release\n")
        later = self.commit("Later changes")
        self.run_script("--base", self.base, "--execute")
        self.assertEqual(self.tags(), {tag: later for tag in self.expected})


if __name__ == "__main__":
    unittest.main()
