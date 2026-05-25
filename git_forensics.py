#!/usr/bin/env python3
"""
git_forensics.py -- KAPE Git Forensics Tool
Forensic analysis of .git repos collected from disk (e.g. via KAPE).
No git binary required -- uses dulwich (pure Python git).

Usage:
    git_forensics.py <evidence_root>                    # summary mode
    git_forensics.py <evidence_root> --extract <outdir> # full extraction
    git_forensics.py <evidence_root> --deleted <outdir> # deleted files only
"""

import argparse
import difflib
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from dulwich.errors import NotGitRepository
from dulwich.objects import Blob, Commit, Tree
from dulwich.repo import Repo
from dulwich.diff_tree import tree_changes, CHANGE_ADD, CHANGE_MODIFY, CHANGE_DELETE, CHANGE_RENAME

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Keywords that suggest anti-forensic intent — only meaningful combined with evidence
ANTIFORENSIC_MSG_KEYWORDS = {
    "delete", "remov", "wipe", "erase", "purge", "overwrite",
    "cover", "hide", "clear log", "clean log", "drop log",
}

# File types that carry forensic value — deletion of these is noteworthy
SENSITIVE_EXTENSIONS = {".log", ".json", ".db", ".sqlite", ".sqlite3", ".csv", ".xml", ".bak"}

# Filename fragments that suggest credentials or auth data
SENSITIVE_NAME_FRAGMENTS = {
    "admin", "credential", "password", "passwd", "secret",
    "token", "key", "auth", "session", "config", "log",
}

# Commits this close together (seconds) flag as rapid succession
RAPID_SUCCESSION_SECONDS = 300

CHANGE_SYMBOL = {
    CHANGE_ADD: "+",
    CHANGE_MODIFY: "~",
    CHANGE_DELETE: "-",
    CHANGE_RENAME: "R",
}

BINARY_CHECK_BYTES = 8192


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def ts_to_iso(unix_ts: int, tz_offset: int = 0) -> str:
    dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def slugify(s: str, maxlen: int = 40) -> str:
    s = re.sub(r"[^\w\s-]", "", s.lower())
    s = re.sub(r"[\s_-]+", "_", s).strip("_")
    return s[:maxlen]


def is_binary(data: bytes) -> bool:
    return b"\x00" in data[:BINARY_CHECK_BYTES]


def detect_suspicion(ci: "CommitInfo", prev_ci: "CommitInfo | None" = None) -> list[str]:
    """
    Return list of suspicion reasons for a commit.
    Empty list = not suspicious.
    Combines message keywords WITH evidence (changes, file types, timing).
    """
    reasons = []
    msg_lower = ci.message.lower()
    has_keyword = any(kw in msg_lower for kw in ANTIFORENSIC_MSG_KEYWORDS)

    deleted = ci.deleted_files
    all_changes = ci.changes
    only_deletions = bool(all_changes) and all(ch.symbol == "-" for ch in all_changes)

    sensitive_deleted = [
        ch for ch in deleted
        if ch.old_path and (
            Path(ch.old_path).suffix.lower() in SENSITIVE_EXTENSIONS
            or any(frag in ch.old_path.lower() for frag in SENSITIVE_NAME_FRAGMENTS)
        )
    ]

    # Rule 1: keyword + deletions in same commit
    if has_keyword and deleted:
        files = ", ".join(ch.old_path or "?" for ch in deleted[:3])
        if len(deleted) > 3:
            files += f" (+{len(deleted) - 3} more)"
        reasons.append(f"anti-forensic keyword in message + {len(deleted)} deletion(s): {files}")

    # Rule 2: sensitive file deleted (with or without keyword)
    if sensitive_deleted:
        files = ", ".join(ch.old_path or "?" for ch in sensitive_deleted[:3])
        reasons.append(f"sensitive file(s) deleted: {files}")

    # Rule 3: commit is pure deletions only (no adds/modifies)
    if only_deletions and len(deleted) > 1:
        reasons.append(f"commit contains ONLY deletions ({len(deleted)} files, nothing added)")

    # Rule 4: keyword in message but NO file changes (metadata/message scrub attempt)
    if has_keyword and not all_changes:
        reasons.append("anti-forensic keyword in message but no file changes (possible empty scrub commit)")

    # Rule 5: rapid succession after previous commit
    if prev_ci is not None:
        gap = abs(ci.timestamp - prev_ci.timestamp)
        if gap <= RAPID_SUCCESSION_SECONDS and (has_keyword or sensitive_deleted):
            reasons.append(
                f"rapid succession: {gap}s after previous commit "
                f"({prev_ci.sha_short} \"{prev_ci.message[:40]}\")"
            )

    return reasons


# ---------------------------------------------------------------------------
# Repo discovery
# ---------------------------------------------------------------------------

def find_git_repos(root: Path) -> list[Path]:
    """Walk root for directories containing a .git subdir."""
    repos = []
    for dirpath, dirnames, _ in os.walk(root):
        if ".git" in dirnames:
            repos.append(Path(dirpath))
            dirnames.remove(".git")
    return sorted(repos)


# ---------------------------------------------------------------------------
# Dulwich helpers
# ---------------------------------------------------------------------------

def open_repo(path: Path) -> Repo | None:
    try:
        return Repo(str(path))
    except NotGitRepository:
        return None
    except Exception:
        return None


def get_head_sha(repo: Repo) -> bytes | None:
    """Resolve HEAD SHA from refs dict -- avoids dulwich symref bug."""
    try:
        refs = repo.refs.as_dict()
        if not refs:
            return None
        return (
            refs.get(b"refs/heads/master")
            or refs.get(b"refs/heads/main")
            or next(iter(refs.values()))
        )
    except Exception:
        return None


def get_all_branch_shas(repo: Repo) -> dict[str, bytes]:
    """Return {branch_name: sha} for all local branches."""
    result = {}
    try:
        for key, sha in repo.refs.as_dict().items():
            key_str = key.decode("utf-8", errors="replace")
            if key_str.startswith("refs/heads/"):
                branch = key_str[len("refs/heads/"):]
                result[branch] = sha
    except Exception:
        pass
    return result


def walk_all_commits(repo: Repo) -> list[Commit]:
    """Walk all commits reachable from all branches, deduplicated."""
    seen = set()
    commits = []
    branches = get_all_branch_shas(repo)
    tips = list(branches.values()) if branches else []

    if not tips:
        return []

    try:
        for entry in repo.get_walker(include=tips):
            sha = entry.commit.id
            if sha not in seen:
                seen.add(sha)
                commits.append(entry.commit)
    except Exception:
        pass

    return commits


def get_blob_data(repo: Repo, sha: bytes) -> bytes | None:
    try:
        obj = repo.get_object(sha)
        if isinstance(obj, Blob):
            return obj.as_raw_string()
    except Exception:
        pass
    return None


def get_blob_lines(repo: Repo, sha: bytes) -> list[str]:
    data = get_blob_data(repo, sha)
    if data is None or is_binary(data):
        return []
    return data.decode("utf-8", errors="replace").splitlines(keepends=True)


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

class FileChange:
    def __init__(self, symbol: str, old_path: str | None, new_path: str | None,
                 diff_lines: list[str], is_binary_file: bool, old_sha: bytes | None,
                 new_sha: bytes | None):
        self.symbol = symbol
        self.old_path = old_path
        self.new_path = new_path
        self.diff_lines = diff_lines
        self.is_binary = is_binary_file
        self.old_sha = old_sha
        self.new_sha = new_sha

    @property
    def path(self) -> str:
        return self.new_path or self.old_path or "(unknown)"


def diff_trees(repo: Repo, old_tree_sha: bytes | None, new_tree_sha: bytes | None) -> list[FileChange]:
    changes = []
    try:
        old_tree = repo.get_object(old_tree_sha) if old_tree_sha else None
        new_tree = repo.get_object(new_tree_sha) if new_tree_sha else None
        raw_changes = list(tree_changes(
            repo.object_store,
            old_tree.id if old_tree else None,
            new_tree.id if new_tree else None,
        ))
    except Exception as e:
        return []

    for ch in raw_changes:
        symbol = CHANGE_SYMBOL.get(ch.type, "?")
        old_path = ch.old.path.decode("utf-8", errors="replace") if ch.old and ch.old.path else None
        new_path = ch.new.path.decode("utf-8", errors="replace") if ch.new and ch.new.path else None
        old_sha = ch.old.sha if ch.old else None
        new_sha = ch.new.sha if ch.new else None

        old_data = get_blob_data(repo, old_sha) if old_sha else None
        new_data = get_blob_data(repo, new_sha) if new_sha else None

        binary = (old_data is not None and is_binary(old_data)) or \
                 (new_data is not None and is_binary(new_data))

        diff_lines = []
        if not binary:
            old_lines = old_data.decode("utf-8", errors="replace").splitlines(keepends=True) if old_data else []
            new_lines = new_data.decode("utf-8", errors="replace").splitlines(keepends=True) if new_data else []
            diff_lines = list(difflib.unified_diff(
                old_lines, new_lines,
                fromfile=f"a/{old_path or ''}",
                tofile=f"b/{new_path or ''}",
                lineterm="",
            ))

        changes.append(FileChange(symbol, old_path, new_path, diff_lines, binary, old_sha, new_sha))

    return changes


# ---------------------------------------------------------------------------
# Core data model
# ---------------------------------------------------------------------------

class CommitInfo:
    def __init__(self, commit: Commit, changes: list[FileChange], repo_name: str):
        self.commit = commit
        self.changes = changes
        self.repo_name = repo_name
        self.suspicion_reasons: list[str] = []  # populated by analyze_repo after walk

    @property
    def sha(self) -> str:
        return self.commit.id.decode()

    @property
    def sha_short(self) -> str:
        return self.sha[:8]

    @property
    def author(self) -> str:
        return self.commit.author.decode("utf-8", errors="replace")

    @property
    def message(self) -> str:
        return self.commit.message.decode("utf-8", errors="replace").strip()

    @property
    def timestamp(self) -> int:
        return self.commit.author_time

    @property
    def timestamp_str(self) -> str:
        return ts_to_iso(self.commit.author_time)

    @property
    def suspicious(self) -> bool:
        return bool(self.suspicion_reasons)

    @property
    def deleted_files(self) -> list[FileChange]:
        return [c for c in self.changes if c.symbol == "-"]


class RepoInfo:
    def __init__(self, path: Path, repo: Repo):
        self.path = path
        self.name = path.name
        self.repo = repo
        self.commits: list[CommitInfo] = []
        self.branches: dict[str, bytes] = {}
        self.config_user_name: str = ""
        self.config_user_email: str = ""
        self.gitkraken_timestamps: dict[str, dict] = {}
        self.error: str = ""

    @property
    def authors(self) -> list[str]:
        seen = set()
        result = []
        for ci in self.commits:
            a = ci.author
            if a not in seen:
                seen.add(a)
                result.append(a)
        return result

    @property
    def date_range(self) -> tuple[str, str]:
        if not self.commits:
            return ("", "")
        sorted_c = sorted(self.commits, key=lambda c: c.timestamp)
        return (sorted_c[-1].timestamp_str, sorted_c[0].timestamp_str)  # newest, oldest

    @property
    def suspicious_commits(self) -> list[CommitInfo]:
        return [c for c in self.commits if c.suspicious]


# ---------------------------------------------------------------------------
# Analysis engine
# ---------------------------------------------------------------------------

def analyze_repo(path: Path) -> RepoInfo:
    repo = open_repo(path)
    info = RepoInfo(path, repo)

    if repo is None:
        info.error = "Cannot open repo (NotGitRepository or permission error)"
        return info

    # Config
    try:
        cfg = repo.get_config()
        try:
            info.config_user_name = cfg.get((b"user",), b"name", b"").decode()
        except Exception:
            pass
        try:
            info.config_user_email = cfg.get((b"user",), b"email", b"").decode()
        except Exception:
            pass
        for section in cfg.sections():
            if section[0] == b"branch":
                branch = section[1].decode()
                gk = {}
                for key in (b"gk-last-accessed", b"gk-last-modified"):
                    try:
                        val = cfg.get(section, key, b"").decode()
                        if val:
                            gk[key.decode()] = val
                    except Exception:
                        pass
                if gk:
                    info.gitkraken_timestamps[branch] = gk
    except Exception:
        pass

    # Branches
    info.branches = get_all_branch_shas(repo)

    # Commits
    raw_commits = walk_all_commits(repo)
    for c in raw_commits:
        parent_tree = None
        if c.parents:
            try:
                parent = repo.get_object(c.parents[0])
                parent_tree = parent.tree
            except Exception:
                pass
        changes = diff_trees(repo, parent_tree, c.tree)
        info.commits.append(CommitInfo(c, changes, info.name))

    # Sort chronologically for suspicion analysis (need prev commit context)
    info.commits.sort(key=lambda c: c.timestamp)

    # Suspicion detection — needs ordered commits for rapid succession check
    for idx, ci in enumerate(info.commits):
        prev = info.commits[idx - 1] if idx > 0 else None
        ci.suspicion_reasons = detect_suspicion(ci, prev)

    # Flip to newest-first for display
    info.commits.reverse()

    return info


# ---------------------------------------------------------------------------
# Summary mode output
# ---------------------------------------------------------------------------

def print_summary(repos: list[RepoInfo]) -> None:
    print("=" * 70)
    print("GIT FORENSICS -- SUMMARY")
    print(f"Repos found: {len(repos)}")
    print("=" * 70)

    all_authors: dict[str, list[str]] = {}  # email -> [repo names]

    for info in repos:
        print(f"\n{'-' * 70}")
        print(f"REPO : {info.path}")
        print(f"Name : {info.name}")

        if info.error:
            print(f"ERROR: {info.error}")
            continue

        print(f"Branches   : {', '.join(info.branches.keys()) or '(none)'}")
        print(f"Commits    : {len(info.commits)}")

        if info.commits:
            newest, oldest = info.date_range
            print(f"Date range : {oldest}  ->  {newest}")

        if info.config_user_name or info.config_user_email:
            print(f"Config user: {info.config_user_name} <{info.config_user_email}>")

        if info.gitkraken_timestamps:
            for branch, gk in info.gitkraken_timestamps.items():
                for k, v in gk.items():
                    print(f"GitKraken  : [{branch}] {k} = {v}")

        if info.authors:
            print(f"Authors:")
            for a in info.authors:
                print(f"  {a}")
                # track for cross-repo correlation
                match = re.search(r"<([^>]+)>", a)
                if match:
                    email = match.group(1).lower()
                    all_authors.setdefault(email, [])
                    if info.name not in all_authors[email]:
                        all_authors[email].append(info.name)

        if info.suspicious_commits:
            print(f"Suspicious commits ({len(info.suspicious_commits)}):")
            for sc in info.suspicious_commits:
                print(f"  [!] {sc.sha_short}  {sc.timestamp_str}  \"{sc.message}\"")
                for reason in sc.suspicion_reasons:
                    print(f"       -> {reason}")

        total_deleted = sum(len(ci.deleted_files) for ci in info.commits)
        if total_deleted:
            print(f"Deleted files across history: {total_deleted}")

    # Cross-repo author correlation
    shared = {email: repos for email, repos in all_authors.items() if len(repos) > 1}
    if shared:
        print(f"\n{'-' * 70}")
        print("CROSS-REPO AUTHOR CORRELATION:")
        for email, repo_names in shared.items():
            print(f"  {email}  ->  {', '.join(repo_names)}")

    # Cross-repo timeline overview
    all_commits = []
    for info in repos:
        for ci in info.commits:
            all_commits.append(ci)
    all_commits.sort(key=lambda c: c.timestamp)

    if all_commits:
        print(f"\n{'-' * 70}")
        print("CROSS-REPO TIMELINE (oldest -> newest):")
        for ci in all_commits:
            flag = "  [!]" if ci.suspicious else ""
            print(f"  {ci.timestamp_str}  [{ci.repo_name}]  {ci.sha_short}  {ci.message[:60]}{flag}")


# ---------------------------------------------------------------------------
# Extract mode
# ---------------------------------------------------------------------------

def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def format_commit_file(ci: CommitInfo) -> str:
    lines = []
    lines.append(f"commit  {ci.sha}")
    lines.append(f"author  {ci.author}")
    lines.append(f"date    {ci.timestamp_str}  ({ci.timestamp})")
    lines.append(f"message {ci.message}")
    for reason in ci.suspicion_reasons:
        lines.append(f"flag    [SUSPICIOUS] {reason}")
    lines.append("")
    lines.append("Changes:")
    for ch in ci.changes:
        if ch.symbol == "R":
            lines.append(f"  {ch.symbol}  {ch.old_path} -> {ch.new_path}")
        else:
            lines.append(f"  {ch.symbol}  {ch.path}")
            if ch.symbol == "-" and ch.new_sha is None and ch.old_sha:
                lines.append(f"     [DELETED -- recovered in deleted/ dir  sha:{ch.old_sha.hex()[:12]}]")
            if ch.is_binary:
                size_info = ""
                lines.append(f"     [BINARY  sha:{(ch.new_sha or ch.old_sha or b'').hex()[:12]}{size_info}]")

    for ch in ci.changes:
        if ch.diff_lines and not ch.is_binary:
            lines.append("")
            lines.append(f"Diff: {ch.path}")
            lines.extend(line.rstrip("\n") for line in ch.diff_lines[:200])
            if len(ch.diff_lines) > 200:
                lines.append(f"... [{len(ch.diff_lines) - 200} more lines truncated]")

    return "\n".join(lines) + "\n"


def extract_repos(repos: list[RepoInfo], out_root: Path) -> None:
    out_root.mkdir(parents=True, exist_ok=True)

    all_commits_global: list[CommitInfo] = []

    for info in repos:
        if info.error or not info.commits:
            continue

        repo_dir = out_root / info.name

        # summary.txt
        summary_lines = [
            f"REPO     : {info.path}",
            f"Branches : {', '.join(info.branches.keys())}",
            f"Commits  : {len(info.commits)}",
        ]
        if info.commits:
            newest, oldest = info.date_range
            summary_lines.append(f"Oldest   : {oldest}")
            summary_lines.append(f"Newest   : {newest}")
        if info.config_user_name or info.config_user_email:
            summary_lines.append(f"Config   : {info.config_user_name} <{info.config_user_email}>")
        for branch, gk in info.gitkraken_timestamps.items():
            for k, v in gk.items():
                summary_lines.append(f"GitKraken: [{branch}] {k} = {v}")
        summary_lines.append("Authors:")
        for a in info.authors:
            summary_lines.append(f"  {a}")
        suspicious = info.suspicious_commits
        if suspicious:
            summary_lines.append(f"\nSuspicious commits ({len(suspicious)}):")
            for sc in suspicious:
                summary_lines.append(f"  [!] {sc.sha_short}  {sc.timestamp_str}  \"{sc.message}\"")

        write_file(repo_dir / "summary.txt", "\n".join(summary_lines) + "\n")

        # commits/ -- sorted oldest-first for numbering
        sorted_commits = sorted(info.commits, key=lambda c: c.timestamp)
        for idx, ci in enumerate(sorted_commits, 1):
            filename = f"{idx:04d}_{ci.sha_short}_{slugify(ci.message)}.txt"
            write_file(repo_dir / "commits" / filename, format_commit_file(ci))

        # branches/
        for branch, tip_sha in info.branches.items():
            branch_commits = sorted(info.commits, key=lambda c: c.timestamp, reverse=True)
            lines = [f"Branch: {branch}  tip: {tip_sha.decode() if isinstance(tip_sha, bytes) else tip_sha}", ""]
            for ci in branch_commits:
                flag = "  [!]" if ci.suspicious else ""
                lines.append(f"{ci.timestamp_str}  {ci.sha_short}  {ci.message}{flag}")
            write_file(repo_dir / "branches" / f"{branch}.txt", "\n".join(lines) + "\n")

        # deleted/ -- recover content of deleted blobs
        deleted_dir = repo_dir / "deleted"
        for ci in info.commits:
            for ch in ci.deleted_files:
                if ch.old_sha:
                    data = get_blob_data(info.repo, ch.old_sha)
                    if data:
                        safe_name = re.sub(r"[\\/:*?\"<>|]", "_", ch.old_path or "unknown")
                        out_path = deleted_dir / f"{ci.sha_short}_{safe_name}"
                        out_path.parent.mkdir(parents=True, exist_ok=True)
                        out_path.write_bytes(data)

        all_commits_global.extend(info.commits)

    # timeline.txt -- cross-repo, chronological
    all_commits_global.sort(key=lambda c: c.timestamp)
    lines = ["CROSS-REPO TIMELINE", "=" * 70, ""]
    for ci in all_commits_global:
        flag = "  [!]" if ci.suspicious else ""
        lines.append(f"{ci.timestamp_str}  [{ci.repo_name:20s}]  {ci.sha_short}  {ci.message[:60]}{flag}")
    write_file(out_root / "timeline.txt", "\n".join(lines) + "\n")

    # authors.txt -- cross-repo author list
    seen_authors: dict[str, list[str]] = {}
    for ci in all_commits_global:
        match = re.search(r"<([^>]+)>", ci.author)
        email = match.group(1).lower() if match else ci.author.lower()
        seen_authors.setdefault(email, {"full": ci.author, "repos": set()})
        seen_authors[email]["repos"].add(ci.repo_name)

    lines = ["AUTHORS", "=" * 70, ""]
    for email, data in sorted(seen_authors.items()):
        repos_str = ", ".join(sorted(data["repos"]))
        lines.append(f"{data['full']}")
        lines.append(f"  repos: {repos_str}")
        lines.append("")
    write_file(out_root / "authors.txt", "\n".join(lines) + "\n")

    print(f"Extracted to: {out_root}")
    print(f"  timeline.txt")
    print(f"  authors.txt")
    for info in repos:
        if not info.error:
            print(f"  {info.name}/  ({len(info.commits)} commits)")


# ---------------------------------------------------------------------------
# Deleted-only mode
# ---------------------------------------------------------------------------

def extract_deleted(repos: list[RepoInfo], out_root: Path) -> None:
    out_root.mkdir(parents=True, exist_ok=True)
    total = 0

    for info in repos:
        if info.error or not info.commits:
            continue

        for ci in info.commits:
            for ch in ci.deleted_files:
                if ch.old_sha:
                    data = get_blob_data(info.repo, ch.old_sha)
                    if data:
                        safe_name = re.sub(r"[\\/:*?\"<>|]", "_", ch.old_path or "unknown")
                        out_path = out_root / info.name / f"{ci.sha_short}_{safe_name}"
                        out_path.parent.mkdir(parents=True, exist_ok=True)
                        out_path.write_bytes(data)
                        print(f"  recovered: [{info.name}] {ci.sha_short} -> {ch.old_path}")
                        total += 1

    print(f"\nTotal recovered: {total} files -> {out_root}")


# ---------------------------------------------------------------------------
# Recreate HEAD
# ---------------------------------------------------------------------------

def recreate_head(repos: list[RepoInfo]) -> None:
    print("=" * 70)
    print("WARNING: --recreate-head MODIFIES the .git directory.")
    print("Run this on a working COPY of evidence, not the original.")
    print("=" * 70)
    print()

    for info in repos:
        head_path = info.path / ".git" / "HEAD"

        if head_path.exists():
            print(f"  [{info.name}] HEAD exists ({head_path.read_text().strip()}) -- skipped")
            continue

        branches = get_all_branch_shas(info.repo)
        if not branches:
            print(f"  [{info.name}] no branches found -- cannot recreate HEAD")
            continue

        branch = (
            "master" if "master" in branches else
            "main"   if "main"   in branches else
            sorted(branches.keys())[0]
        )

        head_path.write_text(f"ref: refs/heads/{branch}\n", encoding="ascii")
        tip = branches[branch].decode() if isinstance(branches[branch], bytes) else branches[branch]
        print(f"  [{info.name}] HEAD recreated -> refs/heads/{branch}  ({tip[:8]})")
        print(f"             git log: git -C \"{info.path}\" -c safe.directory=\"*\" log --oneline")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="KAPE Git Forensics Tool -- no git binary required",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("evidence_root", help="Root of KAPE evidence directory")
    parser.add_argument("--extract", metavar="OUTDIR", help="Full forensic extraction to directory")
    parser.add_argument("--deleted", metavar="OUTDIR", help="Recover only deleted files to directory")
    parser.add_argument("--recreate-head", action="store_true",
                        help="Recreate missing HEAD files so native git works (MODIFIES .git -- use on working copy only)")
    args = parser.parse_args()

    root = Path(args.evidence_root)
    if not root.exists():
        print(f"[ERROR] Path not found: {root}", file=sys.stderr)
        sys.exit(1)

    repo_paths = find_git_repos(root)
    print(f"Found {len(repo_paths)} git repo(s) under {root}\n")

    repos: list[RepoInfo] = []
    for path in repo_paths:
        print(f"  Analyzing: {path} ...", end=" ", flush=True)
        info = analyze_repo(path)
        repos.append(info)
        if info.error:
            print(f"ERROR: {info.error}")
        else:
            print(f"{len(info.commits)} commits")

    print()

    if args.recreate_head:
        recreate_head(repos)
    elif args.extract:
        extract_repos(repos, Path(args.extract))
    elif args.deleted:
        extract_deleted(repos, Path(args.deleted))
    else:
        print_summary(repos)


if __name__ == "__main__":
    main()
