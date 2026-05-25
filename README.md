# git_forensics

Forensic analysis of `.git` repositories collected from disk — no git binary required.

Built for evidence collected via [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) or similar disk acquisition tools, where the standard `git` binary fails due to ownership/safe.directory mismatches on collected NTFS evidence.

---

## Why not just use git?

When KAPE collects a `.git` directory from a target machine, running `git log` on the collected evidence fails:

```
fatal: not a git repository         # run from outside the dir
your current branch 'master' does not have any commits yet  # run from inside
```

Root cause: Git 2.35+ safe.directory enforcement + NTFS ownership mismatch on the analysis machine. Even `-c safe.directory='*'` does not fully resolve it.

**git_forensics** bypasses the git binary entirely using [dulwich](https://www.dulwich.io/) (pure Python git implementation) and reads object files directly.

---

## What it does

- Discovers all `.git` repos under an evidence root (recursive)
- Reconstructs full commit history from git objects without the git binary
- Detects suspicious/anti-forensic commits using multi-signal analysis
- Recovers content of deleted files from git history
- Produces cross-repo timelines and author correlation across multiple repos on the same host
- Reads GitKraken metadata (last-accessed, last-modified timestamps) from `.git/config`

---

## Suspicious commit detection

Detection combines **multiple signals** — not just keyword matching:

| Rule | Triggers when |
|------|---------------|
| Keyword + deletion | Anti-forensic keyword in message AND file(s) deleted in same commit |
| Sensitive file deleted | `.json`, `.db`, `.log`, `.csv`, `.sqlite` or files named `admin`, `credential`, `password`, `token`, `key`, `auth`, `session`, `config`, `log` |
| Pure deletion commit | Commit contains ONLY deletions with no additions or modifications |
| Empty scrub commit | Anti-forensic keyword in message but zero file changes |
| Rapid succession | Suspicious commit occurs within 5 minutes of a previous commit |

Each flagged commit shows the specific reason(s) it was flagged.

---

## Installation

Requires Python 3.11+ and [uv](https://github.com/astral-sh/uv).

```bash
git clone https://github.com/yourname/git_forensics
cd git_forensics
uv run --with dulwich git_forensics.py --help
```

Or add dulwich to your project:

```bash
uv add dulwich
uv run git_forensics.py --help
```

---

## Usage

### Summary mode (default)

Quick triage — repos, authors, suspicious commits, cross-repo timeline.

```bash
uv run --with dulwich git_forensics.py <evidence_root>
```

```
Found 3 git repo(s) under evidence/

  Analyzing: evidence\host\projects\backend ... 12 commits
  Analyzing: evidence\host\projects\webapp ... 9 commits
  Analyzing: evidence\host\projects\tools ... ERROR: Cannot open repo

======================================================================
GIT FORENSICS -- SUMMARY
======================================================================

REPO : evidence\host\projects\webapp
Branches   : master
Commits    : 9
Date range : 2024-03-01 08:12:04 UTC  ->  2024-03-15 14:22:37 UTC
Authors:
  John Dev <jdev@corp-internal.local>
Suspicious commits (1):
  [!] a1b2c3d4  2024-03-15 14:10:22 UTC  "delete logs"
       -> anti-forensic keyword in message + 1 deletion(s): app_logs.json
       -> sensitive file(s) deleted: app_logs.json
       -> rapid succession: 247s after previous commit (e5f6a7b8 "add login protection")

CROSS-REPO TIMELINE (oldest -> newest):
  2024-03-15 14:06:32 UTC  [webapp]  e5f6a7b8  add login protection
  2024-03-15 14:10:39 UTC  [webapp]  a1b2c3d4  delete logs  [!]
  2024-03-15 14:16:28 UTC  [webapp]  c9d0e1f2  add gitignore
```

### Extract mode

Full forensic extraction — per-commit files, branch logs, deleted file recovery, cross-repo timeline.

```bash
uv run --with dulwich git_forensics.py <evidence_root> --extract <output_dir>
```

Output structure:

```
output/
  timeline.txt              # all commits across all repos, chronological
  authors.txt               # deduplicated author list with repo associations
  <repo_name>/
    summary.txt             # config, branches, commit range, author list
    commits/
      0001_<sha>_<msg>.txt  # numbered for chronological sort
      0002_<sha>_<msg>.txt
      ...
    branches/
      master.txt            # full commit log for branch
    deleted/
      <sha>_<filename>      # recovered content of deleted files
```

### Deleted files only

Fast path — recover only files deleted across all commits in all repos.

```bash
uv run --with dulwich git_forensics.py <evidence_root> --deleted <output_dir>
```

### Recreate missing HEAD

KAPE sometimes omits the `HEAD` file (locked during collection, or not listed in the target mask). Without it, `git log` reports _"your current branch does not have any commits yet"_ even though the repo is intact.

This option writes a valid `HEAD` back so native git tools work:

```bash
uv run --with dulwich git_forensics.py <evidence_root> --recreate-head
```

```
======================================================================
WARNING: --recreate-head MODIFIES the .git directory.
Run this on a working COPY of evidence, not the original.
======================================================================

  [pdftoolkit] HEAD exists (ref: refs/heads/master) -- skipped
  [webpage] HEAD recreated -> refs/heads/master  (082f2abb)
             git log: git -C "evidence\webpage" -c safe.directory="*" log --oneline
```

Branch selection order: `master` → `main` → first branch alphabetically.

> **Forensic note**: this modifies the `.git` directory. Always work on a copy (`xcopy /e /h /i evidence\ working_copy\`) — never run on original evidence.

---

## Output: commit file format

Each file in `commits/` contains full metadata and unified diff:

```
commit  a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
author  John Dev <jdev@corp-internal.local>
date    2024-03-15 14:10:22 UTC  (1710508222)
message delete logs
flag    [SUSPICIOUS] anti-forensic keyword in message + 1 deletion(s): app_logs.json
flag    [SUSPICIOUS] sensitive file(s) deleted: app_logs.json
flag    [SUSPICIOUS] rapid succession: 247s after previous commit (e5f6a7b8 "add login protection")

Changes:
  -  app_logs.json
     [DELETED -- recovered in deleted/ dir  sha:3f4a5b6c7d8e]

Diff: app_logs.json
--- a/app_logs.json
+++ b/
@@ -1,20 +0,0 @@
-{
-    "logs": [
-        {
-            "timestamp": "2024-03-15T13:45:12.000000",
-            "username": "admin",
-            "ip": "192.168.1.50",
-            "action": "Failed login attempt"
-        }
-    ]
-}
...
```

---

## Limitations

- **Pack files**: dulwich supports packfiles but collection tools may not capture them — missing objects are skipped gracefully
- **Merge commits**: diffs against first parent only (standard forensic convention)
- **Shallow clones**: detected and flagged; history will be incomplete
- **Empty repos**: repos with no commits (objects not collected by acquisition tool) report an error and continue
- **Read-only**: tool never modifies evidence except when `--recreate-head` is explicitly passed

---

## Dependencies

- Python 3.11+
- [dulwich](https://www.dulwich.io/) >= 0.21 — pure Python git, no git binary needed

---

## License

MIT
