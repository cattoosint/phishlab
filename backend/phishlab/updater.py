"""phishlab/updater.py — in-app self-update from the GitHub repo.

Compares the local git HEAD against origin and (on request) fast-forwards to it. A successful pull of
backend code is applied by a clean self-restart (the app exits 42 and the launcher — start.bat — relaunches
with the fresh code) — NOT uvicorn --reload, which on Windows breaks Playwright's browser subprocess. A
PUBLIC repo needs no auth:
git ls-remote / pull do the work (no GitHub API token). All calls are non-fatal — if there's no git
checkout or no remote yet, they report that instead of raising.
"""
from __future__ import annotations

import pathlib
import subprocess

REPO_DIR = str(pathlib.Path(__file__).resolve().parents[2])   # .../PhishLab (holds .git)


def _git(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", REPO_DIR, *args],
                          capture_output=True, text=True, timeout=timeout)


def _branch() -> str:
    return (_git("rev-parse", "--abbrev-ref", "HEAD").stdout or "").strip() or "master"


def _has_origin() -> bool:
    return "origin" in (_git("remote").stdout or "").split()


def check() -> dict:
    """Is a newer commit available on origin? configured:False when there's no repo/remote (not an error)."""
    try:
        if _git("rev-parse", "--is-inside-work-tree").returncode != 0:
            return {"configured": False, "reason": "not a git checkout"}
        if not _has_origin():
            return {"configured": False, "reason": "no GitHub remote configured yet"}
        branch = _branch()
        local = (_git("rev-parse", "HEAD").stdout or "").strip()
        ls = _git("ls-remote", "origin", f"refs/heads/{branch}", timeout=20)
        remote = ((ls.stdout or "").split() or [""])[0]
        if not remote:
            return {"configured": True, "behind": False, "reason": f"branch {branch} not on origin"}
        # local != remote could mean we're BEHIND (origin has new commits) OR just AHEAD (unpushed local
        # commits). Only 'behind' should light the update badge: if the remote commit is already an
        # ancestor of HEAD we're ahead, not behind.
        behind = local != remote
        if behind and _git("cat-file", "-e", remote).returncode == 0 \
                and _git("merge-base", "--is-ancestor", remote, "HEAD").returncode == 0:
            behind = False
        return {"configured": True, "behind": behind,
                "current": local[:7], "latest": remote[:7], "branch": branch}
    except Exception as exc:
        return {"configured": False, "reason": f"{type(exc).__name__}: {exc}"[:140]}


def apply() -> dict:
    """Fast-forward the working tree to origin/<branch>. ff-only NEVER clobbers local commits/changes —
    it fails safely and says so. backend_changed tells the GUI whether to trigger a restart (via
    /api/update/restart -> exit 42 -> start.bat relaunches) or just refresh the page (web-only)."""
    try:
        if not _has_origin():
            return {"ok": False, "output": "no GitHub remote configured yet"}
        branch = _branch()
        before = (_git("rev-parse", "HEAD").stdout or "").strip()
        _git("fetch", "origin", branch, timeout=90)
        pull = _git("pull", "--ff-only", "origin", branch, timeout=90)
        after = (_git("rev-parse", "HEAD").stdout or "").strip()
        ok = pull.returncode == 0
        changed: list[str] = []
        if ok and before != after:
            diff = _git("diff", "--name-only", before, after)
            changed = [ln for ln in (diff.stdout or "").splitlines() if ln]
        # a change outside backend/web/ needs the Python app to reload; web-only just needs a page refresh
        backend_changed = any(not c.startswith("backend/web/") for c in changed)
        out = ((pull.stdout or "") + (pull.stderr or "")).strip()[-800:]
        return {"ok": ok, "updated": before != after, "output": out or "already up to date",
                "changed": changed[:40], "backend_changed": backend_changed}
    except Exception as exc:
        return {"ok": False, "output": f"{type(exc).__name__}: {exc}"[:200]}
