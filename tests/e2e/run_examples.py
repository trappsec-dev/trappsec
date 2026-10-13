#!/usr/bin/env python3
import argparse
import concurrent.futures
import csv
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


REPO_ROOT = Path(__file__).resolve().parents[2]
E2E_DIR = REPO_ROOT / "tests" / "e2e"


@dataclass(frozen=True)
class Case:
    name: str
    cwd: Path
    command: List[str]
    unsupported: FrozenSet[str] = frozenset()  # features the example does not implement



def _default_cases() -> List[Case]:
    """Commands may use {webhook}; each case gets its own app port ($PORT) and receiver."""
    node = lambda d: ["node", "app.js", "--webhook={webhook}"]  # noqa: E731
    py = lambda d: ["uv", "run", "{uv_lock}", "app.py", "--webhook={webhook}"]  # noqa: E731
    go = lambda d: ["go", "run", "main.go", "--webhook={webhook}"]  # noqa: E731
    ex = REPO_ROOT / "examples"
    return [
        Case("node-express", ex / "express", node("express")),
        Case("node-fastify", ex / "fastify", node("fastify")),
        Case("node-hapi", ex / "hapi", node("hapi")),
        Case("node-koa", ex / "koa", node("koa")),
        Case("node-nestjs-express", ex / "nestjs", ["npm", "run", "start", "--", "--webhook={webhook}"]),
        Case("node-nestjs-fastify", ex / "nestjs", ["npm", "run", "start_fastify", "--", "--webhook={webhook}"]),
        Case("py-django", ex / "django", py("django")),
        Case("py-fastapi", ex / "fastapi", py("fastapi")),
        Case("py-flask", ex / "flask", py("flask")),
        Case("py-litestar", ex / "litestar", py("litestar")),
        Case("py-sanic", ex / "sanic", py("sanic")),
        Case("py-starlette", ex / "starlette", py("starlette")),
        Case("py-tornado", ex / "tornado", py("tornado")),
        Case("go-chi", ex / "go-chi", go("go-chi")),
        Case("go-echo", ex / "go-echo", go("go-echo")),
        Case("go-gin", ex / "go-gin", go("go-gin")),
        Case("go-nethttp", ex / "go-nethttp", go("go-nethttp")),
    ]


def _find_test_python() -> str:
    candidates = [
        E2E_DIR / ".venv" / "Scripts" / "python.exe",
        E2E_DIR / ".venv" / "bin" / "python",
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    return sys.executable


def _wait_for_port_or_process_exit(
    proc: subprocess.Popen, host: str, port: int, timeout_sec: float
) -> Tuple[bool, Optional[int]]:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if proc.poll() is not None:
            return False, proc.returncode
        if _is_port_open(host, port):
            return True, None
        time.sleep(0.25)
    return False, proc.poll()


def _wait_for_http(url: str, proc: subprocess.Popen, timeout_sec: float) -> bool:
    """An open port is not a ready app: wait until it answers HTTP at all."""
    deadline = time.time() + timeout_sec
    while time.time() < deadline and proc.poll() is None:
        try:
            urllib.request.urlopen(url, timeout=2).close()
            return True
        except urllib.error.HTTPError:
            return True  # any status code means the server is handling requests
        except (urllib.error.URLError, OSError):
            time.sleep(0.25)
    return False


def _is_port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.4)
        try:
            s.connect((host, port))
            return True
        except OSError:
            return False


def _wait_for_port_release(host: str, port: int, timeout_sec: float) -> bool:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if not _is_port_open(host, port):
            return True
        time.sleep(0.25)
    return not _is_port_open(host, port)


def _listening_pids(port: int) -> List[int]:
    pids: Set[int] = set()
    if os.name == "nt":
        cp = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True,
            text=True,
            check=False,
        )
        if cp.returncode != 0:
            return []
        port_token = f":{port}"
        for line in cp.stdout.splitlines():
            if "LISTENING" not in line.upper():
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            local_addr = parts[1]
            state = parts[3]
            pid_str = parts[4]
            if state.upper() != "LISTENING":
                continue
            if not local_addr.endswith(port_token):
                continue
            try:
                pids.add(int(pid_str))
            except ValueError:
                continue
        return sorted(pids)

    cp = subprocess.run(
        ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"],
        capture_output=True,
        text=True,
        check=False,
    )
    if cp.returncode == 0:
        for line in cp.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                pids.add(int(line))
            except ValueError:
                continue
    return sorted(pids)


def _kill_pids(pids: List[int]) -> None:
    for pid in pids:
        if pid <= 0:
            continue
        try:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            else:
                os.kill(pid, signal.SIGTERM)
        except Exception:
            continue
    if os.name != "nt":
        # Best effort: force-kill any survivors.
        time.sleep(1.0)
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass


def _ensure_port_free(host: str, port: int, wait_timeout_sec: float, context: str, kill_blockers: bool) -> Tuple[bool, str]:
    if _wait_for_port_release(host, port, wait_timeout_sec):
        return True, ""

    if not kill_blockers:
        return False, f"port {host}:{port} is still in use {context} (waited {wait_timeout_sec}s)"

    pids = _listening_pids(port)
    if not pids:
        return False, f"port {host}:{port} is still in use {context}; no blocker PID found"

    print(f"    port busy {context}; killing blockers on {host}:{port}: {', '.join(str(p) for p in pids)}")
    _kill_pids(pids)
    if _wait_for_port_release(host, port, max(3.0, wait_timeout_sec)):
        return True, ""
    return False, f"port {host}:{port} is still in use {context} after killing blockers ({', '.join(str(p) for p in pids)})"


def _terminate_process_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            for _ in range(30):
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
            if proc.poll() is None:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        pass


def _run_pytest(url: str, timeout_sec: int, secret: str, webhook_port: int,
                unsupported: FrozenSet[str]) -> Tuple[subprocess.CompletedProcess, Dict[str, int]]:
    py = _find_test_python()
    with tempfile.TemporaryDirectory() as tmp:
        junit = Path(tmp) / "junit.xml"
        cp = subprocess.run(
            [py, "-m", "pytest", "-q", "test_example.py", f"--url={url}", f"--junitxml={junit}",
             f"--webhook-secret={secret}", f"--webhook-port={webhook_port}", "--check-alerts-only",
             f"--unsupported={','.join(sorted(unsupported))}"],
            cwd=E2E_DIR,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        return cp, _junit_counts(junit)


def _junit_counts(path: Path) -> Dict[str, int]:
    counts = _empty_counts()
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return counts
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    for suite in suites:
        tests = int(suite.get("tests", 0))
        failed, errors, skipped = (int(suite.get(k, 0)) for k in ("failures", "errors", "skipped"))
        counts["failed"] += failed
        counts["errors"] += errors
        counts["skipped"] += skipped
        counts["passed"] += tests - failed - errors - skipped
    return counts


_INSTALLED: Set[Path] = set()


def _install_dependencies(case: Case, log_dir: Optional[Path], latest: bool = False) -> Tuple[bool, str]:
    """Install Node dependencies (once per directory): `npm ci` from the committed
    lockfile, or `npm install` (newest matching releases) with --latest."""
    if case.command[0] not in ("node", "npm"):
        return True, ""
    targets = [REPO_ROOT / "packages" / "node", case.cwd]
    for target in targets:
        if target in _INSTALLED or not (target / "package.json").exists():
            continue
        locked = (target / "package-lock.json").exists() and not latest
        cmd = _resolve_command(["npm", "ci" if locked else "install", "--no-audit", "--no-fund"])
        print(f"    installing node dependencies in {target.relative_to(REPO_ROOT)}")
        cp = subprocess.run(cmd, cwd=str(target), capture_output=True, text=True, check=False)
        if log_dir is not None:
            (log_dir / f"{case.name}.npm-install.log").write_text((cp.stdout or "") + (cp.stderr or ""))
        if cp.returncode != 0:
            return False, f"npm install failed in {target} (exit {cp.returncode}): {(cp.stderr or '').strip()[-500:]}"
        _INSTALLED.add(target)
    return True, ""


def _format_command(cmd: List[str]) -> str:
    return " ".join(cmd)


def _resolve_command(cmd: List[str]) -> List[str]:
    if not cmd:
        return cmd
    exe = cmd[0]
    # On Windows, shell=False does not reliably resolve scripts like npm unless
    # we provide a concrete path (for example npm.cmd).
    if os.name == "nt" and not os.path.dirname(exe):
        candidates = [
            exe,
            f"{exe}.cmd",
            f"{exe}.bat",
            f"{exe}.exe",
            f"{exe}.com",
        ]
        for candidate in candidates:
            resolved = shutil.which(candidate)
            if resolved:
                return [resolved, *cmd[1:]]
    return cmd


def _empty_counts() -> Dict[str, int]:
    return {"passed": 0, "failed": 0, "errors": 0, "skipped": 0, "xfailed": 0, "xpassed": 0}


def _format_counts(counts: Dict[str, int]) -> str:
    return (
        f"passed={counts['passed']} failed={counts['failed']} errors={counts['errors']} "
        f"skipped={counts['skipped']} xfailed={counts['xfailed']} xpassed={counts['xpassed']}"
    )


def _build_summary_report(results: List[Dict[str, object]], failure_details: List[str]) -> str:
    lines: List[str] = []
    lines.append("Summary")
    lines.append("-------")

    if not results:
        lines.append("No cases were run.")
        lines.append("")
        lines.append("Failures")
        lines.append("--------")
        lines.append("None")
        return "\n".join(lines)

    case_name_width = max(4, max(len(str(r["case"])) for r in results))
    status_width = max(6, max(len(str(r["status"])) for r in results))
    header = (
        f"{'Case':<{case_name_width}}  {'Status':<{status_width}}  "
        f"{'Pass':>4}  {'Fail':>4}  {'Err':>3}  {'Skip':>4}  {'XFail':>5}  {'XPass':>5}"
    )
    lines.append(header)
    lines.append("-" * len(header))

    totals = {
        "passed": 0,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
    }

    for r in results:
        counts = r["counts"]
        totals["passed"] += int(counts["passed"])
        totals["failed"] += int(counts["failed"])
        totals["errors"] += int(counts["errors"])
        totals["skipped"] += int(counts["skipped"])
        totals["xfailed"] += int(counts["xfailed"])
        totals["xpassed"] += int(counts["xpassed"])
        lines.append(
            f"{str(r['case']):<{case_name_width}}  {str(r['status']):<{status_width}}  "
            f"{counts['passed']:>4}  {counts['failed']:>4}  {counts['errors']:>3}  "
            f"{counts['skipped']:>4}  {counts['xfailed']:>5}  {counts['xpassed']:>5}"
        )

    overall_status = "pass" if not failure_details else "fail"
    lines.append("-" * len(header))
    lines.append(
        f"{'TOTALS':<{case_name_width}}  {overall_status:<{status_width}}  "
        f"{totals['passed']:>4}  {totals['failed']:>4}  {totals['errors']:>3}  "
        f"{totals['skipped']:>4}  {totals['xfailed']:>5}  {totals['xpassed']:>5}"
    )
    lines.append("")
    lines.append("Failures")
    lines.append("--------")
    if not failure_details:
        lines.append("None")
    else:
        lines.extend(failure_details)
    return "\n".join(lines)


def _run_case(case: Case, app_port: int, webhook_port: int, secret: str, args: argparse.Namespace,
              log_dir: Optional[Path]) -> Tuple[Dict[str, object], List[str]]:
    """Start one example on its own ports, run pytest against it, tear it down."""
    out: List[str] = []
    url = f"http://{args.host}:{app_port}"
    receiver = f"http://127.0.0.1:{webhook_port}"
    uv_lock = "--upgrade" if args.latest else "--locked"  # app.py.lock pins Python example dependencies
    command = _resolve_command([part.format(webhook=f"{receiver}/webhook", uv_lock=uv_lock) for part in case.command])
    out.append(f"==> [{case.name}] port {app_port}, receiver {webhook_port}: {_format_command(command)}")

    def result(status: str, code: str, reason: str, counts: Optional[Dict[str, int]] = None) -> Dict[str, object]:
        return {"case": case.name, "status": status, "code": code, "counts": counts or _empty_counts(),
                "failure_reason": reason}

    for port, what in ((app_port, "app"), (webhook_port, "receiver")):
        ok, msg = _ensure_port_free(args.host, port, args.port_release_timeout,
                                    context=f"before starting ({what} port)", kill_blockers=args.kill_port_blockers)
        if not ok:
            out.append(f"    {msg}")
            return result("fail", "port-busy", msg), out

    proc: Optional[subprocess.Popen] = None
    app_log = None
    case_result: Optional[Dict[str, object]] = None
    try:
        try:
            if log_dir is not None:
                app_log = open(log_dir / f"{case.name}.app.log", "w")
            popen_kwargs = {
                "cwd": str(case.cwd),
                "env": {**os.environ, "PORT": str(app_port), "TRAPPSEC_WEBHOOK_SECRET": secret,
                        "TRAPPSEC_ALERTS_WEBHOOK": f"{receiver}/alerts"},
                "stdout": app_log or subprocess.DEVNULL,
                "stderr": subprocess.STDOUT if app_log else subprocess.DEVNULL,
                "text": True,
            }
            if os.name != "nt":
                popen_kwargs["preexec_fn"] = os.setsid
            else:
                popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            proc = subprocess.Popen(command, **popen_kwargs)
        except FileNotFoundError as e:
            case_result = result("error", "127", f"failed to start: {e}")

        if case_result is None:
            started, exit_code = _wait_for_port_or_process_exit(proc, args.host, app_port, args.startup_timeout)
            if started and not _wait_for_http(url, proc, args.startup_timeout):
                started, exit_code = False, proc.poll()
            if not started:
                if exit_code is not None:
                    case_result = result("fail", "startup-exit",
                                         f"process exited before port became ready (exit code {exit_code})")
                else:
                    case_result = result("fail", "startup-timeout", f"startup timeout after {args.startup_timeout}s")

        if case_result is None:
            try:
                test_result, counts = _run_pytest(url, args.pytest_timeout, secret, webhook_port, case.unsupported)
                combined = (test_result.stdout or "") + (test_result.stderr or "")
                if log_dir is not None:
                    (log_dir / f"{case.name}.pytest.log").write_text(combined)
                status = "pass" if test_result.returncode == 0 else "fail"
                case_result = result(status, str(test_result.returncode), combined.strip() if status != "pass" else "",
                                     counts)
                out.append(f"    pytest: {status} ({_format_counts(counts)})")
            except subprocess.TimeoutExpired:
                case_result = result("fail", "pytest-timeout", f"pytest timeout after {args.pytest_timeout}s")
    finally:
        if proc is not None:
            _terminate_process_tree(proc)
            release_ok, release_msg = _ensure_port_free(args.host, app_port, args.port_release_timeout,
                                                        context="after teardown", kill_blockers=args.kill_port_blockers)
            if not release_ok:
                if case_result is None or case_result["status"] == "pass":
                    case_result = result("fail", "port-release-timeout", release_msg)
                else:
                    case_result["failure_reason"] = f"{case_result['failure_reason']}\n{release_msg}".strip()
        if app_log is not None:
            app_log.close()

    if case_result is None:
        case_result = result("error", "internal-error", "unknown harness state")
    if case_result["status"] != "pass" and not out[-1].startswith("    pytest:"):
        out.append(f"    {case_result['status']}: {case_result['failure_reason']}")
    return case_result, out


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the E2E suite against every example, in parallel.")
    parser.add_argument("--host", default="127.0.0.1", help="Host the examples listen on.")
    parser.add_argument("--port", type=int, default=8000,
                        help="First app port; case N listens on port+N.")
    parser.add_argument("--webhook-port", type=int, default=5050,
                        help="First receiver port; case N's pytest receiver listens on webhook-port+N.")
    parser.add_argument("--jobs", "-j", type=int, default=min(4, os.cpu_count() or 1),
                        help="Cases to run at once (default: min(4, CPUs)).")
    parser.add_argument("--startup-timeout", type=int, default=90, help="Seconds to wait for app startup.")
    parser.add_argument(
        "--port-release-timeout",
        type=int,
        default=15,
        help="Seconds to wait for a port to be released.",
    )
    parser.add_argument(
        "--kill-port-blockers",
        action="store_true",
        default=False,
        help="Opt-in: if a port is still busy after waiting, kill the listener processes blocking it. "
        "Off by default because it can terminate unrelated processes.",
    )
    parser.add_argument(
        "--install",
        action=argparse.BooleanOptionalAction,
        default=bool(os.environ.get("CI")),
        help="Install Node example dependencies before starting them (default: on when $CI is set).",
    )
    parser.add_argument(
        "--log-dir",
        default=None,
        help="Directory for per-case app logs, pytest output and summary.csv (created if missing).",
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        default=False,
        help="Ignore the examples' lockfiles and use the newest matching releases (uv --upgrade, npm install). "
        "May refresh lockfiles in the working tree.",
    )
    parser.add_argument("--pytest-timeout", type=int, default=240, help="Seconds before pytest is force-terminated.")
    parser.add_argument(
        "--cases",
        default="",
        help="Comma-separated case names to run. Empty means run all.",
    )
    args = parser.parse_args()
    log_dir: Optional[Path] = Path(args.log_dir).resolve() if args.log_dir else None
    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)

    all_cases = _default_cases()
    secret = secrets.token_hex(16)  # every delivery must carry a valid signature
    selected: List[Case]
    if args.cases.strip():
        wanted = {x.strip() for x in args.cases.split(",") if x.strip()}
        selected = [c for c in all_cases if c.name in wanted]
        missing = sorted(wanted - {c.name for c in selected})
        if missing:
            print(f"Unknown case(s): {', '.join(missing)}", file=sys.stderr)
            return 2
    else:
        selected = all_cases

    results: Dict[str, Dict[str, object]] = {}
    runnable: List[Tuple[int, Case]] = []
    for i, case in enumerate(all_cases):
        if case not in selected:
            continue
        if args.install:  # sequential: cases can share a directory (nestjs)
            ok, msg = _install_dependencies(case, log_dir, latest=args.latest)
            if not ok:
                print(f"==> [{case.name}] {msg}")
                results[case.name] = {"case": case.name, "status": "fail", "code": "install-failed",
                                      "counts": _empty_counts(), "failure_reason": msg}
                continue
        runnable.append((i, case))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futures = {pool.submit(_run_case, case, args.port + i, args.webhook_port + i, secret, args, log_dir): case
                   for i, case in runnable}
        for future in concurrent.futures.as_completed(futures):
            case_result, lines = future.result()
            print("\n".join(lines), flush=True)
            results[futures[future].name] = case_result

    ordered = [results[c.name] for c in selected if c.name in results]
    failure_details = [f"[{r['case']}] {str(r.get('failure_reason', '')).strip()}"
                       for r in ordered if r["status"] != "pass" and str(r.get("failure_reason", "")).strip()]
    report = _build_summary_report(ordered, failure_details)
    print(f"\n{report}")

    if log_dir is not None:
        with open(log_dir / "summary.csv", "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["case", "status", "code", "passed", "failed", "errors", "skipped", "xfailed", "xpassed"])
            for r in ordered:
                c = r["counts"]
                writer.writerow([r["case"], r["status"], r.get("code", ""), c["passed"], c["failed"],
                                 c["errors"], c["skipped"], c["xfailed"], c["xpassed"]])
        (log_dir / "summary.txt").write_text(report + "\n")
        print(f"Logs and summary.csv written to {log_dir}")

    return 0 if all(r["status"] == "pass" for r in ordered) and len(ordered) == len(selected) else 1


if __name__ == "__main__":
    raise SystemExit(main())
