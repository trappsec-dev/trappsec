#!/usr/bin/env python3
import argparse
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


REPO_ROOT = Path(__file__).resolve().parents[2]
E2E_DIR = REPO_ROOT / "tests" / "e2e"


@dataclass(frozen=True)
class Case:
    name: str
    cwd: Path
    command: List[str]


def _default_cases(webhook_url: str) -> List[Case]:
    return [
        Case("node-express", REPO_ROOT / "examples" / "express", ["node", "app.js", f"--webhook={webhook_url}"]),
        Case("node-fastify", REPO_ROOT / "examples" / "fastify", ["node", "app.js", f"--webhook={webhook_url}"]),
        Case("node-hapi", REPO_ROOT / "examples" / "hapi", ["node", "app.js", f"--webhook={webhook_url}"]),
        Case("node-koa", REPO_ROOT / "examples" / "koa", ["node", "app.js", f"--webhook={webhook_url}"]),
        Case("node-nestjs-express", REPO_ROOT / "examples" / "nestjs", ["npm", "run", "start"]),
        Case("node-nestjs-fastify", REPO_ROOT / "examples" / "nestjs", ["npm", "run", "start_fastify"]),
        Case("py-django", REPO_ROOT / "examples" / "django", ["uv", "run", "app.py", f"--webhook={webhook_url}"]),
        Case("py-fastapi", REPO_ROOT / "examples" / "fastapi", ["uv", "run", "app.py", f"--webhook={webhook_url}"]),
        Case("py-flask", REPO_ROOT / "examples" / "flask", ["uv", "run", "app.py", f"--webhook={webhook_url}"]),
        Case("py-litestar", REPO_ROOT / "examples" / "litestar", ["uv", "run", "app.py", f"--webhook={webhook_url}"]),
        Case("py-sanic", REPO_ROOT / "examples" / "sanic", ["uv", "run", "app.py", f"--webhook={webhook_url}"]),
        Case("py-starlette", REPO_ROOT / "examples" / "starlette", ["uv", "run", "app.py", f"--webhook={webhook_url}"]),
        Case("py-tornado", REPO_ROOT / "examples" / "tornado", ["uv", "run", "app.py", f"--webhook={webhook_url}"]),
        Case("go-echo", REPO_ROOT / "examples" / "go-echo", ["go", "run", "main.go", f"--webhook={webhook_url}"]),
        Case("go-gin", REPO_ROOT / "examples" / "go-gin", ["go", "run", "main.go", f"--webhook={webhook_url}"]),
        Case("go-nethttp", REPO_ROOT / "examples" / "go-nethttp", ["go", "run", "main.go", f"--webhook={webhook_url}"]),
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


def _run_pytest(url: str, timeout_sec: int) -> subprocess.CompletedProcess:
    py = _find_test_python()
    return subprocess.run(
        [py, "-m", "pytest", "-q", "test_example.py", f"--url={url}"],
        cwd=E2E_DIR,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
    )


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


def _parse_pytest_counts(output: str) -> Dict[str, int]:
    counts = {
        "passed": 0,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
    }
    for match in re.finditer(r"(\d+)\s+(passed|failed|error|errors|skipped|xfailed|xpassed)", output, re.IGNORECASE):
        value = int(match.group(1))
        key = match.group(2).lower()
        if key in {"error", "errors"}:
            key = "errors"
        counts[key] = value
    return counts


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


def main() -> int:
    parser = argparse.ArgumentParser(description="Run E2E suite against all implementation examples sequentially.")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="Base URL used by pytest (--url).")
    parser.add_argument("--host", default="127.0.0.1", help="Host to probe for readiness.")
    parser.add_argument("--port", type=int, default=8000, help="Port to probe for readiness.")
    parser.add_argument("--webhook-url", default="http://localhost:5050/webhook", help="Webhook URL passed to examples.")
    parser.add_argument("--startup-timeout", type=int, default=45, help="Seconds to wait for app startup.")
    parser.add_argument(
        "--port-release-timeout",
        type=int,
        default=15,
        help="Seconds to wait for the app port to be released after teardown.",
    )
    parser.add_argument(
        "--kill-port-blockers",
        action="store_true",
        default=True,
        help="If port is still busy after waiting, kill listener processes blocking the port.",
    )
    parser.add_argument(
        "--no-kill-port-blockers",
        dest="kill_port_blockers",
        action="store_false",
        help="Disable auto-kill of processes blocking the port.",
    )
    parser.add_argument("--pytest-timeout", type=int, default=240, help="Seconds before pytest is force-terminated.")
    parser.add_argument(
        "--cases",
        default="",
        help="Comma-separated case names to run. Empty means run all.",
    )
    args = parser.parse_args()

    all_cases = _default_cases(args.webhook_url)
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

    results: List[Dict[str, object]] = []
    failure_details: List[str] = []

    for case in selected:
        resolved_command = _resolve_command(case.command)
        print(f"\n==> [{case.name}] starting: {_format_command(resolved_command)}")
        pre_ok, pre_msg = _ensure_port_free(
            args.host,
            args.port,
            args.port_release_timeout,
            context="before starting this case",
            kill_blockers=args.kill_port_blockers,
        )
        if not pre_ok:
            msg = pre_msg
            print(f"    {msg}")
            case_result = {
                "case": case.name,
                "status": "fail",
                "code": "port-busy",
                "counts": _parse_pytest_counts(""),
                "failure_reason": msg,
            }
            results.append(case_result)
            failure_details.append(f"[{case.name}] {msg}")
            continue

        proc: Optional[subprocess.Popen] = None
        case_result: Optional[Dict[str, object]] = None
        try:
            try:
                popen_kwargs = {
                    "cwd": str(case.cwd),
                    "stdout": subprocess.DEVNULL,
                    "stderr": subprocess.DEVNULL,
                    "text": True,
                }
                if os.name != "nt":
                    popen_kwargs["preexec_fn"] = os.setsid
                else:
                    popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

                proc = subprocess.Popen(resolved_command, **popen_kwargs)
            except FileNotFoundError as e:
                msg = f"failed to start: {e}"
                print(f"    {msg}")
                case_result = {
                    "case": case.name,
                    "status": "error",
                    "code": "127",
                    "counts": _parse_pytest_counts(""),
                    "failure_reason": msg,
                }

            if case_result is None:
                started, exit_code = _wait_for_port_or_process_exit(proc, args.host, args.port, args.startup_timeout)
                if not started:
                    if exit_code is not None:
                        msg = f"process exited before port became ready (exit code {exit_code})"
                        code = "startup-exit"
                    else:
                        msg = f"startup timeout after {args.startup_timeout}s"
                        code = "startup-timeout"
                    print(f"    {msg}")
                    case_result = {
                        "case": case.name,
                        "status": "fail",
                        "code": code,
                        "counts": _parse_pytest_counts(""),
                        "failure_reason": msg,
                    }

            if case_result is None:
                try:
                    test_result = _run_pytest(args.url, args.pytest_timeout)
                    combined = (test_result.stdout or "") + (test_result.stderr or "")
                    counts = _parse_pytest_counts(combined)
                    status = "pass" if test_result.returncode == 0 else "fail"
                    case_result = {
                        "case": case.name,
                        "status": status,
                        "code": str(test_result.returncode),
                        "counts": counts,
                        "failure_reason": combined.strip() if status != "pass" else "",
                    }
                    print(f"    pytest: {status} ({_format_counts(counts)})")
                except subprocess.TimeoutExpired:
                    msg = f"pytest timeout after {args.pytest_timeout}s"
                    counts = _parse_pytest_counts("")
                    case_result = {
                        "case": case.name,
                        "status": "fail",
                        "code": "pytest-timeout",
                        "counts": counts,
                        "failure_reason": msg,
                    }
                    print(f"    pytest: fail ({msg})")
        finally:
            if proc is not None:
                _terminate_process_tree(proc)
                release_ok, release_msg = _ensure_port_free(
                    args.host,
                    args.port,
                    args.port_release_timeout,
                    context="after teardown",
                    kill_blockers=args.kill_port_blockers,
                )
                if not release_ok:
                    print(f"    {release_msg}")
                    if case_result is None:
                        case_result = {
                            "case": case.name,
                            "status": "fail",
                            "code": "port-release-timeout",
                            "counts": _parse_pytest_counts(""),
                            "failure_reason": release_msg,
                        }
                    elif str(case_result["status"]) == "pass":
                        case_result["status"] = "fail"
                        case_result["code"] = "port-release-timeout"
                        case_result["failure_reason"] = release_msg
                    else:
                        existing_reason = str(case_result.get("failure_reason", "")).strip()
                        case_result["failure_reason"] = (
                            f"{existing_reason}\n{release_msg}".strip() if existing_reason else release_msg
                        )

        if case_result is None:
            case_result = {
                "case": case.name,
                "status": "error",
                "code": "internal-error",
                "counts": _parse_pytest_counts(""),
                "failure_reason": "unknown harness state",
            }
        results.append(case_result)
        if str(case_result["status"]) != "pass":
            reason = str(case_result.get("failure_reason", "")).strip()
            if reason:
                failure_details.append(f"[{case.name}] {reason}")

    report = _build_summary_report(results, failure_details)
    print(f"\n{report}")

    failures = [r for r in results if r["status"] != "pass"]
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
