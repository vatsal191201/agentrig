"""LocalBackend: a sandbox driver built from tools already on the host.

Composition, not invention:

    systemd-run --user --scope   -> cgroup v2 resource caps + a unit to kill
      strace -f -o <host file>   -> syscall-visible observation (reads, execs,
                                    connects) written where the agent can't see
        bwrap --unshare-*        -> filesystem + pid + (optional) network
                                    isolation; $HOME and the host fs vanish
          <agent argv>           -> the thing under test

Every layer is optional-degradable *except* filesystem isolation: if bubblewrap
cannot create a user namespace we raise IsolationError and refuse to run. We
never execute an attack scenario on the bare host.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from typing import Optional

from agentrig.backends import rss
from agentrig.backends.base import (
    LAUNCHER_PATH,
    NET_MOUNT,
    SANDBOX_WORKDIR,
    Capabilities,
    ExecResult,
    SandboxBackend,
    SandboxHandle,
    SandboxSpec,
)
from agentrig.errors import BackendError, IsolationError

# Syscalls we ask strace to record. Kept tight so traces stay small and cheap
# to parse: file opens (reads *and* denied writes), execs, and network connects.
TRACE_SYSCALLS = (
    "openat,open,openat2,connect,socket,execve,execveat,"
    "unlink,unlinkat,rename,renameat,renameat2,mkdir,mkdirat,"
    "link,linkat,symlink,symlinkat"
)

# The in-sandbox launcher (loopback forwards + secret env), and the interpreter
# that runs it inside the sandbox (the host's /usr is mounted read-only).
_LAUNCHER_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inside.py")
_LAUNCHER_PYTHON = "/usr/bin/python3"
LAUNCHER_ARGV_PREFIX = [_LAUNCHER_PYTHON, "-I", "-S", LAUNCHER_PATH]

# usr-merge symlinks recreated inside the sandbox so /bin/sh etc. resolve.
_USRMERGE_SYMLINKS = [
    ("usr/bin", "/bin"),
    ("usr/sbin", "/sbin"),
    ("usr/lib", "/lib"),
    ("usr/lib64", "/lib64"),
]


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


class LocalBackend(SandboxBackend):
    """bubblewrap + cgroup v2 + strace driver for local development."""

    name = "local"

    def __init__(self) -> None:
        self._caps: Optional[Capabilities] = None
        self._uid = os.getuid()

    # -- capability probing -------------------------------------------------

    def capabilities(self) -> Capabilities:
        if self._caps is not None:
            return self._caps

        notes: dict[str, str] = {}
        bwrap = _which("bwrap")
        strace = _which("strace")
        systemd_run = _which("systemd-run")

        fs_iso = False
        net_iso = False
        if not bwrap:
            notes["bwrap"] = "not found on PATH; filesystem isolation unavailable"
        else:
            ok, detail = self._probe_userns(bwrap)
            fs_iso = ok
            net_iso = ok  # same --unshare mechanism
            notes["bwrap"] = detail

        mem = cpu = pids = False
        if not systemd_run:
            notes["cgroup"] = "systemd-run not found; resource limits unavailable"
        else:
            ok, detail = self._probe_cgroup(systemd_run)
            mem = cpu = pids = ok
            notes["cgroup"] = detail

        syscall = bool(strace)
        notes["strace"] = (
            f"present ({strace})" if strace else "not found; syscall observation off"
        )
        if net_iso:
            notes["network"] = (
                "every sandbox gets its own network namespace (bwrap --unshare-net); "
                "only bridged fake services and the recording egress gate are reachable")
        if not os.path.exists(_LAUNCHER_PYTHON):
            notes["launcher"] = (f"{_LAUNCHER_PYTHON} missing: loopback forwards and "
                                 "secret env are unavailable (such runs error out)")

        self._caps = Capabilities(
            backend=self.name,
            filesystem_isolation=fs_iso,
            network_isolation=net_iso,
            memory_limit=mem,
            cpu_limit=cpu,
            pids_limit=pids,
            syscall_observation=syscall,
            notes=notes,
        )
        return self._caps

    def _probe_userns(self, bwrap: str) -> tuple[bool, str]:
        """Actually create a throwaway user namespace; don't trust a version.

        Mirrors the real mount layout (usr-merge symlinks so the dynamic loader
        at /lib64 resolves) so that a green result means an agent can truly run
        inside the sandbox, not just that the namespace was created.
        """
        args = [bwrap, "--unshare-user", "--ro-bind", "/usr", "/usr"]
        for src, dst in _USRMERGE_SYMLINKS:
            if os.path.exists("/" + src):
                args += ["--symlink", src, dst]
        args += ["--proc", "/proc", "--die-with-parent", "--", "/usr/bin/true"]
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"bwrap probe failed to launch: {exc}"
        if proc.returncode == 0:
            return True, "unprivileged user namespaces work"
        err = (proc.stderr or "").strip().splitlines()
        detail = err[-1] if err else f"exit {proc.returncode}"
        if "uid map" in (proc.stderr or "") or "Permission denied" in (proc.stderr or ""):
            detail += " (remedy: sysctl kernel.apparmor_restrict_unprivileged_userns=0)"
        return False, f"user namespace creation blocked: {detail}"

    def _probe_cgroup(self, systemd_run: str) -> tuple[bool, str]:
        """Enforce a tiny cap on /usr/bin/true to prove the controller works."""
        if not os.environ.get("XDG_RUNTIME_DIR"):
            return False, "no XDG_RUNTIME_DIR; user systemd manager unreachable"
        try:
            proc = subprocess.run(
                [systemd_run, "--user", "--scope", "--quiet",
                 "-p", "MemoryMax=64M", "-p", "MemorySwapMax=0", "-p", "TasksMax=64",
                 "--", "/usr/bin/true"],
                capture_output=True, text=True, timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"systemd-run probe failed: {exc}"
        if proc.returncode == 0:
            return True, "systemd-run --user enforces MemoryMax/TasksMax (cgroup v2)"
        err = (proc.stderr or "").strip().splitlines()
        return False, "systemd-run --user failed: " + (err[-1] if err else "unknown")

    # -- lifecycle ----------------------------------------------------------

    def create(self, spec: SandboxSpec) -> SandboxHandle:
        caps = self.capabilities()
        if not caps.can_isolate:
            # Fail closed: never run a hostile scenario without isolation.
            raise IsolationError(
                "LocalBackend cannot establish filesystem isolation: "
                + caps.notes.get("bwrap", "bwrap unavailable")
            )
        root = tempfile.mkdtemp(prefix="agentrig-")
        work = os.path.join(root, "work")
        control = os.path.join(root, ".control")
        os.mkdir(work, 0o755)
        os.mkdir(control, 0o700)
        sandbox_id = os.path.basename(root)
        return SandboxHandle(
            sandbox_id=sandbox_id,
            spec=spec,
            root=root,
            work_dir=work,
            control_dir=control,
        )

    def put_file(self, handle: SandboxHandle, rel_path: str, data: bytes,
                 *, mode: int = 0o644) -> None:
        target = self._resolve_work(handle, rel_path)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as fh:
            fh.write(data)
        os.chmod(target, mode)

    def get_file(self, handle: SandboxHandle, rel_path: str) -> bytes:
        with open(self._resolve_work(handle, rel_path), "rb") as fh:
            return fh.read()

    def _resolve_work(self, handle: SandboxHandle, rel_path: str) -> str:
        rel = rel_path.lstrip("/")
        target = os.path.realpath(os.path.join(handle.work_dir, rel))
        base = os.path.realpath(handle.work_dir)
        if target != base and not target.startswith(base + os.sep):
            raise BackendError(f"refusing path escape outside work dir: {rel_path!r}")
        return target

    def destroy(self, handle: SandboxHandle) -> None:
        # Stop any lingering scope first, then remove the tree. Idempotent.
        unit = handle.extra.get("scope_unit")
        if unit:
            try:
                subprocess.run(["systemctl", "--user", "stop", unit],
                               capture_output=True, timeout=10)
            except (OSError, subprocess.SubprocessError):
                pass
        shutil.rmtree(handle.root, ignore_errors=True)

    # -- execution ----------------------------------------------------------

    def exec(self, handle: SandboxHandle, argv: list[str], *,
             stdin: Optional[str] = None, timeout: Optional[float] = None) -> ExecResult:
        caps = self.capabilities()
        spec = handle.spec
        limits = spec.limits
        wall = timeout if timeout is not None else limits.wall_timeout_s

        trace_path = None
        cmd: list[str] = []

        # Layer 1: cgroup scope (best-effort; absence never disables isolation).
        scope_unit = None
        if caps.memory_limit and _which("systemd-run"):
            scope_unit = f"agentrig-{handle.sandbox_id}-{int(time.time()*1000) & 0xffffff}.scope"
            handle.extra["scope_unit"] = scope_unit
            cmd += ["systemd-run", "--user", "--scope", "--quiet", "--unit", scope_unit]
            if limits.memory_mb:
                cmd += ["-p", f"MemoryMax={limits.memory_mb}M", "-p", "MemorySwapMax=0"]
            if limits.cpu_quota_percent:
                cmd += ["-p", f"CPUQuota={limits.cpu_quota_percent}%"]
            if limits.pids_max:
                cmd += ["-p", f"TasksMax={limits.pids_max}"]
            cmd += ["--"]

        # Layer 2: strace observation (host-side log the agent cannot touch).
        if spec.trace_syscalls and caps.syscall_observation:
            trace_path = os.path.join(handle.control_dir, "trace.log")
            cmd += ["strace", "-f", "-qq", "-y", "-yy", "-s", "256",
                    "-e", f"trace={TRACE_SYSCALLS}", "-o", trace_path]

        # Layer 3: bubblewrap isolation.
        cmd += self._bwrap_args(handle)

        # Layer 4: the agent -- behind the in-sandbox launcher when it needs
        # loopback forwards or secret env. The launcher config (which may hold
        # secrets) travels through an inherited pipe: never argv, never disk.
        pass_fds: tuple[int, ...] = ()
        cfg_fd = None
        if spec.forwards or spec.secret_env:
            if not os.path.exists(_LAUNCHER_PYTHON):
                raise BackendError(caps.notes.get("launcher", "launcher unavailable"))
            cfg = {"forwards": [{"port": port, "unix": f"{NET_MOUNT}/{sock}"}
                                for port, sock in spec.forwards],
                   "env": dict(spec.secret_env)}
            cfg_fd, wfd = os.pipe()
            data = json.dumps(cfg).encode("utf-8")
            if len(data) > 60000:  # stay under the pipe buffer; no writer thread
                os.close(cfg_fd)
                os.close(wfd)
                raise BackendError("launcher config too large")
            os.write(wfd, data)
            os.close(wfd)
            pass_fds = (cfg_fd,)
            cmd += LAUNCHER_ARGV_PREFIX + [str(cfg_fd), "--"]
        cmd += list(argv)

        env = self._sandbox_env_passthrough()
        rusage_before = rss.max_child_rss_kb()
        stop_poll = threading.Event()
        peak_holder: dict[str, Optional[int]] = {"kb": None}
        poller = None
        if scope_unit:
            poller = threading.Thread(
                target=rss.poll_peak_rss,
                args=(self._uid, scope_unit, stop_poll, peak_holder), daemon=True)
            poller.start()

        start = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.Popen(
                cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=env, text=True, errors="replace",
                start_new_session=True,  # own process group for clean kill
                pass_fds=pass_fds,
            )
        except OSError as exc:
            stop_poll.set()
            raise BackendError(f"failed to launch sandbox command: {exc}") from exc
        finally:
            if cfg_fd is not None:
                os.close(cfg_fd)

        try:
            out, err = proc.communicate(input=stdin, timeout=wall)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            self._kill_group(proc)
            try:
                out, err = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                out, err = "", ""
            rc = proc.returncode
        finally:
            stop_poll.set()
            if poller:
                poller.join(timeout=2)

        duration = time.monotonic() - start
        peak = peak_holder["kb"]
        if peak is None:
            after = rss.max_child_rss_kb()
            if after and (rusage_before is None or after >= rusage_before):
                peak = after  # approximate: largest child RSS across the process

        return ExecResult(
            argv=list(argv), exit_code=rc, timed_out=timed_out,
            duration_s=round(duration, 4), stdout=out or "", stderr=err or "",
            peak_rss_kb=peak, trace_path=trace_path, backend=self.name,
        )

    def _bwrap_args(self, handle: SandboxHandle) -> list[str]:
        spec = handle.spec
        args = ["bwrap",
                "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
                "--die-with-parent", "--new-session",
                "--ro-bind", "/usr", "/usr"]
        for src, dst in _USRMERGE_SYMLINKS:
            if os.path.exists("/" + src):
                args += ["--symlink", src, dst]
        # /etc is exposed read-only for realism (SSL certs, resolv.conf, passwd).
        # It is read-only, so the agent cannot damage host config; $HOME and the
        # rest of the host filesystem remain invisible.
        if os.path.isdir("/etc"):
            args += ["--ro-bind", "/etc", "/etc"]
        args += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
        # Read-only mounts (e.g. the agent-under-test's code), added before the
        # workdir so /work always wins if paths ever overlap.
        for host_path, sandbox_path in spec.ro_mounts:
            if os.path.exists(host_path):
                args += ["--ro-bind", host_path, sandbox_path]
        if spec.forwards or spec.secret_env:
            args += ["--ro-bind", _LAUNCHER_SRC, LAUNCHER_PATH]
        if spec.net_dir:
            args += ["--ro-bind", spec.net_dir, NET_MOUNT]
        args += ["--bind", handle.work_dir, SANDBOX_WORKDIR, "--chdir", SANDBOX_WORKDIR]
        # Egress is enforced, not just recorded: every sandbox -- "none" and
        # "loopback" alike -- gets its own network namespace with only `lo`.
        # Scenario services and the egress gate are bridged in by the launcher.
        args += ["--unshare-net"]
        # The sandbox root is bwrap's private tmpfs. Make it read-only once the
        # mounts are in place, so `mkdir -p $HOME && cp ... $HOME/` is *denied*
        # (EROFS) rather than landing on the throwaway root: only /work and
        # /tmp are writable. (Either way the host is untouched and the attempt
        # is recorded; read-only makes the denial real.)
        args += ["--remount-ro", "/"]
        # Controlled environment: clear everything, then set only what we choose.
        args += ["--clearenv"]
        for key, value in self._agent_env(handle).items():
            args += ["--setenv", key, value]
        args += ["--"]
        return args

    def _agent_env(self, handle: SandboxHandle) -> dict[str, str]:
        # HOME points at the *real host home path* on purpose: a scenario that
        # coaxes a write to "$HOME/..." then resolves outside every mount, so
        # the attempt is denied by isolation and still recorded by strace.
        host_home = os.path.realpath(os.path.expanduser("~"))
        env = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": host_home,
            "TMPDIR": "/tmp",
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "AGENTRIG_WORKDIR": SANDBOX_WORKDIR,
            # Don't let the interpreter scribble .pyc into the read-only agent
            # mount; that would otherwise surface as a spurious write attempt.
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        env.update(handle.spec.env)  # scenario-provided vars win
        return env

    def _sandbox_env_passthrough(self) -> dict[str, str]:
        # Env for the *outer* command (systemd-run/strace/bwrap). The user
        # systemd manager needs these; the agent never sees them (bwrap
        # --clearenv wipes the slate before --setenv).
        keep = ("PATH", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "HOME",
                "USER", "LOGNAME", "LANG", "TERM")
        return {k: os.environ[k] for k in keep if k in os.environ}

    def _kill_group(self, proc: subprocess.Popen) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except OSError:
                pass
