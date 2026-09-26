"""Shared, evidence-based read and executable matching for checks and guards."""

from __future__ import annotations

import os
import re
import shlex
import stat
from typing import Iterator, Optional


def under_path(path: str, under: str) -> bool:
    norm = under.strip("/")
    return f"/{norm}/" in (path.rstrip("/") + "/")


def is_file_read(event: dict) -> bool:
    return (event.get("type") == "file_read"
            and not event.get("is_directory", False)
            and not any(f in event.get("open_flags", "")
                        for f in ("O_DIRECTORY", "O_PATH")))


def snapshot_directory(path: str, root: Optional[str], workdir: str = "/work"
                       ) -> Optional[bool]:
    """Inspect only the sandbox snapshot, never the host's /work or symlinks out."""
    if root is None or not (path == workdir or path.startswith(workdir + "/")):
        return None
    root = os.path.realpath(root)
    local = os.path.realpath(os.path.join(root, os.path.relpath(path, workdir)))
    if os.path.commonpath((root, local)) != root:
        return None
    try:
        return stat.S_ISDIR(os.stat(local).st_mode)
    except OSError:
        return None


_ASSIGNMENT = re.compile(r"[a-zA-Z_][a-zA-Z_0-9]*=")
_SHELLS = {"sh", "bash", "dash", "zsh"}
# Options whose next argument is configuration, not the wrapped command.
_OPTION_ARGS = {
    "env": {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"},
    "exec": {"-a"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "xargs": {"-a", "--arg-file", "-d", "--delimiter", "-E", "-I", "-L",
              "-n", "--max-args", "-P", "--max-procs", "-s", "--max-chars"},
    "command": set(), "nohup": set(),
}


def _programs(argv: list[str], depth: int = 0) -> Iterator[str]:
    if depth > 20:
        return
    i = 0
    while i < len(argv) and _ASSIGNMENT.match(argv[i]):
        i += 1
    if i == len(argv):
        return
    program = argv[i]
    yield program
    name = os.path.basename(program)
    args = argv[i + 1:]
    if name in _SHELLS:
        for j, arg in enumerate(args):
            if arg == "--" or not arg.startswith("-"):
                break
            if not arg.startswith("--") and "c" in arg[1:]:
                if j + 1 < len(args):
                    yield from _shell_programs(args[j + 1], depth + 1)
                break
    elif name in _OPTION_ARGS:
        j = 0
        while j < len(args) and args[j].startswith("-"):
            option = args[j]
            if option == "--":
                j += 1
                break
            # These query a command's location; they do not execute it.
            if name == "command" and ("v" in option or "V" in option):
                return
            if option in ("--help", "--version"):
                return
            if name == "env" and option in ("-S", "--split-string"):
                if j + 1 < len(args):
                    try:
                        expanded = shlex.split(args[j + 1]) + args[j + 2:]
                    except ValueError:
                        return
                    yield from _programs(expanded, depth + 1)
                return
            j += 2 if option in _OPTION_ARGS[name] else 1
        if name == "timeout":
            j += 1  # duration
        yield from _programs(args[j:], depth + 1)


def _shell_segments(source: str, start: int = 0, end: str = ""):
    """Split shell command positions without turning quoted arguments into code.

    Substitutions are parsed separately, including inside double quotes. This
    is a lexical check, not shell evaluation: variables and aliases are left
    to their actual exec events.
    """
    segments, nested, word = [], [], []
    quote = ""
    i = start
    while i < len(source):
        c = source[i]
        if c == "\\" and quote != "'" and i + 1 < len(source):
            word.extend(source[i:i + 2])
            i += 2
            continue
        if end and c == end and not quote:
            break
        if quote != "'" and (source.startswith("$(", i) or c == "`"):
            offset, close = (2, ")") if c == "$" else (1, "`")
            sub, i = _shell_segments(source, i + offset, close)
            nested.extend(sub)
            word.append("__substitution__")
        elif c in "\"'":
            if quote == c:
                quote = ""
            elif not quote:
                quote = c
            word.append(c)
        elif not quote and c in ";&|\n()":
            segments.append("".join(word))
            word = []
        elif not quote and c == "#" and (not word or word[-1].isspace()):
            i = source.find("\n", i)
            if i < 0:
                i = len(source)
                break
            continue
        else:
            word.append(c)
        i += 1
    segments.append("".join(word))
    return segments + nested, i


def _shell_programs(source: str, depth: int) -> Iterator[str]:
    segments, _ = _shell_segments(source)
    for segment in segments:
        try:
            argv = shlex.split(segment)
        except ValueError:
            continue  # truncated trace strings cannot be evaluated as shell code
        # Shell syntax before a simple command, not executable arguments.
        while argv and argv[0] in {"if", "then", "elif", "else", "while", "until",
                                   "do", "!", "{"}:
            argv.pop(0)
        yield from _programs(argv, depth)


def command_match(event: dict, pattern: re.Pattern) -> Optional[str]:
    """Return the executable that matched, preserving the event as evidence."""
    argv = event.get("argv") or []
    path = event.get("path", "")
    candidates = [path] if path else []
    candidates.extend(_programs(argv))
    # argv[0] can be spoofed. The execve filename still identifies a shell.
    if path and os.path.basename(path) in _SHELLS and argv:
        candidates.extend(_programs([path, *argv[1:]]))
    return next((p for p in candidates
                 if pattern.search(os.path.basename(p)) or pattern.search(p)), None)
