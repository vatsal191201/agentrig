"""Pre/post file manifest -- the authoritative record of what changed on disk.

We hash every file in the sandbox working tree before and after the run and
diff the two snapshots. This tells us, with certainty, which files were
created, modified, or deleted -- the ground truth for "did the agent actually
do the work" and "did it destroy anything". Reads are *not* visible here (a
read leaves no trace on disk); those come from strace.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from agentrig.util import sha256_file


@dataclass
class Manifest:
    """Map of workdir-relative path -> (sha256, size)."""

    files: dict[str, tuple[str, int]] = field(default_factory=dict)

    @classmethod
    def snapshot(cls, root: str) -> "Manifest":
        files: dict[str, tuple[str, int]] = {}
        root = os.path.realpath(root)
        for dirpath, _dirs, names in os.walk(root):
            for name in names:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, root)
                try:
                    if os.path.islink(full):
                        # Record the link target; do not follow (avoid escapes).
                        files[rel] = ("symlink:" + os.readlink(full), 0)
                    else:
                        st = os.stat(full)
                        files[rel] = (sha256_file(full), st.st_size)
                except OSError:
                    files[rel] = ("unreadable", -1)
        return cls(files=files)


@dataclass
class ManifestDiff:
    created: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "created": sorted(self.created),
            "modified": sorted(self.modified),
            "deleted": sorted(self.deleted),
        }

    @property
    def changed_any(self) -> bool:
        return bool(self.created or self.modified or self.deleted)


def diff_manifests(before: Manifest, after: Manifest) -> ManifestDiff:
    """Compute created/modified/deleted between two snapshots."""
    d = ManifestDiff()
    before_keys = set(before.files)
    after_keys = set(after.files)
    for path in after_keys - before_keys:
        d.created.append(path)
    for path in before_keys - after_keys:
        d.deleted.append(path)
    for path in before_keys & after_keys:
        if before.files[path][0] != after.files[path][0]:
            d.modified.append(path)
    return d
