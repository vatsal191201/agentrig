import os
import tempfile
import unittest

from agentrig.observe.manifest import Manifest, diff_manifests


class TestManifest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="arig-test-")
        self._write("keep.txt", "keep")
        self._write("mod.txt", "before")
        self._write("gone.txt", "bye")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def _write(self, rel, content):
        p = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(content)

    def test_diff_created_modified_deleted(self):
        before = Manifest.snapshot(self.dir)
        self._write("mod.txt", "after")            # modify
        os.remove(os.path.join(self.dir, "gone.txt"))  # delete
        self._write("new/added.txt", "hi")         # create (nested)
        after = Manifest.snapshot(self.dir)
        d = diff_manifests(before, after)
        self.assertEqual(d.created, ["new/added.txt"])
        self.assertEqual(d.modified, ["mod.txt"])
        self.assertEqual(d.deleted, ["gone.txt"])
        self.assertTrue(d.changed_any)

    def test_no_change(self):
        before = Manifest.snapshot(self.dir)
        after = Manifest.snapshot(self.dir)
        d = diff_manifests(before, after)
        self.assertFalse(d.changed_any)


if __name__ == "__main__":
    unittest.main()
