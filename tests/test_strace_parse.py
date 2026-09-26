import unittest

from agentrig.observe import strace_parse as sp


class TestStraceParse(unittest.TestCase):
    def parse(self, lines):
        return sp.parse_lines(lines, workdir="/work")

    def test_read_under_workdir(self):
        ev = self.parse([
            '111 openat(AT_FDCWD</work>, "/work/.env", O_RDONLY|O_CLOEXEC) = 3</work/.env>',
        ])
        self.assertEqual(ev, [{"type": "file_read", "path": "/work/.env",
                               "open_flags": "O_RDONLY|O_CLOEXEC"}])

    def test_read_write_open_is_also_a_read(self):
        ev = self.parse(['openat(AT_FDCWD</work>, "solution.md", O_RDWR) = 3'])
        self.assertEqual(ev[0]["type"], "file_read")

    def test_failed_open_is_not_a_read(self):
        self.assertEqual(self.parse([
            'openat(AT_FDCWD</work>, "solution.md", O_RDONLY) = -1 EACCES']), [])

    def test_relative_read_resolved_via_dirfd(self):
        ev = self.parse([
            '111 openat(AT_FDCWD</work>, "notes.txt", O_RDONLY) = 4</work/notes.txt>',
        ])
        self.assertEqual(ev[0]["path"], "/work/notes.txt")

    def test_reads_outside_workdir_are_dropped(self):
        ev = self.parse([
            '111 openat(AT_FDCWD</work>, "/usr/lib/x.so", O_RDONLY) = 5</usr/lib/x.so>',
        ])
        self.assertEqual(ev, [])

    def test_denied_write_to_home_recorded(self):
        ev = self.parse([
            '111 openat(AT_FDCWD</work>, "/home/u/x", O_WRONLY|O_CREAT|O_TRUNC, 0666) = -1 ENOENT (x)',
        ])
        self.assertEqual(ev, [{"type": "file_write_attempt_denied",
                               "path": "/home/u/x", "errno": "ENOENT"}])

    def test_denied_write_to_etc_recorded_not_noise(self):
        ev = self.parse([
            '111 openat(AT_FDCWD</work>, "/etc/cron.d/p", O_WRONLY|O_CREAT, 0644) = -1 EROFS (ro)',
        ])
        self.assertEqual(ev[0]["type"], "file_write_attempt_denied")
        self.assertEqual(ev[0]["path"], "/etc/cron.d/p")

    def test_workdir_writes_left_to_manifest(self):
        ev = self.parse([
            '111 openat(AT_FDCWD</work>, "out.txt", O_WRONLY|O_CREAT, 0644) = 6</work/out.txt>',
        ])
        self.assertEqual(ev, [])

    def test_tmp_writes_are_noise(self):
        ev = self.parse([
            '111 openat(AT_FDCWD</work>, "/tmp/scratch", O_WRONLY|O_CREAT, 0644) = 7',
        ])
        self.assertEqual(ev, [])

    def test_connect_ipv4_allowed_and_denied(self):
        ev = self.parse([
            '111 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 EINPROGRESS (x)',
            '111 connect(4, {sa_family=AF_INET, sin_port=htons(9), sin_addr=inet_addr("10.0.0.5")}, 16) = -1 ECONNREFUSED (x)',
        ])
        self.assertEqual(ev[0], {"type": "connect", "family": "AF_INET",
                                 "addr": "127.0.0.1", "port": 80, "result": "ok",
                                 "errno": "EINPROGRESS"})
        self.assertEqual(ev[1]["result"], "denied")
        self.assertEqual(ev[1]["addr"], "10.0.0.5")

    def test_connect_ipv6(self):
        ev = self.parse([
            '111 connect(5, {sa_family=AF_INET6, sin6_port=htons(443), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0',
        ])
        self.assertEqual(ev[0]["family"], "AF_INET6")
        self.assertEqual(ev[0]["addr"], "::1")
        self.assertEqual(ev[0]["port"], 443)

    def test_af_unix_connect_dropped(self):
        ev = self.parse([
            '111 connect(6, {sa_family=AF_UNIX, sun_path="/run/x"}, 110) = 0',
        ])
        self.assertEqual(ev, [])

    def test_execve_spawn_and_harness_filter(self):
        ev = self.parse([
            '111 execve("/usr/bin/rm", ["rm", "-rf", "/work/d"], 0x0 /* 5 vars */) = 0',
            '110 execve("/usr/bin/bwrap", ["bwrap", "--unshare-user"], 0x0) = 0',
        ])
        self.assertEqual(ev, [{"type": "process_spawn", "path": "/usr/bin/rm",
                               "argv": ["rm", "-rf", "/work/d"]}])

    def test_unfinished_resumed_stitch(self):
        ev = self.parse([
            '111 connect(9, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16 <unfinished ...>',
            '111 <... connect resumed>) = 0',
        ])
        self.assertEqual(ev[0]["port"], 8080)
        self.assertEqual(ev[0]["result"], "ok")

    def test_agent_mount_write_is_filtered(self):
        # A denied bytecode-cache write into the agent's own (read-only) mount
        # must NOT be reported as an out-of-scope write (regression).
        line = ('111 openat(AT_FDCWD</work>, "/agent0/__pycache__/x.pyc.123", '
                'O_WRONLY|O_CREAT|O_EXCL, 0644) = -1 EROFS (ro)')
        self.assertEqual(sp.parse_lines([line], workdir="/work"),
                         [{"type": "file_write_attempt_denied",
                           "path": "/agent0/__pycache__/x.pyc.123", "errno": "EROFS"}])
        # with the agent mount declared as noise, it is dropped
        self.assertEqual(
            sp.parse_lines([line], workdir="/work",
                           extra_noise_write_roots=("/agent0",)), [])

    def test_unlink_and_rename_under_workdir(self):
        ev = self.parse([
            '111 unlink("/work/a") = 0',
            '111 rename("/work/a", "/work/b") = 0',
        ])
        self.assertEqual(ev[0], {"type": "file_delete", "path": "/work/a"})
        self.assertEqual(ev[1]["type"], "file_rename")


if __name__ == "__main__":
    unittest.main()
