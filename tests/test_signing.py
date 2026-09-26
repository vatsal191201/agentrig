import os
import tempfile
import unittest

from agentrig import signing


@unittest.skipUnless(signing.crypto_available(), "cryptography not installed")
class TestSigning(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="arig-key-")
        self.key = os.path.join(self.tmp, "k.key")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_sign_verify_roundtrip(self):
        signer = signing.Signer(key_path=__import__("pathlib").Path(self.key))
        self.assertTrue(signer.available)
        data = b"hello chain head"
        sig = signer.sign_hex(data)
        self.assertTrue(signing.verify_signature(signer.public_key_hex(), data, sig))

    def test_tampered_data_fails(self):
        signer = signing.Signer(key_path=__import__("pathlib").Path(self.key))
        sig = signer.sign_hex(b"original")
        self.assertFalse(signing.verify_signature(signer.public_key_hex(), b"tampered", sig))

    def test_key_persists(self):
        from pathlib import Path
        s1 = signing.Signer(key_path=Path(self.key))
        s2 = signing.Signer(key_path=Path(self.key))
        self.assertEqual(s1.public_key_hex(), s2.public_key_hex())

    def test_key_permissions(self):
        from pathlib import Path
        signing.Signer(key_path=Path(self.key))
        mode = os.stat(self.key).st_mode & 0o777
        self.assertEqual(mode, 0o600)


if __name__ == "__main__":
    unittest.main()
