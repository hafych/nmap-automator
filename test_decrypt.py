import contextlib
import io
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.fernet import Fernet

import decrypt


class DecryptTests(unittest.TestCase):
    def test_main_decrypts_to_output_file(self):
        key = Fernet.generate_key()
        plaintext = '{"status": "ok"}\n'

        with tempfile.TemporaryDirectory() as tmp:
            encrypted_path = Path(tmp) / "scan.enc"
            output_path = Path(tmp) / "scan.json"
            encrypted_path.write_bytes(Fernet(key).encrypt(plaintext.encode()))

            original_argv = sys.argv
            original_key = os.environ.get("FERNET_KEY")
            sys.argv = ["decrypt.py", str(encrypted_path), "-o", str(output_path)]
            os.environ["FERNET_KEY"] = key.decode()
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    decrypt.main()
            finally:
                sys.argv = original_argv
                if original_key is None:
                    os.environ.pop("FERNET_KEY", None)
                else:
                    os.environ["FERNET_KEY"] = original_key

            self.assertEqual(output_path.read_text(encoding="utf-8"), plaintext)
            self.assertEqual(stat.S_IMODE(output_path.stat().st_mode), 0o600)

    def test_main_requires_key(self):
        original_argv = sys.argv
        original_key = os.environ.pop("FERNET_KEY", None)
        sys.argv = ["decrypt.py", "unused.enc"]
        try:
            with self.assertRaisesRegex(RuntimeError, "FERNET_KEY"):
                decrypt.main()
        finally:
            sys.argv = original_argv
            if original_key is not None:
                os.environ["FERNET_KEY"] = original_key
