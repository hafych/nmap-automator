import argparse
import os
import sys
import tempfile

from cryptography.fernet import InvalidToken
from dotenv import load_dotenv

from recon_operator.crypto import build_fernet_cipher, load_fernet_key_material

load_dotenv()


def _write_private_text(path: str, text: str) -> None:
    """Atomically write decrypted content with owner-only permissions."""
    destination = os.path.abspath(path)
    directory = os.path.dirname(destination)
    descriptor, temporary_path = tempfile.mkstemp(
        dir=directory,
        prefix=f".{os.path.basename(destination)}.",
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, destination)
        os.chmod(destination, 0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


def parse_args():
    parser = argparse.ArgumentParser(description="Decrypt result file encrypted by Recon Operator.")
    parser.add_argument("input_file", help="Path to encrypted result file")
    parser.add_argument(
        "-o",
        "--output",
        help="Output file path (optional). If not set, decrypted data is printed",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    # Primary FERNET_KEY encrypts; FERNET_PREVIOUS_KEYS decrypt older results.
    keys = load_fernet_key_material()
    cipher = build_fernet_cipher(keys)

    with open(args.input_file, "rb") as f:
        encrypted_data = f.read()

    decrypted = cipher.decrypt(encrypted_data)
    text = decrypted.decode("utf-8")

    if args.output:
        _write_private_text(args.output, text)
        print(f"Decrypted content written to {args.output}")
    else:
        print(text)


def cli() -> int:
    try:
        main()
    except InvalidToken:
        print("Decryption failed: wrong FERNET_KEY or corrupted input file.", file=sys.stderr)
        return 1
    except (RuntimeError, OSError, UnicodeDecodeError) as exc:
        print(f"Decryption failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
