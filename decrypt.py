import argparse
import os
import tempfile

from cryptography.fernet import Fernet
from dotenv import load_dotenv

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
    parser = argparse.ArgumentParser(description="Decrypt result file encrypted by nmap-automator.")
    parser.add_argument("input_file", help="Path to encrypted result file")
    parser.add_argument(
        "-o",
        "--output",
        help="Output file path (optional). If not set, decrypted data is printed",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    fernet_key = os.getenv("FERNET_KEY", "").strip()
    if not fernet_key:
        raise RuntimeError("FERNET_KEY is required in environment.")

    try:
        cipher = Fernet(fernet_key.encode())
    except Exception as exc:
        raise RuntimeError("Invalid FERNET_KEY. Must be valid Fernet key.") from exc

    with open(args.input_file, "rb") as f:
        encrypted_data = f.read()

    decrypted = cipher.decrypt(encrypted_data)
    text = decrypted.decode("utf-8")

    if args.output:
        _write_private_text(args.output, text)
        print(f"Decrypted content written to {args.output}")
    else:
        print(text)


if __name__ == "__main__":
    main()
