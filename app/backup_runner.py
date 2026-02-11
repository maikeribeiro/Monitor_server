from app import _create_backup


def main() -> int:
    ok, message = _create_backup()
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
