# main.py
from __future__ import annotations
import argparse
from pathlib import Path

from forensic_analyzer.inventory import collect_inventory, write_inventory_csv
from forensic_analyzer.hashing import add_hashes_to_rows

def cmd_inventory(args: argparse.Namespace) -> None:
    rows = collect_inventory(
        args.root,
        follow_symlinks=args.follow_symlinks,
        exclude_globs=args.exclude,
    )
    if args.with_hash:
        rows = add_hashes_to_rows(
            rows,
            algorithms=("md5", "sha256"),
            chunk_size=args.hash_block_size,
        )
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    write_inventory_csv(rows, out_path)
    print(f"[OK] {len(rows)} files → {out_path}")

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ForensicFileAnalyzer",
        description="ForensicFileAnalyzer CLI"
    )
    sub = p.add_subparsers(dest="command", required=True)

    inv = sub.add_parser("inventory", help="파일 인벤토리 & 메타데이터 추출")
    inv.add_argument("root", help="스캔할 루트 폴더 경로")
    inv.add_argument("--out", default="outputs/inventory.csv",
                    help="CSV 저장 경로 (기본: outputs/inventory.csv)")
    inv.add_argument("--follow-symlinks", action="store_true",
                    help="심볼릭 링크를 따라감")
    inv.add_argument("--exclude", nargs="*", default=[
        "*/.git/*", "*/node_modules/*", "*.tmp", "*.log", "*.bak"
    ], help="제외할 글롭 패턴(공백 구분)")
    inv.add_argument("--with-hash", action="store_true",
                    help="인벤토리와 함께 MD5, SHA-256 해시 열 추가")
    inv.add_argument("--hash-block-size", type=int, default=1024 * 1024,
                    help="해시 블록 크기(바이트). 기본 1MB")

    inv.set_defaults(func=cmd_inventory)
    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
