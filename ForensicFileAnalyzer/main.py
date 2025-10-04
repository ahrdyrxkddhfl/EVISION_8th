# main.py
from __future__ import annotations
import argparse
import csv
from pathlib import Path
from typing import Dict, Iterable, List, Union

#내뷰 모듈 가져오기

from forensic_analyzer.inventory import collect_inventory #main에서 처리
from forensic_analyzer.hashing import add_hashes_to_rows
from forensic_analyzer.signature import add_signature_to_rows
from forensic_analyzer.search import search_texts, write_hits_csv
from forensic_analyzer.timeline import build_timeline_rows, write_timeline_csv, DEFAULT_EVENTS
from forensic_analyzer.validate import (
    validate_inventory_rows, sample_verify_hashes,
    write_issues_csv, summarize_issues
)


#공용

def _ensure_parent(path: Union[str, Path]) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

def _write_csv_dynamic(rows: List[Dict[str, object]], out_path: Union[str, Path]) -> None:
    """
    rows의 모든 키를 합쳐 동적 헤더를 만들고 CSV로 저장한다.
    UTF-8 with BOM(엑셀 호환).
    """
    out = _ensure_parent(out_path)
    # 헤더 생성(안정적 순서: 자주 쓰는 컬럼을 앞으로)
    preferred = [
        "path", "name", "parent", "size_bytes",
        "mtime_epoch", "atime_epoch", "ctime_epoch", "birthtime_epoch",
        "is_symlink",
        # 해시/시그니처/검색 등 확장 필드가 있다면 이어서 붙음
        "md5", "sha256",
        "sig_mime", "sig_ext", "sig_desc", "ext_on_disk", "ext_mismatch",
    ]
    keys_order: List[str] = []
    seen = set()
    for k in preferred:
        seen.add(k)
        keys_order.append(k)
    for r in rows:
        for k in r.keys():
            if k not in seen:
                seen.add(k)
                keys_order.append(k)

    with open(out, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys_order, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    print(f"[OK] saved {len(rows)} rows → {out}")

# =======================
# inventory 서브커맨드
# =======================

def cmd_inventory(args: argparse.Namespace) -> None:
    rows = collect_inventory(
        args.root,
        follow_symlinks=args.follow_symlinks,
        exclude_globs=args.exclude,
    )

    if args.with_hash:
        rows = add_hashes_to_rows(
            rows,
            algorithms=tuple(args.hash_algorithms),
            chunk_size=args.hash_block_size,
        )

    if args.with_signature:
        rows = add_signature_to_rows(
            rows,
            prefer_magic=not args.sig_no_magic,
            disk_ext_field="ext_on_disk",
            sig_prefix="sig_",
        )

    _write_csv_dynamic(rows, args.out)

# =======================
# search 서브커맨드
# =======================

def cmd_search(args: argparse.Namespace) -> None:
    if not args.keywords:
        raise SystemExit("[-] 검색할 키워드가 필요합니다 (예: --kw password --kw token)")
    hits = search_texts(
        root=args.root,
        keywords=args.keywords,
        use_regex=args.regex,
        case_sensitive=args.case_sensitive,
        include_exts=tuple(args.include_exts),
        exclude_globs=args.exclude,
        follow_symlinks=args.follow_symlinks,
        max_file_size_bytes=args.max_file_size,
        encodings=tuple(args.encodings),
        preview_max_len=args.preview_len,
    )
    _ensure_parent(args.out_hits)
    write_hits_csv(hits, args.out_hits)
    print(f"[OK] {len(hits)} hits → {args.out_hits}")

# =======================
# timeline 서브커맨드
# =======================

def cmd_timeline(args: argparse.Namespace) -> None:
    # 타임라인은 inventory 기반이므로 우선 rows 생성
    rows = collect_inventory(
        args.root,
        follow_symlinks=args.follow_symlinks,
        exclude_globs=args.exclude,
    )

    # 필요 시 해시/시그니처까지 붙여서 나중 분석에 도움이 되도록
    if args.with_hash:
        rows = add_hashes_to_rows(rows, algorithms=tuple(args.hash_algorithms), chunk_size=args.hash_block_size)
    if args.with_signature:
        rows = add_signature_to_rows(rows, prefer_magic=not args.sig_no_magic)

    timeline_rows = build_timeline_rows(
        rows,
        tz_offset_minutes=args.tz_offset_min,
        # 이벤트 커스터마이즈 필요하면 여기서 events=... 전달
    )
    write_timeline_csv(timeline_rows, args.out_timeline)
    print(f"[OK] {len(timeline_rows)} events → {args.out_timeline}")

    # 원하면 인벤토리도 같이 보존
    if args.out_inventory:
        _write_csv_dynamic(rows, args.out_inventory)

# =======================
# validate 서브커맨드
# =======================

def cmd_validate(args: argparse.Namespace) -> None:
    rows = collect_inventory(
        args.root,
        follow_symlinks=args.follow_symlinks,
        exclude_globs=args.exclude,
    )

    # 검증 전에 선택적으로 해시/시그니처를 붙여 정합성 체크 범위 확대
    if args.with_hash:
        rows = add_hashes_to_rows(rows, algorithms=tuple(args.hash_algorithms), chunk_size=args.hash_block_size)
    if args.with_signature:
        rows = add_signature_to_rows(rows, prefer_magic=not args.sig_no_magic)

    issues = []
    issues += validate_inventory_rows(
        rows,
        check_file_exists=not args.skip_exist_check,
        check_size_matches=not args.skip_size_check,
        allow_missing_birthtime=not args.strict_birthtime,
        detect_duplicate_paths=not args.skip_dup_check,
    )

    # 해시가 있는 경우에만 샘플 재검증
    if args.verify_hash and any(("md5" in r or "sha256" in r) for r in rows):
        issues += sample_verify_hashes(
            rows,
            algorithms=tuple(args.hash_algorithms),
            sample_ratio=args.hash_sample_ratio,
            sample_min=args.hash_sample_min,
            sample_max=args.hash_sample_max,
            chunk_size=args.hash_block_size,
        )

    _ensure_parent(args.out_issues)
    write_issues_csv(issues, args.out_issues)
    summary = summarize_issues(issues)
    print(f"[OK] issues: {len(issues)} → {args.out_issues}")
    print("[SUMMARY]", summary)

    # 원하면 인벤토리 스냅샷도 남김
    if args.out_inventory:
        _write_csv_dynamic(rows, args.out_inventory)

# =======================
# argparse
# =======================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ForensicFileAnalyzer", description="ForensicFileAnalyzer CLI")
    sub = p.add_subparsers(dest="command", required=True)

    # 공통 옵션 preset
    def add_common_inventory_opts(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("root", help="스캔할 루트 폴더 경로")
        sp.add_argument("--exclude", nargs="*", default=[
            "*/.git/*", "*/node_modules/*", "*.tmp", "*.log", "*.bak"
        ], help="제외할 글롭 패턴(공백 구분)")
        sp.add_argument("--follow-symlinks", action="store_true", help="심볼릭 링크를 따라감")

        # 해시
        sp.add_argument("--with-hash", action="store_true", help="MD5/SHA-256 해시 열 추가")
        sp.add_argument("--hash-algorithms", nargs="*", default=["md5", "sha256"], help="해시 알고리즘 목록")
        sp.add_argument("--hash-block-size", type=int, default=1024 * 1024, help="해시 블록 크기(바이트)")

        # 시그니처
        sp.add_argument("--with-signature", action="store_true", help="파일 시그니처(libmagic) 판정 열 추가")
        sp.add_argument("--sig-no-magic", action="store_true", help="libmagic 미사용(가능 시 mimetypes로 폴백)")

    # inventory
    inv = sub.add_parser("inventory", help="파일 인벤토리 & 메타데이터 추출(+옵션: 해시/시그니처)")
    add_common_inventory_opts(inv)
    inv.add_argument("--out", default="outputs/inventory.csv", help="CSV 저장 경로")
    inv.set_defaults(func=cmd_inventory)

    # search
    sea = sub.add_parser("search", help="경량 텍스트 키워드/정규식 검색")
    sea.add_argument("root", help="검색 루트 폴더")
    sea.add_argument("--kw", dest="keywords", action="append", default=[], help="검색 키워드/패턴 (여러 번 사용 가능)")
    sea.add_argument("--regex", action="store_true", help="키워드를 정규식으로 처리")
    sea.add_argument("--case-sensitive", action="store_true", help="대소문자 구분")
    sea.add_argument("--include-exts", nargs="*", default=["txt", "log", "csv", "json", "xml", "md", "ini", "conf"],
                     help="대상 확장자 화이트리스트")
    sea.add_argument("--exclude", nargs="*", default=["*/.git/*", "*/node_modules/*", "*.bak", "*.tmp"],
                     help="제외할 글롭 패턴")
    sea.add_argument("--follow-symlinks", action="store_true", help="심볼릭 링크를 따라감")
    sea.add_argument("--max-file-size", type=int, default=10 * 1024 * 1024, help="대상 파일 최대 크기(바이트)")
    sea.add_argument("--encodings", nargs="*", default=["utf-8", "cp949", "latin-1"], help="시도할 인코딩 목록")
    sea.add_argument("--preview-len", type=int, default=240, help="미리보기 최대 길이")
    sea.add_argument("--out-hits", default="outputs/keyword_hits.csv", help="검색 결과 CSV 경로")
    sea.set_defaults(func=cmd_search)

    # timeline
    tl = sub.add_parser("timeline", help="파일 활동 타임라인 CSV 생성")
    add_common_inventory_opts(tl)
    tl.add_argument("--tz-offset-min", type=int, default=None,
                    help="타임존 오프셋(분). 예: KST=540, UTC=0. 미지정(None)이면 시스템 로컬")
    tl.add_argument("--out-timeline", default="outputs/timeline.csv", help="타임라인 CSV 경로")
    tl.add_argument("--out-inventory", default="", help="(선택) 인벤토리 스냅샷 CSV 경로")
    tl.set_defaults(func=cmd_timeline)

    # validate
    va = sub.add_parser("validate", help="인벤토리 정합성/해시 샘플 검증 및 이슈 리포트")
    add_common_inventory_opts(va)
    va.add_argument("--skip-exist-check", action="store_true", help="파일 존재 여부 확인 생략")
    va.add_argument("--skip-size-check", action="store_true", help="실제 파일 크기 일치 확인 생략")
    va.add_argument("--strict-birthtime", action="store_true", help="birthtime_epoch 누락도 이슈로 처리")
    va.add_argument("--skip-dup-check", action="store_true", help="중복 path 검사 생략")

    va.add_argument("--verify-hash", action="store_true", help="해시 샘플 재검증 수행")
    va.add_argument("--hash-sample-ratio", type=float, default=0.05, help="해시 샘플 비율(0~1)")
    va.add_argument("--hash-sample-min", type=int, default=5, help="해시 샘플 최소 개수")
    va.add_argument("--hash-sample-max", type=int, default=200, help="해시 샘플 최대 개수")

    va.add_argument("--out-issues", default="outputs/validation_issues.csv", help="이슈 리포트 CSV 경로")
    va.add_argument("--out-inventory", default="", help="(선택) 인벤토리 스냅샷 CSV 경로")
    va.set_defaults(func=cmd_validate)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
