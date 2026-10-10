"""Read-only progress view of an analysis run, from its private cost ledger only.

python -m site_analysis.status --out <record path> [--origin-url URL] [--checkpoint-root DIR] [--watch SECONDS]
"""
import argparse
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

from .resume import checkpoint_path


def folders(args):
    if args.origin_url:
        return [checkpoint_path(args.out, args.origin_url, args.checkpoint_root)]
    # Without the origin the hash is unknown; list every checkpoint made for this output name.
    base = checkpoint_path(args.out, '', args.checkpoint_root).parent
    return sorted(base.glob(Path(args.out).name + '-*'), key=lambda path: path.stat().st_mtime)


def report(folder, stall_minutes):
    path = folder / 'ledger.json'
    if not path.exists():
        return f'{folder.name}: 장부 없음(아직 시작 전이거나 다른 체크포인트)'
    ledger = json.loads(path.read_text(encoding='utf-8-sig'))
    calls = ledger.get('calls') or []
    remaining = ledger.get('remaining_stages') or []
    age = (time.time() - path.stat().st_mtime) / 60
    errors = Counter(call.get('error') for call in calls if call.get('error'))
    lines = [f'{folder.name}',
             f'  비용: {float(ledger.get("spent_usd") or 0):.2f} / {ledger.get("max_cost_usd")} 달러, 호출 {len(calls)}회'
             f'{", 호출 진행 중" if calls and calls[-1].get("inflight") else ""}',
             f'  다음 단계: {next_stage(remaining)}, 남은 단계 {len(remaining)}개',
             f'  마지막 기록: {age:.0f}분 전' + (f' (남은 일이 있는데 {stall_minutes}분 넘게 기록이 없음: 멈춤 의심)'
                                             if remaining and age > stall_minutes else '')]
    if errors:
        lines.append('  실패 호출: ' + ', '.join(f'{name} {count}' for name, count in errors.most_common()))
    recent = Counter(call.get('purpose') for call in calls[-20:])
    if recent:
        lines.append('  최근 20회 목적: ' + ', '.join(f'{name} {count}' for name, count in recent.most_common()))
    if not remaining:
        lines.append('  남은 단계 없음: 끝났거나 아직 계획 전')
    return '\n'.join(lines)


def next_stage(remaining):
    if not remaining:
        return '없음'
    row = remaining[0]
    return row.get('stage', '?') + (f' {row["run"]}회차' if row.get('run') else '')


def main(argv=None):
    parser = argparse.ArgumentParser(description='분석 진행 상황(비공개 비용 장부만 읽음)')
    parser.add_argument('--out', required=True, help='분석 실행에 준 --out 경로')
    parser.add_argument('--origin-url', help='분석 실행에 준 --origin-url. 주면 해당 체크포인트만 본다')
    parser.add_argument('--checkpoint-root', help='분석 실행에 --checkpoint-root를 줬다면 같은 값')
    parser.add_argument('--watch', type=int, default=0, help='초 단위 갱신 간격. 0이면 한 번만 출력')
    parser.add_argument('--stall-minutes', type=int, default=20)
    args = parser.parse_args(argv)
    while True:
        found = folders(args)
        print('\n\n'.join(report(folder, args.stall_minutes) for folder in found) or '체크포인트를 찾지 못함')
        if not args.watch:
            return 0 if found else 1
        time.sleep(args.watch)
        print('\n' + '-' * 40)


if __name__ == '__main__':
    sys.exit(main())
