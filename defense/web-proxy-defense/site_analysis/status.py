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


def summary(folder, stall_minutes):
    path = folder / 'ledger.json'
    if not path.exists():
        return None
    ledger = json.loads(path.read_text(encoding='utf-8-sig'))
    calls = ledger.get('calls') or []
    remaining = ledger.get('remaining_stages') or []
    age = (time.time() - path.stat().st_mtime) / 60
    return {'folder': folder.name, 'spent_usd': float(ledger.get('spent_usd') or 0),
            'max_cost_usd': ledger.get('max_cost_usd'), 'calls': len(calls),
            'inflight': bool(calls and calls[-1].get('inflight')),
            'next_stage': next_stage(remaining), 'remaining_stages': len(remaining),
            'minutes_since_record': age, 'stalled': bool(remaining) and age > stall_minutes,
            'failed_calls': Counter(call.get('error') for call in calls if call.get('error')).most_common(),
            'recent_purposes': Counter(call.get('purpose') for call in calls[-20:]).most_common(),
            # For the console's stage timeline; the command-line report does not print these.
            'remaining': [compact(row) for row in remaining if isinstance(row, dict)],
            'last_purpose': calls[-1].get('purpose') if calls else None}


def compact(row):
    """One remaining stage as stage, run, authority, scope and how many units are left."""
    stage = row.get('stage')
    if stage == 'privacy':
        count = sum(row.get(key) or 0 for key in ('axis_cells', 'fact_cells', 'decision_cells', 'working_notes_cells',
                                                  'cell_count'))
    else:
        count = row.get('axis_count') if stage == 'merge' else row.get('group_count')
    return {'stage': stage, 'run': row.get('run'), 'authority': row.get('authority'), 'scope': row.get('scope'),
            'count': count}


def report(folder, stall_minutes):
    view = summary(folder, stall_minutes)
    if view is None:
        return f'{folder.name}: 장부 없음(아직 시작 전이거나 다른 체크포인트)'
    lines = [f'{folder.name}',
             f'  비용: {view["spent_usd"]:.2f} / {view["max_cost_usd"]} 달러, 호출 {view["calls"]}회'
             f'{", 호출 진행 중" if view["inflight"] else ""}',
             f'  다음 단계: {view["next_stage"]}, 남은 단계 {view["remaining_stages"]}개',
             f'  마지막 기록: {view["minutes_since_record"]:.0f}분 전' + (f' (남은 일이 있는데 {stall_minutes}분 넘게 기록이 없음: 멈춤 의심)'
                                                                     if view['stalled'] else '')]
    if view['failed_calls']:
        lines.append('  실패 호출: ' + ', '.join(f'{name} {count}' for name, count in view['failed_calls']))
    if view['recent_purposes']:
        lines.append('  최근 20회 목적: ' + ', '.join(f'{name} {count}' for name, count in view['recent_purposes']))
    if not view['remaining_stages']:
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
