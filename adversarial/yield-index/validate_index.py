#!/usr/bin/env python3
"""Validation and reporting for the reconstructed adversarial-yield index.

Reads (never modifies):
  searches.jsonl   - engagements, logical searches and raw segments
  findings.jsonl   - every vulnerability claim and its disposition

Checks identifiers and cross-references, detects impossible timestamp
ordering, detects findings that reference missing searches, derives search
durations from the raw segment timestamps, and prints aggregate counts.

Exit status is non-zero if any validation error is found.

Usage:  python3 validate_index.py [--dir DIR]
"""
import json, sys, os, datetime, argparse, collections

def load(path):
    rows = []
    with open(path) as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f'FATAL: {path}:{ln}: invalid JSON: {e}')
                sys.exit(2)
    return rows

def parse(ts):
    if ts is None:
        return None
    return datetime.datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=datetime.timezone.utc)

FAMILIES = {'code_execution','authority_bypass','information_disclosure',
            'integrity_violation','server_request_abuse','protocol_confusion',
            'cryptographic_trust_failure','denial_of_service','memory_safety',
            'unclassified'}
DISPOSITIONS = {'confirmed','duplicate','invalid','unresolved'}
TERMINATIONS = {'completed','interrupted','unclear'}
RELATIONSHIPS = {'resume_same_search','new_search','none','unclear'}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dir', default=os.path.dirname(os.path.abspath(__file__)))
    args = ap.parse_args()
    searches = load(os.path.join(args.dir, 'searches.jsonl'))
    findings = load(os.path.join(args.dir, 'findings.jsonl'))

    errors, warns = [], []
    def err(m): errors.append(m)
    def warn(m): warns.append(m)

    eng = {r['engagement_id']: r for r in searches if r.get('record_type')=='engagement'}
    srows = {r['search_id']: r for r in searches if r.get('record_type')=='search'}
    segs = {r['segment_id']: r for r in searches if r.get('record_type')=='segment'}
    claims = {r['claim_id']: r for r in findings}

    # --- identifier checks ---
    for name, table in (('engagement', eng), ('search', srows), ('segment', segs), ('claim', claims)):
        if len(table) == 0:
            err(f'no {name} rows found')
    for r in searches:
        if r.get('record_type') == 'search':
            if r['engagement_id'] not in eng:
                err(f"search {r['search_id']} references missing engagement {r['engagement_id']}")
            if r.get('operator') != 'JDP':
                err(f"search {r['search_id']} operator != JDP")
            if r.get('completed') is not True:
                warn(f"search {r['search_id']} is not marked completed")
        elif r.get('record_type') == 'segment':
            if r['search_id'] not in srows:
                err(f"segment {r['segment_id']} references missing search {r['search_id']}")
            if r['engagement_id'] not in eng:
                err(f"segment {r['segment_id']} references missing engagement {r['engagement_id']}")
            if r['termination_status'] not in TERMINATIONS:
                err(f"segment {r['segment_id']} bad termination {r['termination_status']}")
            if r['relationship_to_next'] not in RELATIONSHIPS:
                err(f"segment {r['segment_id']} bad relationship {r['relationship_to_next']}")
        elif r.get('record_type') == 'engagement':
            for sid in r.get('search_ids', []):
                if sid not in srows:
                    err(f"engagement {r['engagement_id']} lists missing search {sid}")
        else:
            err(f'unknown record_type in searches.jsonl: {r.get("record_type")}')

    for r in findings:
        if r.get('record_type') != 'finding':
            err(f"unexpected record_type in findings.jsonl: {r.get('record_type')}")
        if r['search_id'] not in srows:
            err(f"finding {r['claim_id']} references missing search {r['search_id']}")
        if r.get('engagement_id') not in eng:
            err(f"finding {r['claim_id']} references missing engagement {r.get('engagement_id')}")
        if r['disposition'] not in DISPOSITIONS:
            err(f"finding {r['claim_id']} bad disposition {r['disposition']}")
        if r.get('primary_family') is not None and r['primary_family'] not in FAMILIES:
            err(f"finding {r['claim_id']} bad primary_family {r['primary_family']}")
        for f in r.get('secondary_families') or []:
            if f not in FAMILIES:
                err(f"finding {r['claim_id']} bad secondary family {f}")
        dup = r.get('duplicate_of')
        if r['disposition'] == 'duplicate':
            if not dup:
                err(f"duplicate {r['claim_id']} without duplicate_of")
            elif dup not in claims:
                err(f"duplicate {r['claim_id']} target {dup} missing")
        if r['disposition'] == 'confirmed':
            if not r.get('composition'):
                err(f"confirmed {r['claim_id']} has no composition block")
            elif r['composition'].get('unintended_behavior_count') is None:
                err(f"confirmed {r['claim_id']} missing unintended_behavior_count")
        if r['disposition'] in ('invalid','unresolved'):
            if not (r.get('invalid_reason') or r.get('unresolved_reason')):
                err(f"{r['disposition']} {r['claim_id']} has no reason string")

    # --- finding_ids cross-check both directions ---
    by_search = collections.defaultdict(set)
    for r in findings:
        by_search[r['search_id']].add(r['claim_id'])
    for sid, sr in srows.items():
        declared = set(sr.get('finding_ids') or [])
        have = by_search.get(sid, set())
        if declared != have:
            err(f"search {sid} finding_ids mismatch: declared-only {sorted(declared-have)}, findings-only {sorted(have-declared)}")
        confirmed = {c for c in declared if claims.get(c, {}).get('disposition') == 'confirmed'}
        declared_confirmed = set(sr.get('confirmed_finding_ids') or [])
        if confirmed != declared_confirmed:
            err(f"search {sid} confirmed_finding_ids mismatch: {sorted(declared_confirmed ^ confirmed)}")

    # --- segment ordering and duration ---
    total = datetime.timedelta()
    per_search = {}
    for sid, sr in sorted(srows.items()):
        ss = [segs[i] for i in sr['segment_ids']]
        last_end = None
        d = datetime.timedelta()
        for s in ss:
            p = parse(s['prompt_timestamp']); e = parse(s['ended_at'])
            if p is None or e is None:
                err(f"segment {s['segment_id']} missing timestamps")
                continue
            if e <= p:
                err(f"segment {s['segment_id']} ends before it starts ({s['prompt_timestamp']} >= {s['ended_at']})")
            if last_end is not None and p < last_end:
                err(f"segment {s['segment_id']} starts before the previous segment ended")
            last_end = e
            d += (e - p)
        per_search[sid] = d
        total += d

    # --- finding bounds ordering ---
    for r in findings:
        b = r.get('first_identified_bounds')
        if b:
            nb, na = parse(b['not_before']), parse(b['not_after'])
            if nb and na and na < nb:
                err(f"finding {r['claim_id']} first_identified bounds inverted")

    # --- aggregates ---
    disp = collections.Counter(r['disposition'] for r in findings)
    fam = collections.Counter(r['primary_family'] for r in findings if r['disposition'] == 'confirmed')
    multi = [sr['search_id'] for sr in srows.values() if len(sr['segment_ids']) > 1]
    status = collections.Counter(
        'completed' if sr['completed'] else 'unclear' for sr in srows.values())
    censored = sum(1 for sr in srows.values() if not sr['completed'])
    resumed = len(multi)
    exact = sum(1 for sr in srows.values() if sr['reviewed_commit_confidence'] == 'exact')
    bounded = sum(1 for sr in srows.values() if sr['reviewed_commit_confidence'] == 'bounded')
    wtree = collections.Counter(sr['worktree_state'] for sr in srows.values())

    print('=' * 72)
    print('ADVERSARIAL YIELD INDEX - VALIDATION REPORT')
    print('=' * 72)
    print(f"engagements:              {len(eng)}")
    print(f"logical searches:         {len(srows)}")
    print(f"  single-segment:         {len(srows)-resumed}")
    print(f"  multi-segment (resumed):{resumed}")
    print(f"  completed:              {status.get('completed',0)}")
    print(f"  censored (never resumed):{censored}")
    print(f"  unclear:                {status.get('unclear',0)}")
    print(f"segments:                 {len(segs)}")
    print(f"claims:                   {len(claims)}")
    for k in ('confirmed','duplicate','invalid','unresolved'):
        print(f"  {k+':':24s}{disp.get(k,0)}")
    print('confirmed findings by primary family:')
    for k, v in fam.most_common():
        print(f"  {k:18s} {v}")
    print(f"reviewed commit exact:    {exact}  bounded: {bounded}  ({100*(exact+bounded)/len(srows):.0f}% exact-or-bounded)")
    print(f"worktree states:          {dict(wtree)}")
    print()
    print('derived durations (sum of segment intervals; outage gaps excluded):')
    dur = sorted(per_search.items(), key=lambda kv: kv[1], reverse=True)
    def fmt(t):
        s = int(t.total_seconds()); h, s = divmod(s, 3600); m, s = divmod(s, 60)
        return f'{h}h{m:02d}m{s:02d}s'
    for sid, d in dur[:10]:
        print(f'  {sid}  {fmt(d)}  ({srows[sid]["pass_label"]})')
    print(f'  ... total {fmt(total)} across {len(srows)} searches; median {fmt(sorted(per_search.values())[len(per_search)//2])}')
    print()
    if errors:
        print(f'ERRORS ({len(errors)}):')
        for e in errors:
            print('  -', e)
    if warns:
        print(f'WARNINGS ({len(warns)}):')
        for w in warns:
            print('  -', w)
    if not errors:
        print('VALIDATION OK (no errors)')
    return 1 if errors else 0

if __name__ == '__main__':
    sys.exit(main())
