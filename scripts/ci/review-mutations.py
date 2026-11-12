#!/usr/bin/env python3
"""Kill review regressions in an isolated copy; compile errors never count as kills."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
root = Path(__file__).resolve().parents[2]
cases = [
    ('wide_abi', 'crates/shirusu-hook/src/engine_generated.inc',
     [('unsafe { original() }\n    })\n', '(unsafe { original() }) as u32 as u64\n    })\n')],
     'shirusu-hook', 'generated_abi', 'generated_abi_preserves_wide'),
    ('float_bits', 'crates/shirusu-hook/src/engine_generated.inc',
     [('a4.to_bits() as u64', 'a4 as u64')],
     'shirusu-hook', 'generated_abi', 'generated_abi_preserves_wide'),
    ('replay_offset', 'crates/shirusu-probe/src/replay.rs',
     [('if number(enter, "lpOverlapped")? != 0 {', 'if false {')],
     'shirusu-probe', 'replay', 'explicit_overlapped_offset'),
    ('uncaptured_evidence', 'crates/shirusu-test/src/eval.rs',
     [('if f.capture != ValueCapture::Captured {', 'if false {')],
     'shirusu-test', 'rules', 'uncaptured_dummy'),
    ('failed_close', 'crates/shirusu-test/src/eval.rs',
     [('if n != 0)', 'if n == 0)')],
     'shirusu-probe', 'review_regressions', 'failed_or_unfinished_close'),
    ('replay_initial_state', 'crates/shirusu-probe/src/replay.rs',
     [('(1, false) =>', '(1 | 3, false) =>')],
     'shirusu-probe', 'replay', 'missing_initial_state'),
    ('utf16', 'crates/shirusu-compare/src/normalize.rs',
     [('Err(_) => NormValue::Utf16(units.clone())', 'Err(_) => NormValue::Text(String::from_utf16_lossy(units))')],
     'shirusu-probe', 'review_regressions', 'utf16_distinct'),
    ('process', 'crates/shirusu-compare/src/normalize.rs',
     [('.entry((ev.session_id, ev.process_id, raw))', '.entry((0, 0, raw))'),
      ('productions.get(&(session, process, raw))', 'productions.get(&(0, 0, raw))')],
     'shirusu-probe', 'review_regressions', 'process_handle'),
    ('drain_order', 'crates/shirusu-compare/src/normalize.rs',
     [('order.then_with(|| a.index.cmp(&b.index))', 'a.index.cmp(&b.index)')],
     'shirusu-probe', 'review_regressions', 'drain_permutations'),
    ('trim', 'crates/shirusu-probe/src/trim.rs', [('&call.completed,', '')],
     'shirusu-probe', 'review_regressions', 'async_difference'),
    ('blob_count', 'crates/shirusu-trace/src/reader.rs',
     [('if !scan.blobs.contains_key(&update.new_version_id) {', 'if false {')],
     'shirusu-trace', 'review_limits', 'derived_blobs'),
    ('hex', 'crates/shirusu-trace/src/blob.rs',
     [(' || !s.bytes().all(|b| b.is_ascii_hexdigit())', '')],
     'shirusu-trace', 'review_limits', 'non_ascii_hex'),
    ('reuse', 'crates/shirusu-hook/src/capture.rs', [('p.call_id == call_id', 'p.call_id != 0')],
     'shirusu-hook', 'lifecycle_schedules', 'completion_before'),
]
with tempfile.TemporaryDirectory(prefix='shirusu-mutations-') as tmp:
    work = Path(tmp)
    for name in ('crates', 'e2e'):
        shutil.copytree(root/name, work/name)
    for name in ('Cargo.toml', 'Cargo.lock'):
        shutil.copy2(root/name, work/name)
    env = dict(os.environ, CARGO_TARGET_DIR=str(root/'target/review-mutations'))
    def run(package, test, name):
        return subprocess.run(['cargo','test','--offline','-p',package,'--test',test,name],
                              cwd=work,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    for label, file, replacements, package, test, name in cases:
        baseline=run(package,test,name)
        if baseline.returncode or '1 passed' not in baseline.stdout:
            raise RuntimeError('baseline failed: '+label+'\n'+baseline.stdout)
        path=work/file; original=path.read_text(); changed=original
        for old,new in replacements:
            if changed.count(old)!=1:
                raise RuntimeError(f'{label}: mutation must match exactly once: {old!r}')
            changed=changed.replace(old,new)
        path.write_text(changed)
        result=run(package,test,name)
        path.write_text(original)
        if result.returncode==0 or 'test result: FAILED' not in result.stdout:
            raise RuntimeError('survived or failed to compile: '+label+'\n'+result.stdout)
        print('KILLED '+label,flush=True)
