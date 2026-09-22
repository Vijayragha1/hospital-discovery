"""Synthetic isolated PostgreSQL backup/restore drill using a preloaded bundle.

Never accepts an existing database or source. Creates a disposable --network=none
PostgreSQL container; its data and backup are in tmpfs / process memory. No ports
are published. This verifies catalog recovery, not hospital backup/key custody.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time


FIXTURE = r'''
import hashlib, json, os, sys
from datetime import timedelta
from sqlalchemy import select, func, text
from app import models as m
from app.db import initialize, session, engine
from app.security import encrypt, decrypt, stable_hash, hash_password
from app.comparison import compare_scans

def snapshot(db):
    old, new = db.get(m.Scan, 'baseline'), db.get(m.Scan, 'current')
    comparison = compare_scans(db, old, new)
    assert comparison['finding_summary'] == {'unchanged': 1}
    return {
        'comparison': comparison,
        'objects': [(o.id, o.object_key, o.fingerprint, o.location_encrypted, o.metadata_encrypted)
                    for o in db.scalars(select(m.ScanObject).where(m.ScanObject.scan_id.in_(['baseline', 'current'])).order_by(m.ScanObject.id))],
        'findings': [(f.id, f.review_status, f.reason_encrypted, f.segment_encrypted)
                     for f in db.scalars(select(m.Finding).where(m.Finding.scan_id.in_(['baseline', 'current'])).order_by(m.Finding.id))],
        'evidence': [(e.finding_id, e.payload_encrypted) for e in db.scalars(select(m.FindingEvidence).where(m.FindingEvidence.finding_id.in_(['finding-baseline', 'finding-current'])).order_by(m.FindingEvidence.finding_id))],
        'audit': db.get(m.Audit, 'review-history').detail_encrypted,
    }

def content(db, scan):
    location = '/synthetic/fixture.txt'
    obj = m.ScanObject(id='object-'+scan.id, scan_id=scan.id,
        object_key=stable_hash('synthetic-source:'+hashlib.sha256(location.encode()).hexdigest()),
        location_encrypted=encrypt(location), status='full', examined=50, unit='characters',
        fingerprint=stable_hash('synthetic-original-content'), metadata_encrypted=encrypt({}))
    db.add(obj); db.flush()
    finding = m.Finding(id='finding-'+scan.id, scan_id=scan.id, object_id=obj.id,
        entity_type='EMAIL_ADDRESS', classification='personal_data', confidence=.99, match_count=1,
        reason_encrypted=encrypt('synthetic pattern'), segment_encrypted=encrypt('record:1'), review_status='confirmed')
    db.add(finding); db.flush()
    db.add(m.FindingEvidence(finding_id=finding.id, payload_encrypted=encrypt({
        'examples': [{'value': 'fixture@example.invalid', 'excerpt': 'Synthetic fixture@example.invalid'}], 'truncated': False})))

action = sys.argv[1]
if action == 'seed':
    initialize()
    with session() as db:
        at = m.now()
        db.add(m.Policy(id=1, retention_days=3650, audit_retention_days=3650, retention_approved=False))
        user = m.User(id='restored-user', username='restored-user', role='admin', password_hash=hash_password(os.environ['DRILL_PASSWORD']))
        source = m.Source(id='synthetic-source', name_encrypted=encrypt('Synthetic recovery source'), kind='filesystem',
            config_encrypted=encrypt({'root':'/synthetic-never-mounted', 'password':'fictional-credential',
                                      'full_scan_allowed':True, 'workload_validation_note':'old synthetic approval'}),
            enabled=True, safety_validated=True)
        db.add_all([user, source]); db.flush()
        db.add(m.LoginSession(token_hash=stable_hash(os.environ['DRILL_SESSION']), user_id=user.id, expires_at=at+timedelta(days=1)))
        for name in ('baseline', 'current'):
            scan = m.Scan(id=name, source_id=source.id, status='completed', options={'capture_evidence':True},
                detector_version='synthetic/runtime-local-'+'a'*64, created_at=at-timedelta(days=1), finished_at=at,
                coverage={'full':1})
            db.add(scan); db.flush(); content(db, scan)
        for status in ('queued', 'running', 'paused', 'interrupted'):
            db.add(m.Scan(id='job-'+status, source_id=source.id, status=status, heartbeat_at=at))
        # More than two cleanup batches, including an expired cancellation lease.
        for index in range(205):
            scan = m.Scan(id='expired-'+str(index), source_id=source.id, status='cancelled' if index==0 else 'completed',
                created_at=at-timedelta(days=400), heartbeat_at=at if index==0 else None,
                error='retention_expired' if index==0 else None)
            db.add(scan); db.flush()
            if index == 0: content(db, scan)
            db.add(m.Audit(id='expired-audit-'+str(index), at=at-timedelta(days=400), actor='synthetic', action='fixture', detail_encrypted=encrypt({})))
        db.add(m.Audit(id='review-history', actor='synthetic-reviewer', action='finding_reviewed',
            detail_encrypted=encrypt({'finding_id':'finding-current','status':'confirmed'})))
        db.commit()
        print(json.dumps({'snapshot': snapshot(db), 'scan_count':db.scalar(select(func.count()).select_from(m.Scan))}))
elif action == 'snapshot':
    with session() as db:
        print(json.dumps({'snapshot': snapshot(db), 'scan_count':db.scalar(select(func.count()).select_from(m.Scan)),
            'sessions':db.scalar(select(func.count()).select_from(m.LoginSession)),
            'source_enabled':db.get(m.Source,'synthetic-source').enabled,
            'user_active':db.get(m.User,'restored-user').active}))
elif action == 'verify':
    with session() as db:
        assert set(db.scalars(select(m.Scan.id))) == {
            'baseline', 'current', 'job-queued', 'job-running', 'job-paused', 'job-interrupted'}
        assert db.scalar(select(func.count()).select_from(m.LoginSession)) == 0
        assert not db.get(m.User,'restored-user').active
        source = db.get(m.Source,'synthetic-source')
        assert not source.enabled and not source.safety_validated
        config = decrypt(source.config_encrypted)
        assert config['password']=='fictional-credential'
        assert not config.get('full_scan_allowed') and not config.get('workload_validation_note')
        for job in db.scalars(select(m.Scan).where(m.Scan.id.like('job-%'))):
            assert job.status=='cancelled' and job.heartbeat_at is None
        assert not db.scalar(select(m.Scan.id).where(m.Scan.heartbeat_at.is_not(None)))
        assert db.scalar(select(func.count()).select_from(m.ScanObject)) == 2
        assert db.scalar(select(func.count()).select_from(m.Finding)) == 2
        assert db.scalar(select(func.count()).select_from(m.FindingEvidence)) == 2
        assert not db.scalar(select(m.Audit.id).where(m.Audit.id.like('expired-audit-%')))
        policy = db.get(m.Policy,1)
        assert policy.retention_approved and policy.retention_days==30 and policy.audit_retention_days==90
        assert decrypt(db.get(m.FindingEvidence,'finding-current').payload_encrypted)['examples'][0]['value']=='fixture@example.invalid'
        for action_name in ('restored_catalog_quarantined','restored_catalog_prepared','retention_purge'):
            assert db.scalar(select(m.Audit.id).where(m.Audit.action==action_name))
        print(json.dumps({'snapshot':snapshot(db),'checks':[
            'expired_scans_removed_across_batches','expired_objects_findings_evidence_cascaded',
            'expired_audits_removed_across_batches','expired_heartbeat_marker_removed','sessions_revoked',
            'restored_users_disabled','sources_disabled_and_revalidation_required','workload_approvals_revoked',
            'source_credentials_preserved_encrypted','four_resumable_job_states_cancelled','all_heartbeats_cleared',
            'explicit_current_retention_applied','evidence_decrypts','recovery_audited']}))
elif action == 'auth':
    from fastapi.testclient import TestClient
    from app.main import app
    headers={'x-requested-with':'SentryDiscovery'}
    with TestClient(app, base_url='https://testserver') as client:
        client.cookies.set('sentry_session',os.environ['DRILL_SESSION'])
        assert client.get('/api/auth/me').status_code==401
        assert client.post('/api/auth/login',headers=headers,json={'username':'restored-user','password':os.environ['DRILL_PASSWORD']}).status_code==401
        assert client.post('/api/auth/login',headers=headers,json={'username':'recovery-admin','password':os.environ['DRILL_PASSWORD']}).status_code==200
        rows=client.get('/api/findings').json()
        assert len(rows)==2 and all(row['review_status']=='confirmed' for row in rows)
        evidence=client.get('/api/findings/finding-current/evidence').json()
        assert evidence['examples'][0]['value']=='fixture@example.invalid'
        result=client.get('/api/compare?baseline=baseline&current=current').json()
        assert result['finding_summary']=={'unchanged':1}
    print(json.dumps({'checks':['old_cookie_rejected','old_password_account_rejected','fresh_cli_admin_login',
        'restored_reviewed_findings_api','restored_evidence_api','restored_comparison_api']}))
'''


def run(*args, input=None, allow_failure=False):
    result = subprocess.run(args, input=input, capture_output=True, timeout=180)
    if result.returncode and not allow_failure:
        # Avoid echoing commands, environment, SQL or fixture content on failure.
        raise RuntimeError('Synthetic recovery subprocess failed: ' + args[0])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    records = json.loads((args.bundle/'images.lock.json').read_text())
    release = json.loads((args.bundle/'release.json').read_text())
    platform = release['platform']
    checks = []
    for name in ('api','postgres'):
        actual = json.loads(run('docker','image','inspect','--platform',platform,records[name]['name']).stdout)[0]
        assert actual['Id']==records[name]['id'], 'Preloaded image differs from bundle lock'
    checks.append('preloaded_image_ids_match_bundle')
    name = 'discovery-recovery-' + secrets.token_hex(6)
    # cryptography is available in the shipped runtime; generate a valid Fernet
    # key locally without adding a host dependency.
    import base64
    values = {'POSTGRES_PASSWORD':secrets.token_urlsafe(32), 'POSTGRES_USER':'drill', 'POSTGRES_DB':'origin',
        'APP_SECRET_KEY':base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
        'SESSION_SECRET':secrets.token_urlsafe(48), 'DRILL_PASSWORD':secrets.token_urlsafe(24),
        'DRILL_SESSION':secrets.token_urlsafe(48), 'ENVIRONMENT':'production', 'DETECTOR_MODE':'presidio',
        'SECURE_COOKIES':'true', 'SOURCE_ALLOWED_ROOTS':'[]'}
    started = False
    with tempfile.TemporaryDirectory(prefix='discovery-recovery-') as temporary:
        env_path = Path(temporary)/'synthetic.env'
        def env(database, wrong=None):
            current = dict(values)
            current['DATABASE_URL']='postgresql+psycopg://drill:'+values['POSTGRES_PASSWORD']+'@127.0.0.1:5432/'+database
            if wrong: current[wrong]=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
            fd=os.open(env_path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
            with os.fdopen(fd,'w') as stream:
                stream.write(''.join(key+'='+value+'\n' for key,value in current.items()))
        def app(*command, input=None, allow_failure=False):
            return run('docker','run','--rm','-i','--platform',platform,'--pull=never',
                '--network','container:'+name,'--read-only','--cap-drop=ALL','--security-opt','no-new-privileges',
                '--memory','3g','--pids-limit','128','--tmpfs','/tmp:rw,noexec,nosuid,size=128m',
                '--env-file',str(env_path),'--entrypoint','python',records['api']['name'],
                *command,input=input,allow_failure=allow_failure)
        def fixture(action):
            return json.loads(app('-c',FIXTURE,action).stdout)
        prepare=('-m','app.cli','prepare-restored-catalog','--retention-days','30',
            '--audit-retention-days','90','--confirm-isolated-restore')
        try:
            env('origin')
            run('docker','run','-d','--name',name,'--platform',platform,'--pull=never',
                '--network=none','--read-only','--user','70:70','--cap-drop=ALL','--security-opt','no-new-privileges',
                '--memory','512m','--pids-limit','128','--tmpfs','/var/lib/postgresql/data:rw,nosuid,uid=70,gid=70,size=256m',
                '--tmpfs','/var/run/postgresql:rw,nosuid,uid=70,gid=70,size=16m',
                '--tmpfs','/tmp:rw,noexec,nosuid,size=64m','--env-file',str(env_path),records['postgres']['name'])
            started=True
            deadline=time.monotonic()+45
            while run('docker','exec',name,'pg_isready','-U','drill','-d','origin',allow_failure=True).returncode:
                if time.monotonic()>deadline: raise RuntimeError('Synthetic PostgreSQL startup timed out')
                time.sleep(.25)
            state=json.loads(run('docker','inspect',name).stdout)[0]
            assert state['HostConfig']['NetworkMode']=='none' and not state['HostConfig']['PortBindings']
            checks.append('no_external_network_or_published_ports')
            origin=fixture('seed')
            assert origin['scan_count']==211
            dump=run('docker','exec',name,'pg_dump','-U','drill','-d','origin','-Fc').stdout
            assert dump.startswith(b'PGDMP')
            run('docker','exec',name,'createdb','-U','drill','restored')
            run('docker','exec','-i',name,'pg_restore','-U','drill','-d','restored','--exit-on-error','--single-transaction',input=dump)
            env('restored')
            initial=fixture('snapshot')
            assert initial['snapshot']==origin['snapshot'] and initial['scan_count']==211
            checks.extend(['custom_format_pg_dump_and_pg_restore','restored_ciphertexts_ids_reviews_comparison_equal'])
            for wrong in ('APP_SECRET_KEY','SESSION_SECRET'):
                env('restored',wrong)
                rejected=app(*prepare,allow_failure=True)
                assert rejected.returncode != 0 and b'Restore preparation failed (' in rejected.stderr
                env('restored')
                assert fixture('snapshot')==initial
                checks.append(wrong.lower()+'_mismatch_rejected_before_mutation')
            prepared=json.loads(app(*prepare).stdout)
            assert prepared['retention_passes']>=3 and prepared['object_identity_key_verified']
            verified=fixture('verify')
            assert verified['snapshot']==origin['snapshot']
            checks.extend(verified['checks'])
            checks.append('surviving_ciphertexts_ids_reviews_comparison_preserved_after_preparation')
            # A one-shot actual worker must find no queued job to execute.
            app('-m','app.worker','--once')
            assert fixture('verify')['snapshot']==origin['snapshot']
            checks.append('actual_worker_once_does_not_resume_restored_jobs')
            app('-m','app.cli','init-admin','--username','recovery-admin',
                input=(values['DRILL_PASSWORD']+'\n') .encode()*2)
            checks.extend(fixture('auth')['checks'])
            # The original backup remains unchanged; preparation touched restored only.
            env('origin')
            original=fixture('snapshot')
            assert original['snapshot']==origin['snapshot'] and original['scan_count']==211
            assert original['sessions']==1 and original['source_enabled'] and original['user_active']
            checks.append('original_database_untouched')
            run('docker','exec',name,'createdb','-U','drill','corrupt_restore')
            corrupt=run('docker','exec','-i',name,'pg_restore','-U','drill','-d','corrupt_restore',
                '--exit-on-error','--single-transaction',input=dump[:80],allow_failure=True)
            assert corrupt.returncode != 0
            checks.append('truncated_dump_restore_rejected')
            del dump
        finally:
            if started: run('docker','rm','-f',name)
    report={'completed_utc':datetime.now(timezone.utc).isoformat(),'release':release['version'],
        'runtime_identity':release['runtime_identity'],'image_ids':{key:records[key]['id'] for key in ('api','postgres')},
        'synthetic_only':True,'hospital_acceptance':False,'status':'passed','check_count':len(checks),'checks':checks,
        'retention_passes':prepared['retention_passes'],'temporary_container_removed':True,
        'limitations':['No hospital backup, keys or source used.','Does not attest host disk encryption, backup encryption, key escrow or site isolation.',
                       'Same-release schema only; no cross-version migration tested.','HTTP checks use in-process ASGI with an HTTPS base URL; no ingress/TLS stack is exercised.']}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':'passed','check_count':len(checks),'release':release['version']}))


if __name__=='__main__':
    main()
