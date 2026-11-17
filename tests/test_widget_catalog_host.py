"""Trusted fixed-folder scans, bounded coalescing and stale-result invalidation."""
import json
from threading import Event
import time

import pytest
from ascent_core.widget_catalog import _result
from ascent_core.widget_catalog_host import CatalogCoordinator


def wait_done(manager):
    end=time.monotonic()+2
    while manager.document()['scan_in_progress'] and time.monotonic()<end:
        time.sleep(.005)
    return manager.document()


def test_construction_does_not_scan_create_or_publish_a_folder(tmp_path):
    folder=tmp_path/'Widgets'
    manager=CatalogCoordinator(folder,scanner=lambda p:pytest.fail('not requested'))
    assert manager.folder==folder and not folder.exists()
    assert manager.document()['phase']=='NOT_STARTED'
    assert str(folder) not in json.dumps(manager.document())
    manager.close()


def test_actual_missing_folder_is_observed_without_installation_or_creation(tmp_path):
    folder=tmp_path/'missing';manager=CatalogCoordinator(folder)
    manager.request_scan();doc=wait_done(manager)
    assert doc['phase']=='COMPLETE' and doc['result']['status']=='FOLDER_MISSING'
    assert not folder.exists() and doc['observed_at']
    assert not doc['registration_performed'] and not doc['installation_checked']
    manager.close()


def test_queued_rescans_coalesce_and_never_publish_the_old_generation(tmp_path):
    entered=Event();release=Event();second=Event();finish=Event();calls=[]
    def scan(path):
        calls.append(path)
        if len(calls)==1:
            entered.set();assert release.wait(2)
        else:
            second.set();assert finish.wait(2)
        return _result('OK')
    manager=CatalogCoordinator(tmp_path,scanner=scan)
    try:
        manager.request_scan();assert entered.wait(1)
        for _ in range(100):manager.request_scan()
        assert manager.document()['rescan_queued']
        release.set();assert second.wait(1)
        assert manager.document()['result'] is None
        finish.set();doc=wait_done(manager)
        assert calls==[tmp_path,tmp_path] and doc['generation']==101
        assert doc['phase']=='COMPLETE' and doc['result']['complete']
    finally:
        release.set();finish.set();manager.close()


def test_close_invalidates_an_inflight_result_without_claiming_to_cancel_io(tmp_path):
    entered=Event();release=Event()
    def scan(path):entered.set();release.wait(2);return _result('OK')
    manager=CatalogCoordinator(tmp_path,scanner=scan)
    manager.request_scan();assert entered.wait(1)
    manager.close();doc=manager.document()
    assert doc['phase']=='CLOSED' and doc['scan_in_progress'] and doc['result'] is None
    generation=doc['generation'];manager.request_scan()
    assert manager.document()['generation']==generation
    release.set();assert wait_done(manager)['phase']=='CLOSED'
    assert manager.document()['result'] is None


def test_delayed_scan_is_not_a_terminal_failure_and_status_reads_do_not_wait(tmp_path):
    entered=Event();release=Event();clock=[0]
    def scan(path):entered.set();release.wait(2);return _result('OK')
    manager=CatalogCoordinator(tmp_path,scanner=scan,clock=lambda:clock[0])
    try:
        manager.request_scan();assert entered.wait(1);clock[0]=6
        doc=manager.document()
        assert doc['phase']=='SCAN_DELAYED' and doc['result'] is None
        release.set();assert wait_done(manager)['phase']=='COMPLETE'
    finally:release.set();manager.close()


@pytest.mark.parametrize('kind',['exception','bad-shape','mutating','large','object'])
def test_failed_or_unbounded_results_cannot_be_published_or_echo_errors(tmp_path,kind):
    def scan(path):
        if kind=='exception':raise RuntimeError('synthetic-private-error')
        if kind=='bad-shape':return {'folder':str(tmp_path)}
        report=_result('OK')
        if kind=='mutating':report['registration_performed']=True
        elif kind=='large':report['entries']=['x'*(300*1024)]
        elif kind=='object':report['entries']=[object()]
        return report
    manager=CatalogCoordinator(tmp_path,scanner=scan)
    manager.request_scan();doc=wait_done(manager)
    assert doc['phase']=='FAILED' and doc['result'] is None
    assert doc['error']=='CATALOG_SCAN_FAILED'
    assert str(tmp_path) not in json.dumps(doc) and 'synthetic-private-error' not in json.dumps(doc)
    manager.close()


def test_status_is_a_copy_and_rescan_invalidates_prior_observation(tmp_path):
    manager=CatalogCoordinator(tmp_path,scanner=lambda p:_result('OK'))
    manager.request_scan();first=wait_done(manager)
    first['result']['entries'].append('not owned')
    assert manager.document()['result']['entries']==[]
    generation=manager.document()['generation'];manager.request_scan();last=wait_done(manager)
    assert last['generation']==generation+1 and last['result']['entries']==[]
    manager.close()


def test_worker_start_failure_is_visible_and_retryable(tmp_path, monkeypatch):
    import ascent_core.widget_catalog_host as host
    original = host.Thread
    class RefusedThread:
        def __init__(self, **kwargs):
            pass
        def start(self):
            raise RuntimeError('synthetic-start-error')
    monkeypatch.setattr(host, 'Thread', RefusedThread)
    manager = CatalogCoordinator(tmp_path, scanner=lambda p: _result('OK'))
    failed = manager.request_scan()
    assert failed['phase'] == 'FAILED' and not failed['scan_in_progress']
    assert failed['error'] == 'CATALOG_SCAN_START_FAILED'
    assert 'synthetic-start-error' not in json.dumps(failed)
    monkeypatch.setattr(host, 'Thread', original)
    manager.request_scan()
    recovered = wait_done(manager)
    assert recovered['phase'] == 'COMPLETE' and recovered['error'] is None
    manager.close()


def test_failure_from_obsolete_scan_is_discarded(tmp_path):
    entered = Event()
    release = Event()
    calls = []
    def scan(path):
        calls.append(path)
        if len(calls) == 1:
            entered.set()
            assert release.wait(2)
            raise ValueError('obsolete failure')
        return _result('OK')
    manager = CatalogCoordinator(tmp_path, scanner=scan)
    try:
        manager.request_scan()
        assert entered.wait(1)
        manager.request_scan()
        release.set()
        doc = wait_done(manager)
        assert len(calls) == 2 and doc['generation'] == 2
        assert doc['phase'] == 'COMPLETE' and doc['error'] is None
    finally:
        release.set()
        manager.close()
