"""HD Pro admission preserves exact inputs and never implies hardware evidence."""
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'runtime'))
import firmware_builder as builder


def test_hdpro_resources_and_canonical_filename():
    assert builder.camera_port_blocker('hdpro') is None
    assert builder.inspect_hdpro_assets() == ROOT / 'firmware/hdpro'
    assert builder.output_name('hdpro', '19.2.14') == 'Ascent_G_Sky_19_2_14_HDPro_1.img'
    for name in ('candidate.img', '../Ascent_G_Sky_19_2_14_HDPro_1.img', 'Ascent_G_Sky_19_2_14_HDPro_2.img'):
        with pytest.raises(builder.BuilderError):
            builder.check_output_name(name, 'hdpro')
    with pytest.raises(builder.BuilderError):
        builder.output_name('hdpro', '19.2.13')


def test_hdpro_refuses_wrong_donor_before_creating_work(tmp_path):
    spec = importlib.util.spec_from_file_location('hdpro_test_builder', ROOT / 'firmware/hdpro/hdpro_build.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    donor = tmp_path / 'donor.img'
    donor.write_bytes(b'wrong donor')
    work, image, report = (tmp_path / name for name in ('work', 'output.img', 'report.json'))
    with pytest.raises(ValueError, match='exact normal 19.2.14'):
        module.build(donor, ROOT / 'firmware/mode_a', tmp_path / 'helper', work, image, report)
    assert not work.exists() and not image.exists() and not report.exists()


def test_hdpro_failure_offers_no_image(tmp_path):
    def failed_runner(*args, **kwargs):
        import subprocess
        return subprocess.CompletedProcess(args[0], 1, '', 'build refused')

    result = builder.run_variant_build('hdpro', donor='donor.img', sources={},
        work_dir=str(tmp_path), out_name=builder.output_name('hdpro', '19.2.14'),
        builder_dir=str(ROOT / 'firmware/mode_a'), mkfs='helper', runner=failed_runner,
        wrap=lambda argv: argv)
    assert not result['ok'] and result['image'] is None
    assert result['hardware_qualified'] is False


def test_hdpro_asset_inventory_does_not_claim_hardware_qualification():
    doc = json.loads((ROOT / 'firmware/hdpro/assets.json').read_text())
    assert doc['hardware_qualified'] is False
    assert doc['build_availability'] == 'TESTING'
