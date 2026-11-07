"""Public builder staging rejects linked files without weakening frozen gate 2."""
from pathlib import Path
import sys
import hashlib
import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime'))
import firmware_builder as builder

DELTA={'/fpv/tuning.bin':('add','0'*64,3)}


def test_plain_source_is_copied_and_prior_output_is_preserved(tmp_path):
    root=tmp_path/'usrdata';(root/'fpv').mkdir(parents=True)
    (root/'fpv/tuning.bin').write_bytes(b'abc')
    staged=tmp_path/'staging'
    result=builder.stage_files('z40',DELTA,str(root),str(staged))
    assert Path(result[0]['file']).read_bytes()==b'abc'
    with pytest.raises(builder.BuilderError) as error:
        builder.stage_files('z40',DELTA,str(root),str(staged))
    assert error.value.code=='STAGING_DESTINATION_EXISTS'
    assert (staged/'tuning.bin').read_bytes()==b'abc'


@pytest.mark.parametrize('link_parent',[False,True])
def test_linked_source_file_or_directory_refuses_before_copy(tmp_path,link_parent):
    root=tmp_path/'usrdata';root.mkdir()
    outside=tmp_path/'outside';outside.mkdir();(outside/'tuning.bin').write_bytes(b'abc')
    if link_parent:(root/'fpv').symlink_to(outside,target_is_directory=True)
    else:
        (root/'fpv').mkdir();(root/'fpv/tuning.bin').symlink_to(outside/'tuning.bin')
    with pytest.raises(builder.BuilderError) as error:
        builder.stage_files('z40',DELTA,str(root),str(tmp_path/'stage'),copy=lambda *_:pytest.fail('must refuse before copy'))
    assert error.value.code=='STAGING_SOURCE_UNSAFE'
    assert not list((tmp_path/'stage').glob('*'))


def test_linked_staging_directory_refuses(tmp_path):
    root=tmp_path/'usrdata';(root/'fpv').mkdir(parents=True);(root/'fpv/tuning.bin').write_bytes(b'abc')
    outside=tmp_path/'outside';outside.mkdir();stage=tmp_path/'stage';stage.symlink_to(outside,target_is_directory=True)
    with pytest.raises(builder.BuilderError) as error:builder.stage_files('z40',DELTA,str(root),str(stage))
    assert error.value.code=='STAGING_SOURCE_UNSAFE' and not list(outside.iterdir())


@pytest.mark.parametrize('change',[None,'same-size-change','truncate'])
def test_disk_artifact_must_match_the_gate2_identity(tmp_path,change):
    data=b'independently verified bytes'
    image=tmp_path/'result.img';image.write_bytes(data)
    expected={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
    if change is None:
        assert builder._verified_image_identity(str(image),{'image':expected})==expected
    else:
        image.write_bytes(b'X'+data[1:] if change=='same-size-change' else data[:-1])
        with pytest.raises(builder.BuilderError) as error:
            builder._verified_image_identity(str(image),{'image':expected})
        assert error.value.code=='OUTPUT_IDENTITY_MISMATCH'


@pytest.mark.parametrize('report',[None,{}, {'image':[]},{'image':{'bytes':True,'sha256':'x'}}])
def test_malformed_verified_identity_cannot_offer_an_output(tmp_path,report):
    image=tmp_path/'result.img';image.write_bytes(b'not-qualified')
    with pytest.raises(builder.BuilderError):builder._verified_image_identity(str(image),report)
