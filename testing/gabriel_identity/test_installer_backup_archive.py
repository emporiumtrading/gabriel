"""Installer backup acceptance applies the restore archive bounds before success."""
import io
from pathlib import Path
import sys
import tarfile

import pytest

sys.path.insert(0,str(Path(__file__).parents[2]/'tooling'/'scripts'))
from gabriel_install import validate_backup_files


def backup(directory,entries):
    (directory/'database.dump').write_bytes(b'postgres-custom-dump')
    with tarfile.open(directory/'evidence.tar.gz','w:gz') as archive:
        for name,size in entries:
            member=tarfile.TarInfo(name);member.size=size
            archive.addfile(member,io.BytesIO(b'x'*size))


def test_backup_archive_accepts_the_restore_schema(tmp_path):
    backup(tmp_path,[('./'+'a'*32+'.gbe',29)])
    assert validate_backup_files(tmp_path)=={'evidence_objects':1,'expanded_bytes':29}


@pytest.mark.parametrize('entries',[
    [('../outside',32)],
    [('./'+'a'*32+'.gbe',28)],
    [('./'+'a'*32+'.gbe',32),('./'+'a'*32+'.gbe',32)],
])
def test_backup_archive_rejects_invalid_members_before_success(tmp_path,entries):
    backup(tmp_path,entries)
    with pytest.raises(ValueError): validate_backup_files(tmp_path)
