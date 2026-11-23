from disklens.drives import DriveInfo, get_available_drives, get_scannable_drives


def test_get_available_drives():
    drives = get_available_drives()
    assert isinstance(drives, list)
    assert len(drives) >= 1
    d = drives[0]
    assert isinstance(d, DriveInfo)
    assert d.path
    assert d.letter
    assert isinstance(d.is_ready, bool)


def test_scannable_drives():
    scannable = get_scannable_drives()
    assert isinstance(scannable, list)
    for d in scannable:
        assert d.is_ready
        assert d.is_suitable_for_scan
        assert d.total_bytes > 0
        assert 0.0 <= d.percent_used <= 100.0


def test_drive_info_to_dict():
    d = DriveInfo(
        path="C:\\",
        letter="C",
        drive_type="Fixed",
        label="OS",
        filesystem="NTFS",
        total_bytes=1000,
        used_bytes=600,
        free_bytes=400,
        percent_used=60.0,
        is_ready=True,
        is_suitable_for_scan=True,
    )
    data = d.to_dict()
    assert data["path"] == "C:\\"
    assert data["percent_used"] == 60.0
    assert data["is_suitable_for_scan"] is True
