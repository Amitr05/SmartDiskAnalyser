from disklens.visualization import (
    classify_category,
    format_bytes,
    get_category_summary,
    render_bar,
    render_html_report,
)


def test_format_bytes():
    assert format_bytes(0) == "0 B"
    assert format_bytes(500) == "500 B"
    assert format_bytes(1024) == "1.0 KB"
    assert format_bytes(1024 * 1024) == "1.0 MB"
    assert format_bytes(1024 * 1024 * 1024 * 2.5) == "2.5 GB"
    assert format_bytes(None) == "0 B"
    assert format_bytes(-10) == "0 B"


def test_render_bar():
    bar_0 = render_bar(0, 100, width=10)
    assert bar_0 == "[░░░░░░░░░░] 0.0%"
    bar_50 = render_bar(50, 100, width=10)
    assert bar_50 == "[█████░░░░░] 50.0%"
    bar_100 = render_bar(100, 100, width=10)
    assert bar_100 == "[██████████] 100.0%"
    # Edge case: zero total
    assert render_bar(10, 0, width=10) == "[░░░░░░░░░░] 0.0%"


def test_classify_category():
    assert classify_category(".docx", "C:/Users/User/Documents/file.docx") == "Documents"
    assert classify_category(".png", "C:/Users/User/Pictures/photo.png") == "Images"
    assert classify_category(".mp4", "C:/Users/User/Videos/movie.mp4") == "Videos"
    assert classify_category(".mp3", "C:/Users/User/Music/song.mp3") == "Audio"
    assert classify_category(".exe", "C:/Program Files/App/app.exe") == "Applications"
    assert classify_category(".py", "C:/Projects/app/main.py") == "Development"
    assert classify_category(".zip", "C:/Users/User/Downloads/archive.zip") == "Archives"
    assert classify_category(".tmp", "C:/Users/User/AppData/Local/Temp/tmp.tmp") == "Temporary"
    # Path-based overrides
    assert classify_category(".dll", "C:/Windows/System32/kernel32.dll") == "System"
    assert classify_category(".txt", "C:/Projects/node_modules/lib/README.txt") == "Development"


def test_get_category_summary(db, tree):
    scan = db.scan(tree)
    categories = get_category_summary(db, scan["id"])
    assert isinstance(categories, list)
    cat_names = {c["category"] for c in categories}
    assert "Documents" in cat_names or "Temporary" in cat_names
    for cat in categories:
        assert cat["files"] > 0
        assert cat["bytes"] > 0
        assert 0.0 <= cat["percent"] <= 100.0


def test_render_html_report():
    data = {
        "scan": {
            "root": "C:\\Test",
            "file_count": 42,
            "unique_bytes": 1048576,
            "status": "complete",
            "elapsed": 1.25,
        },
        "categories": [
            {"category": "Documents", "files": 10, "bytes": 500000, "percent": 50.0},
            {"category": "Images", "files": 5, "bytes": 500000, "percent": 50.0},
        ],
        "largest_files": [{"path": "C:\\Test\\doc.pdf", "size": 500000, "extension": ".pdf"}],
    }
    html_text = render_html_report(data)
    assert "<!doctype html>" in html_text
    assert "DiskLens" in html_text
    assert "C:\\Test" in html_text
    assert "Documents" in html_text
    assert "doc.pdf" in html_text
