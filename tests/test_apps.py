from disklens.apps import InstalledApp, analyze_application_storage, get_registry_installed_apps


def test_get_registry_installed_apps():
    apps = get_registry_installed_apps()
    assert isinstance(apps, list)
    for app in apps:
        assert isinstance(app, InstalledApp)
        assert app.name


def test_analyze_application_storage(db, tree):
    # Add a mock node_modules structure
    nm = tree / "node_modules" / "express"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text("console.log('express');")

    scan = db.scan(tree)
    result = analyze_application_storage(db, scan)
    assert result["scan_id"] == scan["id"]
    assert "inferred_environments" in result

    inferred_names = {env["name"] for env in result["inferred_environments"]}
    assert "Node.js / npm Environment" in inferred_names
