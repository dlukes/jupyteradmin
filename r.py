from pathlib import Path


def set_version(username, version):
    version = "" if version == "default" else version
    settings_path = Path("/home") / username / ".rstudio" / "rversion-settings" / "defaultRVersion"
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(version)

