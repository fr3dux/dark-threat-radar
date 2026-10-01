from pathlib import Path

from scripts.apply_update import relocate_virtualenv


def test_relocate_virtualenv_repairs_launchers_and_activation_files(tmp_path: Path):
    staged = tmp_path / ".update-venv-123"
    active = tmp_path / "venv"
    bin_path = active / "bin"
    bin_path.mkdir(parents=True)

    launcher = bin_path / "pytest"
    launcher.write_text(f"#!{staged}/bin/python\nprint('ok')\n", encoding="utf-8")
    launcher.chmod(0o755)
    activate = bin_path / "activate"
    activate.write_text(f'VIRTUAL_ENV="{staged}"\n', encoding="utf-8")
    binary = bin_path / "binary"
    binary.write_bytes(b"\x00" + str(staged).encode("utf-8"))

    relocate_virtualenv(active, staged)

    assert launcher.read_text(encoding="utf-8").startswith(f"#!{active}/bin/python")
    assert str(active) in activate.read_text(encoding="utf-8")
    assert str(staged) not in activate.read_text(encoding="utf-8")
    assert launcher.stat().st_mode & 0o111
    assert binary.read_bytes().startswith(b"\x00")
