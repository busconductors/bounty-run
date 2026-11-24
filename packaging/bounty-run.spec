# PyInstaller spec for the engine sidecar (--onedir; --onefile would unpack to a
# temp dir on every start). Build with `make engine`, which passes --specpath.
# SPECPATH is the directory holding this spec (packaging/), so the repo root is its parent.
import os

ROOT = os.path.dirname(os.path.abspath(SPECPATH))

a = Analysis(
    [os.path.join(ROOT, "bounty_run.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[
        # Read-only resources, resolved at runtime through runner.paths.resource().
        (os.path.join(ROOT, "assets"), "assets"),
        (os.path.join(ROOT, "runner", "vendor", "shcheck.py"), "runner/vendor"),
    ],
    # PySocks is imported lazily by requests/urllib3 only when a socks proxy is used.
    # shcheck.py ships as a data file, so PyInstaller never analyses its imports:
    # list the ones the engine itself does not already pull in.
    hiddenimports=["socks", "urllib3.contrib.socks", "optparse", "http.client", "ssl",
                   "urllib.request", "urllib.error", "urllib.parse"],
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "pytest", "ruff"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="bounty-run",
    console=True,
    upx=False,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    name="bounty-run",
    upx=False,
)
