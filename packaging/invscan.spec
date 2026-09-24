# Native, onedir release. Keep the complete directory beside the executable.
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, copy_metadata

root = Path(SPECPATH).parent
datas = collect_data_files("ai_security_scan", include_py_files=True)
datas += collect_data_files("reportlab")
datas += collect_data_files("certifi")
datas += copy_metadata("headroom-ai")
datas += copy_metadata("reportlab")
datas += copy_metadata("pypdf")

a = Analysis(
    [str(root / "packaging" / "entry.py")],
    pathex=[str(root), str(root / "packaging")],
    binaries=[], datas=datas,
    hiddenimports=["headroom.transforms.content_router", "reportlab.pdfbase._fontdata", "pypdf"],
    hookspath=[], hooksconfig={}, runtime_hooks=[],
    # The scanner never uses interactive GUI components or ML model runtimes.
    excludes=["tkinter", "matplotlib", "torch", "tensorflow", "IPython"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [('X utf8', None, 'OPTION')], exclude_binaries=True, name="invscan",
          debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
          console=True, disable_windowed_traceback=False, argv_emulation=False,
          target_arch=None, codesign_identity=None, entitlements_file=None)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="invscan")
