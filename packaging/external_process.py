"""Keep bundled libraries out of explicitly launched vendor/runtime processes.

Only the two scanner modules that launch external executables receive a facade.
The standard-library subprocess module and the parent environment are unchanged.
See https://pyinstaller.org/en/stable/common-issues-and-pitfalls.html
"""
import os
from pathlib import Path
import subprocess
import sys
import threading

_DLL_LOCK = threading.RLock()


def clean_child_environment(environment, bundle_root, injected_ca_file=None):
    """Copy an existing allowlisted environment, removing bundled loader paths."""
    result = dict(os.environ if environment is None else environment)
    # Remove only the exact default injected for the frozen scanner. Preserve
    # all preexisting or subsequently changed user trust-store settings.
    if injected_ca_file and result.get("SSL_CERT_FILE") == injected_ca_file:
        result.pop("SSL_CERT_FILE")
    if "LD_LIBRARY_PATH_ORIG" in result:
        result["LD_LIBRARY_PATH"] = result.pop("LD_LIBRARY_PATH_ORIG")
        if not result["LD_LIBRARY_PATH"]:
            result.pop("LD_LIBRARY_PATH")
    root = Path(bundle_root).resolve()
    for key in ("LD_LIBRARY_PATH", "LIBPATH", "DYLD_LIBRARY_PATH", "PATH"):
        if key not in result:
            continue
        retained = []
        for part in result[key].split(os.pathsep):
            try:
                inside = part and Path(part).resolve().is_relative_to(root)
            except (OSError, ValueError, RuntimeError):
                inside = False
            if not inside:
                retained.append(part)
        if retained:
            result[key] = os.pathsep.join(retained)
        else:
            result.pop(key, None)
    return result


class ExternalSubprocess:
    def __init__(self, bundle_root, module=subprocess, windows_dll=None, injected_ca_file=None):
        self._bundle_root = str(bundle_root)
        self._module = module
        self._windows_dll = windows_dll
        self._injected_ca_file = injected_ca_file

    def __getattr__(self, name):
        return getattr(self._module, name)

    def Popen(self, *args, **kwargs):
        # Existing call sites use keyword env; reject positional env rather than
        # accidentally allowing two independently supplied environments.
        if len(args) > 10:
            raise TypeError("External process environment must be a keyword argument")
        kwargs["env"] = clean_child_environment(kwargs.get("env"), self._bundle_root, self._injected_ca_file)
        if self._windows_dll is None:
            return self._module.Popen(*args, **kwargs)
        with _DLL_LOCK:
            if not self._windows_dll(None):
                raise OSError("Could not reset external DLL search path")
            try:
                return self._module.Popen(*args, **kwargs)
            finally:
                if not self._windows_dll(self._bundle_root):
                    raise OSError("Could not restore bundled DLL search path")


def install_external_process_boundary(injected_ca_file=None):
    if not getattr(sys, "frozen", False):
        return
    windows_dll = None
    if os.name == "nt":
        import ctypes
        windows_dll = ctypes.windll.kernel32.SetDllDirectoryW
        windows_dll.argtypes = [ctypes.c_wchar_p]
        windows_dll.restype = ctypes.c_int
    facade = ExternalSubprocess(sys._MEIPASS, windows_dll=windows_dll, injected_ca_file=injected_ca_file)
    from ai_security_scan import cli_judge, image_runtime
    cli_judge.subprocess = facade
    image_runtime.subprocess = facade
