#!/usr/bin/env python3
"""Build one native, standalone invscan archive in a fresh work directory.

Install the pinned requirements-release.txt and the project first. Run this on
the target OS/architecture; PyInstaller is not a cross compiler. Build manifests
record build inputs and hashes, not a claim of byte-for-byte reproducible output.
"""
from __future__ import annotations

import argparse
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {"pyinstaller": "6.22.3", "headroom-ai": "0.37.0",
            "reportlab": "4.5.1", "pypdf": "6.19.0"}
# Explicit allowlist: local credentials, extra fixtures, generated reports and
# other untracked files in an examples directory must never enter a release.
EXAMPLE_FILES = (
    "vulnerable/agent.py", "vulnerable/mcp.json", "vulnerable/Dockerfile",
    "safer/agent.py", "safer/mcp.json", "skills/README.md",
    "skills/risky/SKILL.md", "skills/risky/tools.json", "investigation/README.md",
    "investigation/context-tools/agent.py", "investigation/context-tools/delivery.py",
    "images/README.md", "images/demo-agent.tar", "review-config.json",
    "judges/codex-cli.json", "judges/claude-cli.json", "judges/grok-cli.json",
    "judges/gemini.json", "judges/openai-responses.json", "judges/ollama.json",
    "judges/openai-compatible.json", "judges/azure-style.json",
    "judges/anthropic.json", "judges/custom-gateway.json",
)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def platform_tag(system=None, machine=None):
    system = system or platform.system()
    machine = (machine or platform.machine()).lower()
    names = {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}
    arches = {"x86_64": "x86_64", "amd64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}
    if system not in names or machine not in arches:
        raise ValueError("Standalone releases support Linux/macOS x86_64 or arm64, and Windows x86_64")
    os_name, arch = names[system], arches[machine]
    if os_name == "windows" and arch != "x86_64":
        raise ValueError("Windows standalone releases currently require x86_64")
    return os_name, arch


def archive_name(version, os_name, arch):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[a-zA-Z0-9.+-]*)", version):
        raise ValueError("Invalid release version")
    return f"invscan-{version}-{os_name}-{arch}" + (".zip" if os_name == "windows" else ".tar.gz")


def portable_sorted(paths, root):
    # WindowsPath's native comparison folds case; release provenance must use
    # identical ordering for the same source bytes on every build platform.
    return sorted(paths, key=lambda path: path.relative_to(root).as_posix())


def file_inventory(directory):
    items = []
    for path in portable_sorted(directory.rglob("*"), directory):
        relative = path.relative_to(directory).as_posix()
        if path.is_symlink():
            # PyInstaller uses relative intra-bundle links on Linux and macOS.
            target = os.readlink(path)
            if Path(target).is_absolute() or not path.resolve().is_relative_to(directory.resolve()):
                raise ValueError(f"Bundle link escapes distribution: {relative}")
            items.append({"path": relative, "symlink": target})
        elif path.is_file():
            items.append({"path": relative, "size": path.stat().st_size, "sha256": sha256(path)})
    return items


def git_state():
    def git(*args):
        result = subprocess.run(["git", *args], cwd=ROOT, text=True, capture_output=True, check=True)
        return result.stdout.strip()
    try:
        return {"commit": git("rev-parse", "HEAD"),
                "dirty": bool(git("status", "--porcelain")),
                "repository": "https://github.com/nimeshbuilds/invarune"}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": None, "dirty": None,
                "repository": "https://github.com/nimeshbuilds/invarune"}


def source_inventory():
    files = [ROOT / "pyproject.toml", ROOT / "requirements-release.txt",
             ROOT / "scripts" / "build_standalone.py", ROOT / "NOTICE.md"]
    files += list((ROOT / "ai_security_scan").glob("*.py"))
    files += list((ROOT / "ai_security_scan" / "data").glob("*.json"))
    files += [p for p in (ROOT / "packaging").rglob("*")
              if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"]
    files += [ROOT / "examples" / example for example in EXAMPLE_FILES]
    return [{"path": p.relative_to(ROOT).as_posix(), "sha256": sha256(p)}
            for p in portable_sorted(set(files), ROOT) if p.is_file() and "__pycache__" not in p.parts]


def write_notices(distribution):
    """Retain wheel-supplied licenses, with metadata when no license file exists.

    The inventory deliberately includes build-only dependencies too, rather than
    misrepresenting the environment's installed set as a precise runtime SBOM.
    Direct-url metadata and installation paths are never copied into notices.
    """
    license_root = distribution / "LICENSES"
    license_root.mkdir()
    dependencies, seen = [], set()
    notices = ["# Third-party notices\n", "This native distribution embeds an unmodified CPython runtime and selected dependency modules. "
               "The inventory below covers the complete build environment, including tools whose code may not be shipped. "
               "It is a provenance inventory, not a vulnerability scan or a complete native-library SBOM.\n",
               "Available wheel license/notice files are retained under LICENSES. Package metadata supplies the declared license where a wheel has no standalone license file. "
               "No third-party package or license is modified.\n"]
    for dist in sorted(metadata.distributions(), key=lambda d: d.metadata.get("Name", "").lower()):
        name = dist.metadata.get("Name", "unknown")
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        if normalized in seen or normalized == "agent-mcp-security-scan":
            continue
        seen.add(normalized)
        destination = license_root / f"{normalized}-{dist.version}"
        destination.mkdir()
        licenses = []
        for item in dist.files or []:
            parts = Path(str(item)).parts
            if any(p == ".." for p in parts):
                continue
            basename = Path(str(item)).name.lower()
            if not (basename.startswith(("license", "licence", "copying", "notice"))
                    or "licenses" in [part.lower() for part in parts]):
                continue
            source = Path(dist.locate_file(item))
            if not source.is_file():
                continue
            # Keep paths unique without recording the absolute environment path.
            target = destination.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            licenses.append(target.relative_to(distribution).as_posix())
        declared = dist.metadata.get("License-Expression") or dist.metadata.get("License") or "Not declared in wheel metadata"
        classifiers = [value for value in dist.metadata.get_all("Classifier", []) if value.startswith("License ::")]
        record = dist.read_text("RECORD")
        metadata_text = dist.read_text("METADATA") or ""
        (destination / "metadata-license.txt").write_text(
            f"Package: {name}\nVersion: {dist.version}\nDeclared license:\n{declared}\n" + "\n".join(classifiers) + "\n", encoding="utf-8")
        entry = {"name": name, "version": dist.version,
                 "metadata_sha256": hashlib.sha256(metadata_text.encode()).hexdigest(),
                 "installed_record_sha256": hashlib.sha256(record.encode()).hexdigest() if record else None,
                 "license_files": licenses,
                 "license_metadata": (destination / "metadata-license.txt").relative_to(distribution).as_posix()}
        dependencies.append(entry)
        notices.append(f"- {name} {dist.version}: `{destination.relative_to(distribution).as_posix()}/`\n")
    candidates = [Path(sysconfig.get_path("stdlib")) / "LICENSE.txt", Path(sys.base_prefix) / "LICENSE.txt",
                  Path(sys.base_prefix) / "LICENSE"]
    python_license = next((p for p in candidates if p.is_file()), None)
    if python_license is None:
        raise RuntimeError("The build Python must provide LICENSE.txt so its runtime license is redistributed")
    shutil.copyfile(python_license, license_root / "PYTHON-LICENSE.txt")
    (distribution / "THIRD_PARTY_NOTICES.md").write_text("\n".join(notices), encoding="utf-8")
    return dependencies


def create_archive(distribution, destination, os_name):
    if os_name == "windows":
        with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in portable_sorted(distribution.rglob("*"), distribution):
                if path.is_file():
                    archive.write(path, path.relative_to(distribution.parent).as_posix())
    else:
        # Refuse an existing archive: never silently replace an already shipped
        # release artifact. tarfile handles required internal symlinks natively.
        with destination.open("xb") as handle:
            with tarfile.open(fileobj=handle, mode="w:gz", compresslevel=9) as archive:
                def portable_metadata(member):
                    member.uid = member.gid = 0
                    member.uname = member.gname = ""
                    member.mtime = 0
                    member.pax_headers = {}
                    return member
                archive.add(distribution, arcname=distribution.name, filter=portable_metadata)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "release", help="Archive/manifest output directory (existing files are never overwritten)")
    parser.add_argument("--work-dir", type=Path, required=True, help="Fresh or empty build directory; retained for inspection")
    parser.add_argument("--expected-version", help="Require this exact project version before building")
    args = parser.parse_args(argv)
    if sys.version_info[:2] != (3, 12):
        parser.error("Standalone releases use Python 3.12; create a dedicated build environment")
    import tomllib
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    if args.expected_version and version != args.expected_version:
        parser.error(f"Expected {args.expected_version}, found {version}")
    for dependency, expected in EXPECTED.items():
        if metadata.version(dependency) != expected:
            parser.error(f"Install requirements-release.txt: {dependency} must be {expected}")
    os_name, arch = platform_tag()
    filename = archive_name(version, os_name, arch)
    stem = filename.removesuffix(".tar.gz").removesuffix(".zip")
    output, work = args.output.resolve(), args.work_dir.resolve()
    if work.exists() and any(work.iterdir()):
        parser.error("--work-dir must be fresh or empty; existing build output is retained")
    if work == output or work.is_relative_to(output) or output.is_relative_to(work):
        parser.error("--output and --work-dir must be separate, non-nested directories")
    artifact, manifest_path = output / filename, output / f"{stem}.build-manifest.json"
    if artifact.exists() or manifest_path.exists():
        parser.error("Release archive or manifest already exists; use a fresh output directory")
    work.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
                    "--distpath", str(work / "dist"), "--workpath", str(work / "pyinstaller"),
                    str(ROOT / "packaging" / "invscan.spec")], cwd=ROOT, check=True)
    distribution = work / "dist" / stem
    (work / "dist" / "invscan").rename(distribution)
    shutil.copyfile(ROOT / "packaging" / "README.txt", distribution / "README.txt")
    shutil.copyfile(ROOT / "NOTICE.md", distribution / "NOTICE.md")
    for example in EXAMPLE_FILES:
        source, destination = ROOT / "examples" / example, distribution / "examples" / example
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"Expected regular bundled example: {example}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    dependencies = write_notices(distribution)
    inputs = source_inventory()
    manifest = {"schema_version": "1.0", "product": "Invarune", "version": version,
                "format": "pyinstaller-onedir", "platform": os_name, "architecture": arch,
                "executable": "invscan.exe" if os_name == "windows" else "invscan",
                "archive": filename, "archive_root": stem, "git": git_state(),
                "python_version": platform.python_version(), "pyinstaller_version": EXPECTED["pyinstaller"],
                "build_os": {"system": platform.system(), "release": platform.release(),
                             "libc": list(platform.libc_ver()), "macos": platform.mac_ver()[0]},
                "source_inputs": inputs,
                "source_inputs_sha256": hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest(),
                "build_dependencies": dependencies,
                "dependency_inventory_scope": "Complete build environment, including build-only packages; not a complete native-library SBOM",
                "features": {"pdf_export_import": True, "headroom": EXPECTED["headroom-ai"],
                             "bundled_vendor_clis": False, "bundled_credentials": False,
                             "tls_ca_fallback": "Bundled certifi only when the system trust store is empty and no SSL_CERT_FILE/SSL_CERT_DIR override exists"},
                "files": file_inventory(distribution)}
    (distribution / "build-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    create_archive(distribution, artifact, os_name)
    manifest["archive_sha256"] = sha256(artifact)
    manifest["archive_size"] = artifact.stat().st_size
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"archive": str(artifact), "manifest": str(manifest_path),
                      "distribution": str(distribution), "sha256": manifest["archive_sha256"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
