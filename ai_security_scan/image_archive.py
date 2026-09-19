"""Bounded, non-executing Docker-save/OCI archive inspection.

Image paths never become extraction paths. Tar contents first enter private
numbered blobs; only the reconstructed regular-file view is copied to rootfs.
There are no tarfile.extract calls, image processes, host links, or network reads.
Limits cover compressed input, expanded outer tar, cumulative expanded layers,
tar headers, layer count, and (separately) final materialized bytes.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import unicodedata


class ImageArchiveError(ValueError):
    """The image cannot be inspected completely and safely."""


_CHUNK = 1024 * 1024
_JSON_LIMIT = 8 * 1024 * 1024
_METADATA_LIMIT = 1024 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RESERVED = re.compile(r"(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\..*)?\Z", re.I)
_MANIFEST_TYPES = {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}
_INDEX_TYPES = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
_LAYER_TYPES = {
    "application/vnd.oci.image.layer.v1.tar": False,
    "application/vnd.oci.image.layer.v1.tar+gzip": True,
    "application/vnd.oci.image.layer.nondistributable.v1.tar": False,
    "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip": True,
    "application/vnd.docker.image.rootfs.diff.tar": False,
    "application/vnd.docker.image.rootfs.diff.tar.gzip": True,
    "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip": True,
}


def _path(value, *, allow_root=False):
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/"):
        raise ImageArchiveError("Unsafe archive path: %r" % value)
    if any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ImageArchiveError("Control or invalid Unicode character in archive path")
    parts = value.rstrip("/").split("/")
    while parts and parts[0] == ".":
        parts.pop(0)
    if not parts and allow_root:
        return ""
    if not parts or any(p in ("", ".", "..") for p in parts):
        raise ImageArchiveError("Unsafe archive path: %r" % value)
    for part in parts:
        if any(c in part for c in ':<>"|?*') or part.endswith((".", " ")) or _RESERVED.fullmatch(part):
            raise ImageArchiveError("Nonportable or Windows-ambiguous image path: %r" % value)
        if len(part.encode("utf-8")) > 255:
            raise ImageArchiveError("Image path component exceeds 255 bytes")
    if len(parts) > 128 or len("/".join(parts).encode("utf-8")) > 4096:
        raise ImageArchiveError("Image path exceeds depth or length limit")
    return "/".join(parts)


def _collision(path):
    return unicodedata.normalize("NFC", path).casefold()


def _json(path, label):
    if path.stat().st_size > _JSON_LIMIT:
        raise ImageArchiveError("%s exceeds JSON metadata limit" % label)
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ImageArchiveError("Duplicate JSON key in %s" % label)
            value[key] = item
        return value
    try:
        with path.open("rb") as stream:
            result = json.loads(stream.read(_JSON_LIMIT + 1), object_pairs_hook=pairs,
                                parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ImageArchiveError("Invalid JSON in %s" % label) from exc
    return result


def _copy(stream, path, limit, label, expected=None):
    total = 0
    digest = hashlib.sha256()
    with path.open("xb") as target:
        os.chmod(str(path), 0o600)
        while True:
            data = stream.read(min(_CHUNK, limit - total + 1))
            if not data:
                break
            total += len(data)
            if total > limit:
                raise ImageArchiveError("%s exceeds byte limit" % label)
            target.write(data)
            digest.update(data)
    if expected is not None and total != expected:
        raise ImageArchiveError("Truncated or inconsistent %s" % label)
    return {"blob_path": path, "size": total, "sha256": digest.hexdigest()}


def _inflate(source, output, remaining, label, expected_gzip=None):
    with source.open("rb") as raw:
        magic = raw.read(6)
        raw.seek(0)
        is_gzip = magic.startswith(b"\x1f\x8b")
        if expected_gzip is not None and is_gzip != expected_gzip:
            raise ImageArchiveError("%s compression does not match media type" % label)
        if magic.startswith((b"BZh", b"\xfd7zXZ", b"\x28\xb5\x2f\xfd")):
            raise ImageArchiveError("Unsupported compression in %s; use plain tar or gzip" % label)
        if is_gzip:
            try:
                with gzip.GzipFile(fileobj=raw) as stream:
                    return _copy(stream, output, remaining, label)
            except (OSError, EOFError) as exc:
                raise ImageArchiveError("Invalid or truncated gzip in %s" % label) from exc
        return _copy(raw, output, remaining, label)


def _members(path, budget, label):
    class SafeTarInfo(tarfile.TarInfo):
        def _proc_member(self, archive):
            budget["headers"] += 1
            if budget["headers"] > budget["max_entries"]:
                raise ImageArchiveError("Image exceeds archive entry limit")
            if self.size < 0:
                raise ImageArchiveError("Negative tar member size")
            if self.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
                if self.size > _METADATA_LIMIT:
                    raise ImageArchiveError("Tar extended header exceeds metadata limit")
            if self.type == tarfile.GNUTYPE_SPARSE:
                raise ImageArchiveError("Sparse tar entries are unsupported")
            if self.type in (tarfile.XHDTYPE, tarfile.XGLTYPE):
                position = archive.fileobj.tell()
                metadata = archive.fileobj.read(self._block(self.size))
                archive.fileobj.seek(position)
                if b"GNU.sparse" in metadata:
                    raise ImageArchiveError("Sparse tar entries are unsupported")
            return super()._proc_member(archive)

    try:
        with tarfile.open(str(path), mode="r:", tarinfo=SafeTarInfo) as archive:
            for entry in archive:
                if entry.size < 0 or any(key.startswith("GNU.sparse") for key in entry.pax_headers):
                    raise ImageArchiveError("Sparse or invalid tar entry in %s" % label)
                yield archive, entry
            # tarfile accepts missing end markers and ignores data after the first
            # zero block. Validate both rather than accepting partial archives.
            with path.open("rb") as stream:
                stream.seek(archive.offset)
                remaining = path.stat().st_size - archive.offset
                if remaining < 1024 or remaining % 512:
                    raise ImageArchiveError("Truncated tar end markers in %s" % label)
                while True:
                    data = stream.read(_CHUNK)
                    if not data:
                        break
                    if any(data):
                        raise ImageArchiveError("Unexpected trailing tar data in %s" % label)
    except (tarfile.TarError, EOFError, OverflowError) as exc:
        raise ImageArchiveError("Invalid or truncated tar in %s" % label) from exc


def _index_outer(path, storage, budget):
    result, portable = {}, {}
    for archive, entry in _members(path, budget, "image archive"):
        name = _path(entry.name, allow_root=entry.isdir())
        if not name:
            continue
        folded = _collision(name)
        if folded in portable and portable[folded] != name:
            raise ImageArchiveError("Case/Unicode-colliding archive paths")
        portable[folded] = name
        if name in result:
            raise ImageArchiveError("Duplicate archive entry: %s" % name)
        if entry.isdir():
            result[name] = {"kind": "directory"}
            continue
        if not entry.isfile():
            raise ImageArchiveError("Outer image archive contains unsupported link or special entry: %s" % name)
        if entry.size > budget["max_archive_bytes"] - budget["outer_file_bytes"]:
            raise ImageArchiveError("Outer archive files exceed byte limit")
        source = archive.extractfile(entry)
        if source is None:
            raise ImageArchiveError("Missing archive member contents")
        with source:
            record = _copy(source, storage / ("outer-%d" % len(result)), entry.size,
                           "outer archive member", expected=entry.size)
        budget["outer_file_bytes"] += record["size"]
        result[name] = dict(record, kind="file")
    return result


def _outer_file(index, path):
    name = _path(path)
    entry = index.get(name)
    if not entry or entry["kind"] != "file":
        raise ImageArchiveError("Required image archive member is missing: %s" % name)
    return entry


def _descriptor(index, descriptor):
    if not isinstance(descriptor, dict):
        raise ImageArchiveError("Image descriptor must be an object")
    digest, size = descriptor.get("digest"), descriptor.get("size")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise ImageArchiveError("Only valid SHA-256 image descriptors are supported")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ImageArchiveError("Image descriptor has invalid size")
    record = _outer_file(index, "blobs/sha256/" + digest.split(":", 1)[1])
    if record["sha256"] != digest[7:] or record["size"] != size:
        raise ImageArchiveError("Image descriptor digest or size mismatch")
    return record


def _platform(config):
    os_name, arch = config.get("os"), config.get("architecture")
    variant = config.get("variant")
    if not isinstance(os_name, str) or not isinstance(arch, str) or not os_name or not arch:
        raise ImageArchiveError("Image config must identify os and architecture")
    if variant is not None and not isinstance(variant, str):
        raise ImageArchiveError("Invalid image platform variant")
    components = [os_name, arch] + ([variant] if variant else [])
    if any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", part) for part in components):
        raise ImageArchiveError("Invalid image platform name")
    return "/".join(components)


def _match_platform(actual, selected):
    return actual == selected or (len(selected.split("/")) == 2 and actual.startswith(selected + "/"))


def _select(candidates, selected):
    if selected is not None:
        if not isinstance(selected, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?", selected):
            raise ImageArchiveError("Platform must be os/architecture[/variant]")
        candidates = [item for item in candidates if _match_platform(item["platform"], selected)]
    # Duplicate references to the same manifest are harmless tag aliases.
    distinct = {}
    for item in candidates:
        distinct[item["manifest_digest"]] = item
    candidates = list(distinct.values())
    if not candidates:
        raise ImageArchiveError("No image matches requested platform")
    if len(candidates) != 1:
        raise ImageArchiveError("Archive contains multiple images; export one image or select an unambiguous --platform")
    return candidates[0]


def _oci(index, selected, coverage):
    layout = _json(_outer_file(index, "oci-layout")["blob_path"], "oci-layout")
    if not isinstance(layout, dict) or layout.get("imageLayoutVersion") != "1.0.0":
        raise ImageArchiveError("Unsupported OCI image layout version")
    root = _json(_outer_file(index, "index.json")["blob_path"], "OCI index")
    candidates = []
    seen_indexes = set()
    def descend(node, depth=0):
        if depth > 8 or not isinstance(node, dict) or node.get("schemaVersion") != 2 or not isinstance(node.get("manifests"), list):
            raise ImageArchiveError("Invalid or excessively nested OCI image index")
        for descriptor in node["manifests"]:
            if not isinstance(descriptor, dict):
                raise ImageArchiveError("Invalid OCI index descriptor")
            media = descriptor.get("mediaType")
            if media not in _INDEX_TYPES | _MANIFEST_TYPES:
                coverage["skipped"].append({"path": "index.json", "reason": "unsupported OCI artifact media type: %s" % str(media)[:160], "coverage_gap": True})
                continue
            record = _descriptor(index, descriptor)
            data = _json(record["blob_path"], "OCI manifest/index")
            if media in _INDEX_TYPES:
                if descriptor["digest"] in seen_indexes:
                    continue
                seen_indexes.add(descriptor["digest"])
                descend(data, depth + 1)
                continue
            if not isinstance(data, dict) or data.get("schemaVersion") != 2 or not isinstance(data.get("layers"), list):
                raise ImageArchiveError("Invalid OCI image manifest")
            if data.get("artifactType"):
                coverage["skipped"].append({"path": descriptor["digest"], "reason": "OCI artifact is not a runnable image", "coverage_gap": True})
                continue
            config_record = _descriptor(index, data.get("config"))
            config = _json(config_record["blob_path"], "image config")
            if not isinstance(config, dict):
                raise ImageArchiveError("Image config must be an object")
            platform = _platform(config)
            declared = descriptor.get("platform")
            if declared is not None:
                if not isinstance(declared, dict) or not _match_platform(platform, _platform(declared)):
                    raise ImageArchiveError("OCI descriptor platform does not match image config")
            candidates.append({"format": "oci", "config": config,
                               "config_digest": "sha256:" + config_record["sha256"],
                               "manifest_digest": descriptor["digest"], "platform": platform,
                               "layer_descriptors": data["layers"]})
    descend(root)
    item = _select(candidates, selected)
    layers = []
    for descriptor in item.pop("layer_descriptors"):
        if not isinstance(descriptor, dict) or descriptor.get("mediaType") not in _LAYER_TYPES:
            raise ImageArchiveError("Unsupported OCI layer media type; use plain tar or gzip")
        layers.append(dict(_descriptor(index, descriptor), gzip=_LAYER_TYPES[descriptor["mediaType"]]))
    return item, layers


def _docker(index, selected):
    manifest_record = _outer_file(index, "manifest.json")
    manifest = _json(manifest_record["blob_path"], "Docker manifest")
    if not isinstance(manifest, list) or not manifest:
        raise ImageArchiveError("Docker manifest must be a nonempty array")
    candidates = []
    for item in manifest:
        if not isinstance(item, dict) or not isinstance(item.get("Layers"), list):
            raise ImageArchiveError("Invalid Docker manifest entry")
        record = _outer_file(index, item.get("Config"))
        config = _json(record["blob_path"], "Docker image config")
        if not isinstance(config, dict):
            raise ImageArchiveError("Docker image config must be an object")
        filename = PurePosixPath(item["Config"]).name
        if re.fullmatch(r"[0-9a-f]{64}\.json", filename) and filename[:-5] != record["sha256"]:
            raise ImageArchiveError("Docker image config filename digest mismatch")
        # Docker-save has no manifest descriptor; hash the selected manifest
        # entry in a documented canonical JSON encoding, not the whole list.
        manifest_digest = hashlib.sha256(json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        candidates.append({"format": "docker-save", "config": config,
                           "config_digest": "sha256:" + record["sha256"],
                           "manifest_digest": "sha256:" + manifest_digest,
                           "platform": _platform(config), "layer_names": item["Layers"],
                           "repo_tags": item.get("RepoTags") or []})
    item = _select(candidates, selected)
    layers = [dict(_outer_file(index, name), gzip=None) for name in item.pop("layer_names")]
    return item, layers


class _ImageState(dict):
    """Index direct descendants so replacing many files is not quadratic."""
    def __init__(self):
        super().__init__()
        self.children = {}

    def __setitem__(self, name, entry):
        super().__setitem__(name, entry)
        parent = name.rsplit("/", 1)[0] if "/" in name else ""
        self.children.setdefault(parent, set()).add(name)

    def __delitem__(self, name):
        super().__delitem__(name)
        parent = name.rsplit("/", 1)[0] if "/" in name else ""
        self.children.get(parent, set()).discard(name)
        self.children.pop(name, None)


def _delete(state, path, children_only=False):
    pending = list(state.children.get(path, ()))
    if not children_only and path in state:
        pending.append(path)
    visited = set()
    while pending:
        key = pending.pop()
        if key in visited:
            continue
        visited.add(key)
        pending.extend(state.children.get(key, ()))
        if key in state:
            del state[key]


def _resolve_link(path, state):
    """Resolve paths in an in-memory image namespace, never in the host FS."""
    parts = path.split("/") if path else []
    visited = set()
    for _ in range(64):
        changed = False
        for i in range(len(parts)):
            name = "/".join(parts[:i + 1])
            entry = state.get(name)
            if entry and entry["kind"] == "symlink":
                key = (name, tuple(parts[i + 1:]))
                if key in visited:
                    raise ImageArchiveError("Cyclic image symlink")
                visited.add(key)
                target = entry["link_target"]
                current = [] if target.startswith("/") else parts[:i]
                for part in target.split("/"):
                    if part in ("", "."):
                        continue
                    if part == "..":
                        if not current:
                            raise ImageArchiveError("Image link escapes root")
                        current.pop()
                    else:
                        current.append(part)
                parts = current + parts[i + 1:]
                if len(parts) > 128:
                    raise ImageArchiveError("Image link resolution exceeds path depth")
                changed = True
                break
        if not changed:
            return "/".join(parts)
    raise ImageArchiveError("Image link resolution exceeds depth limit")


def _apply_layer(layer_path, number, state, revisions, storage, budget, coverage):
    additions, whiteouts, paths = {}, [], set()
    portable = {}
    for archive, member in _members(layer_path, budget, "layer %d" % number):
        name = _path(member.name, allow_root=member.isdir())
        if not name:
            continue
        if name in paths:
            raise ImageArchiveError("Duplicate layer entry: %s" % name)
        paths.add(name)
        folded = _collision(name)
        if folded in portable and portable[folded] != name:
            raise ImageArchiveError("Case/Unicode-colliding layer paths")
        portable[folded] = name
        base = name.rsplit("/", 1)[-1]
        parent = name.rsplit("/", 1)[0] if "/" in name else ""
        if base.startswith(".wh."):
            if not member.isfile() or member.size != 0 or base == ".wh.":
                raise ImageArchiveError("Invalid image whiteout: %s" % name)
            if base == ".wh..wh..opq":
                whiteouts.append((parent, True))
            else:
                target = base[4:]
                _path(target)
                whiteouts.append(((parent + "/" if parent else "") + target, False))
            continue
        entry = {"path": name, "mode": member.mode, "uid": member.uid, "gid": member.gid,
                 "size": member.size, "layer": number}
        if member.isfile():
            source = archive.extractfile(member)
            if source is None:
                raise ImageArchiveError("Missing layer member contents")
            with source:
                record = _copy(source, storage / ("content-%d" % len(revisions)),
                               budget["max_unpacked_bytes"] - budget["content_bytes"],
                               "layer file", expected=member.size)
            budget["content_bytes"] += record["size"]
            entry.update(record, kind="file")
            revisions.append({"path": name, "layer": number, **record})
        elif member.isdir():
            entry["kind"] = "directory"
        elif member.issym() or member.islnk():
            entry["kind"] = "symlink" if member.issym() else "hardlink"
            target = member.linkname
            if not isinstance(target, str) or not target or "\\" in target or any(ord(c) < 32 or ord(c) == 127 for c in target):
                raise ImageArchiveError("Invalid image link target")
            if member.islnk():
                target = _path(target)
            entry["link_target"] = target
        else:
            entry["kind"] = "special"
            entry["tar_type"] = member.type.decode("ascii", "backslashreplace")
            coverage["skipped"].append({"path": name, "reason": "device/FIFO/socket/unknown entry recorded but not materialized", "coverage_gap": True})
        if any(key.startswith(("SCHILY.xattr.", "SCHILY.acl.", "LIBARCHIVE.xattr.", "MSWINDOWS.")) for key in member.pax_headers):
            coverage["skipped"].append({"path": name, "reason": "extended permissions/attributes recorded only in archive; not interpreted", "coverage_gap": True})
        additions[name] = entry
    # OCI whiteouts affect LOWER layers, regardless of their tar ordering.
    for target, children_only in whiteouts:
        parts = target.split("/") if target else []
        ancestor_count = len(parts) if children_only else max(0, len(parts) - 1)
        if any(state.get("/".join(parts[:i]), {}).get("kind", "directory") != "directory"
               for i in range(1, ancestor_count + 1)):
            coverage["errors"].append({"path": target, "error": "whiteout passes through a non-directory image ancestor", "kind": "unsupported_path_semantics"})
            continue
        _delete(state, target, children_only)
    for name, entry in additions.items():
        parts = name.split("/")
        blocked = False
        for i in range(1, len(parts)):
            parent = "/".join(parts[:i])
            existing = state.get(parent)
            if existing and existing["kind"] != "directory":
                coverage["errors"].append({"path": name, "error": "layer write passes through a non-directory image ancestor", "kind": "unsupported_path_semantics"})
                blocked = True
                break
            if not existing:
                if len(state) >= budget["max_entries"]:
                    raise ImageArchiveError("Reconstructed filesystem exceeds entry limit")
                state[parent] = {"path": parent, "kind": "directory", "mode": 0o755,
                                 "uid": 0, "gid": 0, "size": 0, "layer": number, "implicit": True}
        if blocked:
            continue
        previous = state.get(name)
        if entry["kind"] != "directory" or (previous and previous["kind"] != "directory"):
            _delete(state, name)
        if name not in state and len(state) >= budget["max_entries"]:
            raise ImageArchiveError("Reconstructed filesystem exceeds entry limit")
        state[name] = entry
    # Hardlinks bind to this layer's inode content, not a future overwritten path.
    def bind(name, seen):
        entry = state.get(name)
        if not entry:
            raise ImageArchiveError("Hardlink target is absent")
        if entry["kind"] == "hardlink" and "blob_path" not in entry:
            if name in seen or len(seen) >= 64:
                raise ImageArchiveError("Cyclic/deep image hardlink")
            target = bind(entry["link_target"], seen | {name})
            entry.update({key: target[key] for key in ("blob_path", "size", "sha256", "mode", "uid", "gid")})
        if entry["kind"] not in ("file", "hardlink"):
            raise ImageArchiveError("Hardlink target is not a regular file")
        return entry
    for name, entry in additions.items():
        if entry["kind"] == "hardlink" and state.get(name) is entry:
            try:
                bind(name, set())
            except ImageArchiveError as exc:
                coverage["errors"].append({"path": name, "error": str(exc), "kind": "unresolved_hardlink"})
    # Reject ambiguous host names, including ancestor aliases, across layers.
    portable = {}
    for name in state:
        for i in range(1, len(name.split("/")) + 1):
            prefix = "/".join(name.split("/")[:i])
            folded = _collision(prefix)
            if folded in portable and portable[folded] != prefix:
                raise ImageArchiveError("Case/Unicode-colliding image paths")
            portable[folded] = prefix


def _materialize(state, root, budget, coverage):
    root.mkdir(mode=0o700)
    root_entries = []
    for name, entry in sorted(state.items()):
        current = dict(entry)
        blob = current.pop("blob_path", None)
        current["materialized"] = False
        parent_parts = name.split("/")[:-1]
        blocked = any(state.get("/".join(parent_parts[:i]), {}).get("kind", "directory") != "directory"
                      for i in range(1, len(parent_parts) + 1))
        if blocked:
            coverage["errors"].append({"path": name, "error": "entry passes through a non-directory image ancestor", "kind": "unsupported_path_semantics"})
            root_entries.append(current)
            continue
        if current["kind"] == "symlink":
            try:
                resolved = _resolve_link(name, state)
                target = state.get(resolved)
                current["resolved_target"] = resolved
                if target and target["kind"] in ("file", "hardlink") and "blob_path" in target:
                    blob = target["blob_path"]
                    current["size"], current["sha256"] = target["size"], target["sha256"]
                elif resolved == "" or (target and target["kind"] == "directory"):
                    coverage["skipped"].append({"path": name, "reason": "directory symlink alias not materialized; target namespace scanned separately", "coverage_gap": False})
                else:
                    raise ImageArchiveError("Image symlink target is absent or not a regular file")
            except ImageArchiveError as exc:
                coverage["errors"].append({"path": name, "error": str(exc), "kind": "unresolved_symlink"})
        target_path = root.joinpath(*name.split("/"))
        if current["kind"] == "directory":
            target_path.mkdir(parents=True, exist_ok=True, mode=0o700)
            current["materialized"] = True
        elif blob is not None:
            if current["size"] > budget["max_unpacked_bytes"] - budget["materialized_bytes"]:
                raise ImageArchiveError("Final image filesystem exceeds byte limit (including copied links)")
            target_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with blob.open("rb") as source:
                _copy(source, target_path, current["size"], "materialized file", expected=current["size"])
            budget["materialized_bytes"] += current["size"]
            current["materialized"] = True
        root_entries.append(current)
    return root_entries


def materialize_image(archive, destination, *, platform=None, max_archive_bytes=2_000_000_000,
                      max_unpacked_bytes=4_000_000_000, max_entries=500_000, max_layers=200):
    """Return a safe reconstructed image view and provenance/coverage metadata.

    ``destination`` must be a fresh private directory. Fatal malformed archives,
    unsupported compression, ambiguous images, or exceeded budgets raise
    :class:`ImageArchiveError`; callers must report an incomplete scan. Callers
    own temporary directory cleanup. Links/devices are never created on the host.
    """
    archive, destination = Path(archive), Path(destination)
    for name, value in (("max_archive_bytes", max_archive_bytes), ("max_unpacked_bytes", max_unpacked_bytes),
                        ("max_entries", max_entries), ("max_layers", max_layers)):
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ImageArchiveError("%s must be a positive integer" % name)
    if destination.is_symlink() or not destination.is_dir() or any(destination.iterdir()):
        raise ImageArchiveError("Image destination must be an existing empty private directory")
    os.chmod(str(destination), 0o700)
    coverage = {"errors": [], "skipped": []}
    budget = {"max_archive_bytes": max_archive_bytes, "max_unpacked_bytes": max_unpacked_bytes,
              "max_entries": max_entries, "headers": 0, "outer_file_bytes": 0,
              "unpacked_bytes": 0, "content_bytes": 0, "materialized_bytes": 0}
    try:
        info = archive.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ImageArchiveError("Image input must be a regular Docker-save or OCI archive file (export directory layouts as tar)")
        if info.st_size > max_archive_bytes:
            raise ImageArchiveError("Image archive exceeds byte limit")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(str(archive), flags)
        with os.fdopen(fd, "rb") as source:
            opened = os.fstat(source.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise ImageArchiveError("Image archive changed while opening")
            input_record = _copy(source, destination / "archive.input", max_archive_bytes, "image archive", expected=info.st_size)
        storage = destination / "blobs"
        storage.mkdir(mode=0o700)
        outer = destination / "archive.tar"
        _inflate(input_record["blob_path"], outer, max_archive_bytes, "expanded image archive")
        expanded_archive_bytes = outer.stat().st_size
        input_record["blob_path"].unlink()
        index = _index_outer(outer, storage, budget)
        outer.unlink()
        if "oci-layout" in index:
            identity, layers = _oci(index, platform, coverage)
        elif "manifest.json" in index:
            identity, layers = _docker(index, platform)
        else:
            raise ImageArchiveError("Input is not a Docker-save or OCI archive; docker export/rootfs tar is unsupported")
        if len(layers) > max_layers:
            raise ImageArchiveError("Image exceeds layer count limit")
        config = identity.pop("config")
        rootfs = config.get("rootfs")
        diff_ids = None
        if rootfs is not None:
            if not isinstance(rootfs, dict) or rootfs.get("type") != "layers" or not isinstance(rootfs.get("diff_ids"), list):
                raise ImageArchiveError("Invalid image rootfs diff_ids")
            diff_ids = rootfs["diff_ids"]
            if len(diff_ids) != len(layers) or any(not isinstance(value, str) or not _DIGEST.fullmatch(value) for value in diff_ids):
                raise ImageArchiveError("Image rootfs diff_ids count/digest is invalid")
        else:
            coverage["skipped"].append({"path": "image-config", "reason": "rootfs diff_ids absent; uncompressed layer identity cannot be cross-checked", "coverage_gap": True})
        state, revisions, expanded_digests = _ImageState(), [], []
        for number, layer in enumerate(layers):
            temporary = destination / "layer.tar"
            record = _inflate(layer["blob_path"], temporary, max_unpacked_bytes - budget["unpacked_bytes"],
                              "expanded layer %d" % number, layer["gzip"])
            budget["unpacked_bytes"] += record["size"]
            digest = "sha256:" + record["sha256"]
            expanded_digests.append(digest)
            if diff_ids is not None and diff_ids[number] != digest:
                raise ImageArchiveError("Image layer diff_id mismatch")
            _apply_layer(temporary, number, state, revisions, storage, budget, coverage)
            temporary.unlink()
        for record in index.values():
            if record["kind"] == "file":
                record["blob_path"].unlink()
        entries = _materialize(state, destination / "rootfs", budget, coverage)
        identity.update(archive_sha256=input_record["sha256"], layer_digests=["sha256:" + layer["sha256"] for layer in layers],
                        diff_ids=expanded_digests)
        if identity["format"] == "docker-save":
            identity["manifest_digest_encoding"] = "selected-entry-canonical-json"
        coverage.update(archive_bytes=input_record["size"], expanded_archive_bytes=expanded_archive_bytes,
                        unpacked_layer_bytes=budget["unpacked_bytes"], layer_content_bytes=budget["content_bytes"],
                        materialized_bytes=budget["materialized_bytes"], archive_entries=budget["headers"],
                        layers=len(layers), final_entries=len(entries), file_revisions=len(revisions))
        return {"root": destination / "rootfs", "config": config, "identity": identity, "entries": entries,
                "layer_files": revisions, "coverage": coverage}
    except ImageArchiveError:
        raise
    except (OSError, ValueError, RecursionError, TypeError, KeyError, tarfile.TarError, EOFError) as exc:
        raise ImageArchiveError("Unable to inspect image archive safely: %s" % str(exc)[:240]) from exc
