"""Small in-memory Docker-save and OCI fixtures; never need a container daemon."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def tar_bytes(entries):
    """Entries are (path, bytes/str) pairs or dicts (path, kind, data, target, mode...)."""
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for entry in entries:
            if isinstance(entry, (tuple, list)):
                entry = {"path": entry[0], "data": entry[1]}
            item = tarfile.TarInfo(entry["path"])
            kind = entry.get("kind", "file")
            item.mode = entry.get("mode", 0o755 if kind == "directory" else 0o644)
            item.uid, item.gid = entry.get("uid", 0), entry.get("gid", 0)
            item.mtime = 0
            item.pax_headers = entry.get("pax_headers", {})
            if kind == "directory":
                item.type = tarfile.DIRTYPE
            elif kind in ("symlink", "hardlink"):
                item.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
                item.linkname = entry["target"]
            elif kind in ("fifo", "device"):
                item.type = tarfile.FIFOTYPE if kind == "fifo" else tarfile.CHRTYPE
            else:
                data = entry.get("data", b"")
                if isinstance(data, str):
                    data = data.encode("utf-8")
                item.size = len(data)
                archive.addfile(item, io.BytesIO(data))
                continue
            archive.addfile(item)
    return stream.getvalue()


def docker_archive(path, layers, config=None, *, gzip_outer=False, extra_entries=(), diff_ids=True):
    """Write Docker-save archive. Layers are tar bytes or lists accepted by tar_bytes."""
    payloads = [layer if isinstance(layer, bytes) else tar_bytes(layer) for layer in layers]
    actual = {"os": "linux", "architecture": "amd64", "config": {}}
    if config is not None:
        actual.update(config)
    if diff_ids and "rootfs" not in actual:
        actual["rootfs"] = {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest() for layer in payloads]}
    config_bytes = json_bytes(actual)
    config_name = hashlib.sha256(config_bytes).hexdigest() + ".json"
    names = ["layer%d/layer.tar" % i for i in range(len(payloads))]
    manifest = [{"Config": config_name, "RepoTags": ["fixture:latest"], "Layers": names}]
    entries = [("manifest.json", json_bytes(manifest)), (config_name, config_bytes)]
    entries += list(zip(names, payloads)) + list(extra_entries)
    data = tar_bytes(entries)
    Path(path).write_bytes(gzip.compress(data, mtime=0) if gzip_outer else data)
    return Path(path)


def oci_archive(path, layers, config=None, *, gzip_layers=False, platforms=None, extra_entries=(), media_type=None):
    """Write OCI archive; platforms optionally generates an image for each platform."""
    payloads = [layer if isinstance(layer, bytes) else tar_bytes(layer) for layer in layers]
    entries = {}
    descriptors = []
    def blob(data, media):
        digest = hashlib.sha256(data).hexdigest()
        entries["blobs/sha256/" + digest] = data
        return {"mediaType": media, "size": len(data), "digest": "sha256:" + digest}
    for platform in platforms or ["linux/amd64"]:
        pieces = platform.split("/")
        actual = {"os": pieces[0], "architecture": pieces[1], "config": {}}
        if len(pieces) > 2:
            actual["variant"] = pieces[2]
        if config is not None:
            actual.update(config)
        actual.setdefault("rootfs", {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest() for layer in payloads]})
        config_descriptor = blob(json_bytes(actual), "application/vnd.oci.image.config.v1+json")
        layer_descriptors = []
        for payload in payloads:
            layer_descriptors.append(blob(gzip.compress(payload, mtime=0) if gzip_layers else payload,
                                          media_type or ("application/vnd.oci.image.layer.v1.tar+gzip" if gzip_layers else "application/vnd.oci.image.layer.v1.tar")))
        manifest = {"schemaVersion": 2, "config": config_descriptor, "layers": layer_descriptors}
        descriptor = blob(json_bytes(manifest), "application/vnd.oci.image.manifest.v1+json")
        descriptor["platform"] = {key: actual[key] for key in ("os", "architecture", "variant") if key in actual}
        descriptors.append(descriptor)
    entries["oci-layout"] = json_bytes({"imageLayoutVersion": "1.0.0"})
    entries["index.json"] = json_bytes({"schemaVersion": 2, "manifests": descriptors})
    Path(path).write_bytes(tar_bytes(list(entries.items()) + list(extra_entries)))
    return Path(path)


def rewrite_archive(path, transform):
    """Rewrite raw archive entries through transform(list[(path,bytes)])."""
    with tarfile.open(str(path), "r:*") as archive:
        entries = [(member.name, archive.extractfile(member).read()) for member in archive if member.isfile()]
    Path(path).write_bytes(tar_bytes(transform(entries)))
