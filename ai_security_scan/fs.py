"""Read regular files through directory descriptors where the OS supports it."""
import os
from pathlib import Path
import stat


def read_confined(root, relative, limit, root_identity=None):
    relative = Path(relative)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise OSError("Invalid relative source path")
    root = Path(root)
    if os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"):
        directory_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            opened_root = os.fstat(directory_fd)
            if root_identity and (opened_root.st_dev, opened_root.st_ino) != root_identity:
                raise OSError("Source root changed")
            for component in relative.parts[:-1]:
                child_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = child_fd
            fd = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=directory_fd)
        finally:
            os.close(directory_fd)
    else:
        # No dirfd/openat on some platforms. Reject visible symlinks and retain
        # a documented concurrent-filesystem limitation on those platforms.
        path = root / relative
        if any(p.is_symlink() for p in [path, *path.parents]) or root not in path.resolve().parents:
            raise OSError("Source path crossed a symbolic link")
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise OSError("Source is not a regular file")
        if info.st_size > limit:
            raise OSError("Source exceeded read limit")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise OSError("Source grew beyond read limit")
        return data, info
