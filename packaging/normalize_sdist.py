#!/usr/bin/env python3
"""Rewrite an sdist (.tar.gz) deterministically, in place: members sorted, mtime = SOURCE_DATE_EPOCH, root ownership,
fixed modes (the exec bit is kept), no pax headers, gzip header time 0. setuptools stamps build-time metadata into both the
tar and the gzip, so two builds of the same tree differ; after this they do not.

    SOURCE_DATE_EPOCH=1800000000 python packaging/normalize_sdist.py dist/cora_sentinel-X.tar.gz
"""
import gzip
import io
import os
import sys
import tarfile


def normalize(path: str, epoch: int) -> None:
    with tarfile.open(path) as tf:
        members = sorted(tf.getmembers(), key=lambda m: m.name)
        blobs = {m.name: tf.extractfile(m).read() for m in members if m.isfile()}
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as out:
        for m in members:
            ti = tarfile.TarInfo(m.name)
            ti.type = tarfile.DIRTYPE if m.isdir() else tarfile.REGTYPE
            ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = epoch, 0, 0, "", ""
            ti.mode = 0o755 if (m.isdir() or m.mode & 0o111) else 0o644
            if m.isfile():
                ti.size = len(blobs[m.name])
                out.addfile(ti, io.BytesIO(blobs[m.name]))
            else:
                out.addfile(ti)
    with open(path, "wb") as fh:
        with gzip.GzipFile(filename="", mode="wb", fileobj=fh, mtime=0, compresslevel=9) as gz:
            gz.write(raw.getvalue())


if __name__ == "__main__":
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    for p in sys.argv[1:]:
        normalize(p, epoch)
