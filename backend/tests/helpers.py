import io
import json
import zipfile

from sentinel.models import DependencyGraph
from sentinel.parsers import parse_repository
from sentinel.parsers.base import ParseContext
from sentinel.reposource import ZipSource


def make_zip(files: dict, raw_entries: list | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            if isinstance(content, (dict, list)):
                content = json.dumps(content)
            zf.writestr(name, content)
        for info, data in raw_entries or []:
            zf.writestr(info, data)
    return buf.getvalue()


def parse_files(files: dict):
    src = ZipSource(make_zip(files))
    ctx = ParseContext(graph=DependencyGraph())
    parse_repository(src, ctx)
    return ctx, src


def names(ctx, eco=None):
    return {(p.name, p.version) for p in ctx.graph.packages.values() if eco is None or p.ecosystem == eco}
