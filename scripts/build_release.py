"""Build a standalone source ZIP for a tagged wcopy_reader release.

The archive contains the library, its pinned dependency, current documentation,
and runnable examples. No HID hardware, original executables, tests, credentials,
or diagnostic logs are included. Uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
from pathlib import Path
import re
from zipfile import ZIP_DEFLATED, ZipFile

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

PACKAGE_FILES = (
    "README.md",
    "wcopy_reader_package/wcopy_reader.py",
    "wcopy_reader_package/requirements.txt",
    "wcopy_reader_package/PROTOCOL.md",
    "wcopy_reader_package/CYB_PROTOCOL.md",
    "wcopy_reader_package/examples/read_example.py",
    "wcopy_reader_package/examples/write_example.py",
    "wcopy_reader_package/examples/watch_example.py",
)
VERSION_FILE = "wcopy_reader_package/wcopy_reader.py"
TAG_PATTERN = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")


def module_version(path: Path) -> str:
    """Read __version__ without importing the HID-dependent library."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__version__"
            for target in node.targets
        ):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
    raise ValueError(f"Не удалось найти строковую константу __version__ в {path}")


def build_archive(
    tag: str,
    repository_root: Path = REPOSITORY_ROOT,
    output_dir: Path | None = None,
) -> tuple[Path, Path]:
    """Validate release tag/version and create/verify ZIP + SHA-256 file."""
    if not TAG_PATTERN.fullmatch(tag):
        raise ValueError(f"Ожидается тег вида vX.Y.Z, получено {tag!r}")

    root = Path(repository_root).resolve()
    actual_version = module_version(root / VERSION_FILE)
    if tag != f"v{actual_version}":
        raise ValueError(
            f"Тег {tag} не соответствует __version__={actual_version!r}"
        )

    missing = [name for name in PACKAGE_FILES if not (root / name).is_file()]
    if missing:
        raise FileNotFoundError("Не найдены необходимые файлы: " + ", ".join(missing))

    destination = (Path(output_dir) if output_dir is not None else root / "dist").resolve()
    destination.mkdir(parents=True, exist_ok=True)
    package_name = f"wcopy_reader_package_{tag}"
    archive_path = destination / f"{package_name}.zip"
    checksum_path = destination / f"{package_name}.sha256"

    expected = [f"{package_name}/{name}" for name in PACKAGE_FILES]
    with ZipFile(archive_path, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for relative in PACKAGE_FILES:
            archive.write(root / relative, arcname=f"{package_name}/{relative}")

    with ZipFile(archive_path, "r") as archive:
        if archive.namelist() != expected:
            raise RuntimeError("Состав ZIP не совпадает с утверждённым списком файлов")
        corrupt_file = archive.testzip()
        if corrupt_file is not None:
            raise RuntimeError(f"Ошибка проверки ZIP: {corrupt_file}")

    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    checksum_path.write_text(f"{digest}  {archive_path.name}\n", encoding="ascii")
    return archive_path, checksum_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Собрать релиз CyberpunkPcRfidReader")
    parser.add_argument("--tag", required=True, help="Тег vX.Y.Z (должен совпасть с __version__)")
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    args = parser.parse_args()

    archive, checksum = build_archive(args.tag, output_dir=args.output_dir)
    print(f"Готов архив: {archive}")
    print(f"Размер: {archive.stat().st_size} байт")
    print(f"SHA-256: {checksum}")
    print(checksum.read_text(encoding="ascii").strip())


if __name__ == "__main__":
    main()
