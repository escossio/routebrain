from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

from app.collectors.routeviews_metadata import (
    RouteViewsMetadataError,
    get_routeviews_collector_name,
)


class RouteViewsDownloadError(RuntimeError):
    """Raised when the latest RouteViews RIB cannot be downloaded."""


def _load_environment() -> None:
    project_root = Path(__file__).resolve().parents[2]
    load_dotenv(project_root / ".env")
    load_dotenv()


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def find_latest_metadata_path(collector: str | None = None) -> Path:
    collector_name = collector or get_routeviews_collector_name()
    processed_dir = _project_root() / "data" / "processed"
    pattern = f"routeviews_metadata_{collector_name}.json"
    candidates = [path for path in processed_dir.glob(pattern) if path.is_file()]
    if not candidates:
        raise RouteViewsDownloadError(
            f"Nenhum metadata JSON encontrado para o coletor '{collector_name}' em {processed_dir}."
        )
    return max(candidates, key=lambda path: path.stat().st_mtime)


def load_latest_rib_metadata(metadata_path: Path | None = None) -> dict[str, Any]:
    if metadata_path is None:
        metadata_path = find_latest_metadata_path()

    try:
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RouteViewsDownloadError(f"Falha ao ler metadata JSON {metadata_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RouteViewsDownloadError(f"Metadata JSON inválido em {metadata_path}.") from exc

    if not isinstance(payload, dict):
        raise RouteViewsDownloadError("Metadata JSON em formato inesperado.")

    collector = payload.get("collector")
    ribs = payload.get("ribs")
    if not isinstance(collector, str) or not collector:
        raise RouteViewsDownloadError("Metadata sem campo collector válido.")
    if not isinstance(ribs, dict):
        raise RouteViewsDownloadError("Metadata sem campo ribs válido.")

    latest_dump_file = ribs.get("latestDumpFile")
    if not isinstance(latest_dump_file, str) or not latest_dump_file:
        raise RouteViewsDownloadError("Metadata sem ribs.latestDumpFile válido.")

    return {
        "collector": collector,
        "url": latest_dump_file,
    }


def _derive_filename(url: str) -> str:
    parsed = urlparse(url)
    filename = Path(parsed.path).name
    if not filename:
        raise RouteViewsDownloadError(f"Não foi possível extrair o nome do arquivo a partir da URL: {url}")
    return filename


def _stream_download(url: str, output_path: Path) -> int:
    temp_path = output_path.with_suffix(output_path.suffix + ".part")
    temp_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with requests.get(url, stream=True, timeout=60) as response:
            if response.status_code != 200:
                raise RouteViewsDownloadError(
                    f"Falha ao baixar RIB. HTTP {response.status_code} ao acessar {url}"
                )

            total_bytes = response.headers.get("Content-Length")
            expected_size = int(total_bytes) if total_bytes and total_bytes.isdigit() else None
            downloaded_bytes = 0
            last_reported_mb = -1

            with temp_path.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if not chunk:
                        continue
                    handle.write(chunk)
                    downloaded_bytes += len(chunk)

                    current_mb = downloaded_bytes // (1024 * 1024)
                    if current_mb != last_reported_mb:
                        last_reported_mb = current_mb
                        if expected_size:
                            percent = (downloaded_bytes / expected_size) * 100
                            print(
                                f"\rBaixando {output_path.name}: {downloaded_bytes}/{expected_size} bytes ({percent:.1f}%)",
                                end="",
                                flush=True,
                            )
                        else:
                            print(
                                f"\rBaixando {output_path.name}: {downloaded_bytes} bytes",
                                end="",
                                flush=True,
                            )

        temp_path.replace(output_path)
        print(f"\rBaixando {output_path.name}: concluído com {downloaded_bytes} bytes")
        return downloaded_bytes
    except Exception:
        if temp_path.exists():
            temp_path.unlink()
        raise


def download_latest_rib(metadata_path: Path | None = None) -> dict[str, Any]:
    _load_environment()
    metadata = load_latest_rib_metadata(metadata_path)
    collector = metadata["collector"]
    url = metadata["url"]

    filename = _derive_filename(url)
    output_dir = _project_root() / "data" / "raw" / "routeviews" / collector
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / filename

    if output_path.exists() and output_path.stat().st_size > 0:
        return {
            "collector": collector,
            "url": url,
            "filename": filename,
            "output_path": str(output_path),
            "downloaded": False,
            "size_bytes": output_path.stat().st_size,
        }

    size_bytes = _stream_download(url, output_path)
    if size_bytes <= 0:
        raise RouteViewsDownloadError(f"Download concluído sem bytes válidos para {url}")

    return {
        "collector": collector,
        "url": url,
        "filename": filename,
        "output_path": str(output_path),
        "downloaded": True,
        "size_bytes": size_bytes,
    }
