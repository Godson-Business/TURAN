from __future__ import annotations

from app.http.normalizer import normalize_url, same_host


def crawl_links(base_url: str, links: list[str]) -> list[str]:
    return [normalize_url(base_url, link) for link in links if same_host(base_url, normalize_url(base_url, link))]

