from __future__ import annotations

import ipaddress
from typing import Any


def build_bgp_prefix_cidr(raw_prefix: Any, raw_length: Any = None) -> str:
    prefix_text = str(raw_prefix).strip()
    if not prefix_text:
        raise ValueError("Prefixo BGP vazio.")

    if "/" in prefix_text and raw_length in {None, ""}:
        network = ipaddress.ip_network(prefix_text, strict=False)
        return str(network)

    if raw_length in {None, ""}:
        raise ValueError("Prefix length ausente para prefixo BGP.")

    try:
        length = int(str(raw_length).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError("Prefix length inválido.") from exc

    try:
        network = ipaddress.ip_network(f"{prefix_text}/{length}", strict=False)
    except ValueError as exc:
        raise ValueError("Prefixo BGP inválido.") from exc

    max_prefixlen = network.max_prefixlen
    if length < 0 or length > max_prefixlen:
        raise ValueError("Prefix length fora do intervalo suportado.")

    return str(network)
