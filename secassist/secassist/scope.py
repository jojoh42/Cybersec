"""Scope-Datei laden und prüfen, ob ein Ziel getestet werden darf.

Alles, was nicht ausdrücklich erlaubt ist, ist verboten (Default-Deny).
"""
from __future__ import annotations

import fnmatch
import ipaddress
import os
from dataclasses import dataclass, field
from datetime import date
from urllib.parse import urlparse

import yaml


class ScopeError(Exception):
    """Ziel liegt außerhalb des freigegebenen Scopes."""


@dataclass
class Scope:
    engagement: str
    client: str
    authorized_by: str
    valid_until: date | None
    hosts: list[str] = field(default_factory=list)          # exakte Hosts oder *.domain.de
    networks: list[ipaddress._BaseNetwork] = field(default_factory=list)
    exclude_hosts: list[str] = field(default_factory=list)
    exclude_networks: list[ipaddress._BaseNetwork] = field(default_factory=list)
    code_paths: list[str] = field(default_factory=list)
    max_requests_per_second: int = 10

    # ------------------------------------------------------------------ laden
    @classmethod
    def load(cls, path: str) -> "Scope":
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        for key in ("engagement", "client", "authorized_by"):
            if not raw.get(key):
                raise ScopeError(f"Scope-Datei: Pflichtfeld '{key}' fehlt")
        valid_until = raw.get("valid_until")
        if isinstance(valid_until, str):
            valid_until = date.fromisoformat(valid_until)
        targets = raw.get("targets", {}) or {}
        exclude = raw.get("exclude", {}) or {}
        base = os.path.dirname(os.path.abspath(path))
        return cls(
            engagement=raw["engagement"],
            client=raw["client"],
            authorized_by=raw["authorized_by"],
            valid_until=valid_until,
            hosts=[h.lower().strip() for h in targets.get("hosts", []) or []],
            networks=[ipaddress.ip_network(n, strict=False) for n in targets.get("networks", []) or []],
            exclude_hosts=[h.lower().strip() for h in exclude.get("hosts", []) or []],
            exclude_networks=[ipaddress.ip_network(n, strict=False) for n in exclude.get("networks", []) or []],
            code_paths=[os.path.realpath(os.path.join(base, p)) for p in targets.get("code_paths", []) or []],
            max_requests_per_second=int(raw.get("max_requests_per_second", 10)),
        )

    # ---------------------------------------------------------------- prüfen
    def check_valid(self) -> None:
        if self.valid_until and date.today() > self.valid_until:
            raise ScopeError(f"Freigabe für '{self.engagement}' ist am {self.valid_until} abgelaufen")

    @staticmethod
    def _host_of(target: str) -> str:
        target = target.strip()
        if "://" in target:
            host = urlparse(target).hostname or ""
        else:
            host = target.split("/")[0]
            if host.count(":") == 1:          # host:port (kein IPv6)
                host = host.split(":")[0]
        return host.strip("[]").lower()

    @staticmethod
    def _match_host(host: str, patterns: list[str]) -> bool:
        for p in patterns:
            if p.startswith("*."):
                if host == p[2:] or host.endswith(p[1:]):
                    return True
            elif fnmatch.fnmatchcase(host, p):
                return True
        return False

    def check_target(self, target: str) -> str:
        """Gibt den normalisierten Host zurück oder wirft ScopeError."""
        self.check_valid()
        host = self._host_of(target)
        if not host:
            raise ScopeError(f"Kein Host in '{target}' erkennbar")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None:
            if any(ip in n for n in self.exclude_networks):
                raise ScopeError(f"{host} ist ausdrücklich ausgeschlossen")
            if any(ip in n for n in self.networks):
                return host
            raise ScopeError(f"{host} liegt in keinem freigegebenen Netz")
        if self._match_host(host, self.exclude_hosts):
            raise ScopeError(f"{host} ist ausdrücklich ausgeschlossen")
        if self._match_host(host, self.hosts):
            return host
        raise ScopeError(f"{host} ist nicht im Scope")

    def check_network(self, cidr: str) -> str:
        """Ein ganzes Netz darf nur gescannt werden, wenn es komplett in einem freigegebenen Netz liegt."""
        self.check_valid()
        net = ipaddress.ip_network(cidr, strict=False)
        if net.num_addresses == 1:
            return self.check_target(str(net.network_address))
        if any(net.overlaps(n) for n in self.exclude_networks):
            raise ScopeError(f"{cidr} überschneidet sich mit einem ausgeschlossenen Netz")
        if any(net.subnet_of(n) for n in self.networks if n.version == net.version):
            return str(net)
        raise ScopeError(f"{cidr} liegt nicht vollständig in einem freigegebenen Netz")

    def check_path(self, path: str) -> str:
        """Code-Pfad muss innerhalb eines freigegebenen Verzeichnisses liegen (Symlinks aufgelöst)."""
        real = os.path.realpath(path)
        for allowed in self.code_paths:
            if real == allowed or real.startswith(allowed + os.sep):
                return real
        raise ScopeError(f"Pfad {path} ist nicht freigegeben")

    def summary(self) -> str:
        return (
            f"Engagement: {self.engagement} | Kunde: {self.client} | freigegeben von: {self.authorized_by}"
            f" | gültig bis: {self.valid_until or 'unbegrenzt'}\n"
            f"Hosts: {', '.join(self.hosts) or '-'}\n"
            f"Netze: {', '.join(map(str, self.networks)) or '-'}\n"
            f"Ausgeschlossen: {', '.join(self.exclude_hosts + [str(n) for n in self.exclude_networks]) or '-'}\n"
            f"Code-Pfade: {', '.join(self.code_paths) or '-'}\n"
            f"Max. Requests/s: {self.max_requests_per_second}"
        )
