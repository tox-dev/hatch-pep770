"""Check and percent-encode IRI references, as the CycloneDX schema expects them."""

from __future__ import annotations

import ipaddress
import re
import string
from typing import Final, cast
from urllib.parse import quote

# RFC 3986 appendix B: splits any text into scheme, authority, path, query and fragment
_PARTS: Final[re.Pattern[str]] = re.compile(
    r"(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?", re.DOTALL
)
_SCHEME: Final[re.Pattern[str]] = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*")
# what may follow the host: nothing, or a colon and the port's digits
_PORT: Final[re.Pattern[str]] = re.compile(r"(?::[0-9]*)?")
_IP_FUTURE: Final[re.Pattern[str]] = re.compile(r"v[0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+")
# a valid percent-encoding, or any one character
_TOKEN: Final[re.Pattern[str]] = re.compile(r"%[0-9A-Fa-f]{2}|.", re.DOTALL)
_REG_NAME: Final[str] = f"{string.ascii_letters}{string.digits}-._~!$&'()*+,;="
_USERINFO: Final[str] = f"{_REG_NAME}:"
_PATH: Final[str] = f"{_USERINFO}@/"
# the query and the fragment allow the same characters
_QUERY: Final[str] = f"{_PATH}?"
# the characters beyond ASCII an IRI holds unencoded, RFC 3987's ucschar
_UCSCHAR: Final[tuple[tuple[int, int], ...]] = (
    (0xA0, 0xD7FF),
    (0xF900, 0xFDCF),
    (0xFDF0, 0xFFEF),
    *((plane << 16, plane << 16 | 0xFFFD) for plane in range(1, 14)),
    (0xE1000, 0xEFFFD),
)


def iri_reference(text: str) -> str | None:
    # the form CycloneDX requires of a URL: a character no part of an IRI reference allows is percent-encoded, which
    # keeps what the text points at; a scheme, IP literal or port no encoding mends, as in the scp-style
    # git@github.com:org/repo.git, leaves None; the pattern matches any text, every part of it optional
    match: Final = cast("re.Match[str]", _PARTS.fullmatch(text))
    scheme, authority, path, query, fragment = match.groups()
    if scheme is not None and not _SCHEME.fullmatch(scheme):
        return None
    parts: Final[list[str]] = [] if scheme is None else [f"{scheme}:"]
    if authority is not None:
        if (encoded := _authority(authority)) is None:
            return None
        parts.append(f"//{encoded}")
    parts.append(_encoded(path, _PATH))
    if query is not None:
        parts.append(f"?{_encoded(query, _QUERY)}")
    if fragment is not None:
        parts.append(f"#{_encoded(fragment, _QUERY)}")
    return "".join(parts)


def _authority(authority: str) -> str | None:
    userinfo, at, host_port = authority.rpartition("@")
    if host_port.startswith("["):
        literal, _, port = host_port[1:].partition("]")
        if not _ip_literal(literal):
            return None
        host = f"[{literal}]"
    else:
        name, colon, number = host_port.partition(":")
        host, port = _encoded(name, _REG_NAME), f"{colon}{number}"
    if not _PORT.fullmatch(port):
        return None
    return f"{_encoded(userinfo, _USERINFO)}{at}{host}{port}"


def _ip_literal(literal: str) -> bool:
    if _IP_FUTURE.fullmatch(literal):
        return True
    # a zone index has no place in a URI's IP literal
    if "%" in literal:
        return False
    try:
        ipaddress.IPv6Address(literal)
    except ValueError:
        return False
    return True


def _encoded(text: str, allowed: str) -> str:
    return "".join(token if _kept(token, allowed) else quote(token, safe="") for token in _TOKEN.findall(text))


def _kept(token: str, allowed: str) -> bool:
    # a token longer than a character is a valid percent-encoding
    if len(token) > 1 or token in allowed:
        return True
    return any(low <= ord(token) <= high for low, high in _UCSCHAR)


__all__ = [
    "iri_reference",
]
