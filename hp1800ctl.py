#!/usr/bin/env python3
"""
hp1800ctl.py - HP ProCurve 1800-24G (J9028B) PB.03.10 management client

v0.3.1 adds resilient post-reset/read behavior for the PB.03.10 support-report
endpoint, which can reset TCP connections while the switch is otherwise healthy.
YAML desired-state export/import, bulk planning/apply, and guarded reset remain.
The read-side model and tested backup/snapshot workflow from v0.2 are preserved.

Observed/tested management surface:
  * login via POST /login.html
  * dynamic per-page ?session= form actions
  * binary configuration download (/system/cfgdownload.htm)
  * text support reports (/system/loadsupport.html)
  * system identity form
  * read-side HTML state for ports, VLANs, trunks, LACP, and mirroring

Writes are based only on web forms captured from the live J9028B/PB.03.10 UI.
Management-IP mutation and binary switch.cfg upload remain intentionally
unsupported until their exact POST workflows are captured and validated.

Dependencies:
    python3 -m pip install --user requests PyYAML

Examples:
    ./hp1800ctl.py --url http://192.168.2.10 status
    ./hp1800ctl.py --url http://192.168.2.10 ports
    ./hp1800ctl.py --url http://192.168.2.10 vlans
    ./hp1800ctl.py --url http://192.168.2.10 trunks
    ./hp1800ctl.py --url http://192.168.2.10 lacp
    ./hp1800ctl.py --url http://192.168.2.10 mirror
    ./hp1800ctl.py --url http://192.168.2.10 show
    ./hp1800ctl.py --url http://192.168.2.10 snapshot

Password:
    By default the client uses HP1800_PASSWORD if set, otherwise a blank
    password. Use --prompt-password to enter one interactively.
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import html as html_lib
from html.parser import HTMLParser
import json
import os
import random
from pathlib import Path
import re
import sys
import time
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

try:
    import requests
    import yaml
except ImportError:
    print(
        "ERROR: missing dependency: requests and/or PyYAML.\n"
        "Install them with:\n"
        "  python3 -m pip install --user requests PyYAML",
        file=sys.stderr,
    )
    raise SystemExit(2)


VERSION = "0.3.8"
DEFAULT_URL = "http://192.168.2.10"
FACTORY_URL = "http://192.168.2.10"
FACTORY_ADDRESS = "192.168.2.10"
FACTORY_NETMASK = "255.255.255.0"
DEFAULT_TIMEOUT = 10.0

SUPPORT_REPORTS = {
    "general": "0",
    "vlan": "1",
    "stats": "2",
    "protocol": "3",
}

SPEED_DUPLEX = {
    "0": "10FDX",
    "1": "100FDX",
    "2": "1000FDX",
    "3": "Auto",
    "4": "10HDX",
    "5": "100HDX",
}

SPEED_DUPLEX_REVERSE = {v.lower(): k for k, v in SPEED_DUPLEX.items()}

TRUNK_HASH_FALLBACK = {
    0: "SMAC XOR DMAC XOR IP-Info",
    1: "SMAC",
    2: "DMAC",
    3: "SMAC XOR DMAC",
    4: "Pseudo-randomized",
    5: "IP-Info",
}


class HP1800Error(RuntimeError):
    pass


class FormActionParser(HTMLParser):
    """Extract the action from a named HTML form."""

    def __init__(self, wanted_name: str = "tF"):
        super().__init__(convert_charrefs=True)
        self.wanted_name = wanted_name
        self.action: Optional[str] = None

    def handle_starttag(self, tag, attrs):
        if self.action is not None or tag.lower() != "form":
            return
        d = {str(k).lower(): v for k, v in attrs}
        if d.get("name") == self.wanted_name or d.get("id") == self.wanted_name:
            self.action = d.get("action")


def form_action(page_html: str, page_url: str, form_name: str = "tF") -> str:
    parser = FormActionParser(form_name)
    parser.feed(page_html)
    if not parser.action:
        raise HP1800Error(
            f"Could not find form {form_name!r}; refusing to guess a session URL."
        )
    return urljoin(page_url, html_lib.unescape(parser.action))


def _js_string(page_html: str, variable: str, *, last: bool = False) -> Optional[str]:
    pattern = rf'\bvar\s+{re.escape(variable)}\s*=\s*"((?:\\.|[^"])*)"\s*;?'
    matches = list(re.finditer(pattern, page_html, flags=re.S))
    if not matches:
        return None
    raw = (matches[-1] if last else matches[0]).group(1)
    try:
        return bytes(raw, "utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return raw


def _js_scalar(page_html: str, variable: str, *, last: bool = True) -> Optional[str]:
    pattern = rf'\bvar\s+{re.escape(variable)}\s*=\s*([^;\r\n]+)\s*;?'
    matches = list(re.finditer(pattern, page_html, flags=re.S))
    if not matches:
        return None
    value = (matches[-1] if last else matches[0]).group(1).strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    return value.strip()


def _parse_js_token(token: str) -> Any:
    token = token.strip()
    if not token:
        return ""
    if len(token) >= 2 and token[0] == token[-1] == '"':
        raw = token[1:-1]
        try:
            return bytes(raw, "utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            return raw
    if token.lower() == "true":
        return True
    if token.lower() == "false":
        return False
    if re.fullmatch(r"-?\d+", token):
        return int(token)
    return token


def _split_js_array(body: str) -> list[Any]:
    """Parse the primitive new Array(...) values emitted by PB.03.10."""
    tokens: list[str] = []
    buf: list[str] = []
    in_quote = False
    escaped = False
    for ch in body:
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\" and in_quote:
            buf.append(ch)
            escaped = True
            continue
        if ch == '"':
            buf.append(ch)
            in_quote = not in_quote
            continue
        if ch == "," and not in_quote:
            tokens.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if buf or body.endswith(","):
        tokens.append("".join(buf))
    return [_parse_js_token(t) for t in tokens]


def _js_array(page_html: str, variable: str, *, last: bool = True) -> list[Any]:
    # PB.03.10 omits semicolons on several declarations, so anchor to the
    # matching ')' rather than requiring ');'. Values observed are primitive.
    pattern = rf'\bvar\s+{re.escape(variable)}\s*=\s*new\s+Array\((.*?)\)\s*;?'
    matches = list(re.finditer(pattern, page_html, flags=re.S))
    if not matches:
        return []
    body = (matches[-1] if last else matches[0]).group(1)
    # A firmware page contains one malformed-looking duplicate with a trailing
    # quote after the final numeric element. Strip that harmless artifact.
    body = re.sub(r'\)"\s*$', ')', body.strip())
    return _split_js_array(body)


def _int_or_none(value: Any) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _bool_checked(value: Any) -> bool:
    return str(value).strip().lower() == "checked"


def parse_system_identity(page_html: str) -> dict:
    return {
        "name": _js_string(page_html, "titleStr"),
        "contact": _js_string(page_html, "c"),
        "location": _js_string(page_html, "l"),
    }


def parse_port_config(page_html: str) -> dict:
    trunk = _js_array(page_html, "portTrunkArray")
    fc_disabled = _js_array(page_html, "fcDisabledArray")
    fc_checked = _js_array(page_html, "fcCheckedArray")
    speeds = _js_array(page_html, "spdDupArray")
    sfp = _js_array(page_html, "sfpOnArray")
    num_ports = _int_or_none(_js_scalar(page_html, "numPorts")) or max(
        len(speeds), len(trunk), 24
    )
    jumbo = (_js_string(page_html, "jumbo_checked") or "").strip() == "checked"

    ports = []
    for i in range(num_ports):
        speed_code = str(speeds[i]) if i < len(speeds) else None
        ports.append(
            {
                "port": i + 1,
                "speed_duplex_code": speed_code,
                "configured_speed_duplex": SPEED_DUPLEX.get(speed_code, speed_code),
                "flow_control": _bool_checked(fc_checked[i]) if i < len(fc_checked) else None,
                "config_locked": bool(str(fc_disabled[i]).strip()) if i < len(fc_disabled) else None,
                "trunk": None
                if i >= len(trunk) or html_lib.unescape(str(trunk[i])).strip() in ("", "\xa0", "&nbsp;")
                else html_lib.unescape(str(trunk[i])).strip(),
                "sfp_active": str(sfp[i]).strip() == "1" if i < len(sfp) else None,
            }
        )
    return {"jumbo_frames": jumbo, "ports": ports}


def parse_mirror(page_html: str) -> dict:
    port = _int_or_none(_js_string(page_html, "mirrorPort", last=True))
    enabled = _js_array(page_html, "mirrorEnabled", last=True)
    sources = [i + 1 for i, value in enumerate(enabled) if _int_or_none(value) == 1]
    return {"destination": port, "sources": sources}


def parse_trunks(page_html: str) -> dict:
    assignments = _js_array(page_html, "ptArray", last=True)
    mode = _int_or_none(_js_scalar(page_html, "aggr_mode", last=True))
    hash_names = _js_array(page_html, "aggr", last=True)
    if hash_names and mode is not None and 0 <= mode < len(hash_names):
        hash_name = str(hash_names[mode])
    else:
        hash_name = TRUNK_HASH_FALLBACK.get(mode)

    groups: dict[str, list[int]] = {}
    for idx, value in enumerate(assignments):
        trunk_id = _int_or_none(value)
        if trunk_id and trunk_id > 0:
            groups.setdefault(f"T{trunk_id}", []).append(idx + 1)

    return {
        "hash_mode": mode,
        "hash_algorithm": hash_name,
        "groups": [
            {"name": name, "members": members}
            for name, members in sorted(
                groups.items(), key=lambda kv: int(kv[0].lstrip("T") or 0)
            )
        ],
    }


def parse_lacp(page_html: str) -> dict:
    enabled = _js_array(page_html, "proenb", last=True)
    keys = _js_array(page_html, "key", last=True)
    allowed = _js_array(page_html, "noStaticAggr", last=True)
    count = max(len(enabled), len(keys), len(allowed), 24)

    ports = []
    for i in range(count):
        is_enabled = _bool_checked(enabled[i]) if i < len(enabled) else False
        key = _int_or_none(keys[i]) if i < len(keys) else None
        configurable = str(allowed[i]).strip() != "0" if i < len(allowed) else True
        ports.append(
            {
                "port": i + 1,
                "enabled": is_enabled,
                "key": key,
                "key_mode": "auto" if key == 0 else ("manual" if key is not None else None),
                "configurable": configurable,
            }
        )

    return {
        "enabled_ports": [p["port"] for p in ports if p["enabled"]],
        "ports": ports,
    }


def _interface_label(index: int, number_of_ports: int, trunk_no: int) -> str:
    if index < number_of_ports:
        return f"Port {index + 1}"
    if index < number_of_ports + trunk_no:
        return f"Trunk {index - number_of_ports + 1}"
    return f"LACP {index - number_of_ports - trunk_no + 1}"


def parse_vlan_state(page_html: str, vlan_list_html: Optional[str] = None) -> dict:
    vids = [_int_or_none(v) for v in _js_array(page_html, "Vids")]
    vids = [v for v in vids if v is not None]
    vlan_aware = _js_array(page_html, "VlanAware")
    ingress = _js_array(page_html, "ingr")
    frame_type = _js_array(page_html, "FrameType")
    pvids = _js_array(page_html, "Pvid")
    masks = _js_array(page_html, "VidMasks")

    nports = _int_or_none(_js_scalar(page_html, "number_of_ports")) or 24
    ntrunks = _int_or_none(_js_scalar(page_html, "trunNo")) or 12
    nlacps = _int_or_none(_js_scalar(page_html, "nlacps")) or 24
    total = nports + ntrunks + nlacps

    management_vid = None
    if vlan_list_html:
        mgmt_idx = _int_or_none(_js_scalar(vlan_list_html, "mgmt_idx", last=True))
        if mgmt_idx is not None and 0 <= mgmt_idx < len(vids):
            management_vid = vids[mgmt_idx]

    interfaces = []
    for i in range(total):
        aware_raw = vlan_aware[i] if i < len(vlan_aware) else "disabled"
        ingress_raw = ingress[i] if i < len(ingress) else "disabled"
        frame_raw = frame_type[i] if i < len(frame_type) else "disabled"
        pvid_raw = pvids[i] if i < len(pvids) else "disabled"
        mask_raw = masks[i] if i < len(masks) else 0
        mask = _int_or_none(mask_raw) or 0

        memberships = [vid for bit, vid in enumerate(vids) if mask & (1 << bit)]
        configurable = str(aware_raw).strip().lower() != "disabled"
        if str(frame_raw).strip().lower() == "disabled":
            packet_type = "disabled"
        elif str(frame_raw).strip() == "0":
            packet_type = "all"
        elif str(frame_raw).strip() == "1":
            packet_type = "tagged_only"
        else:
            packet_type = str(frame_raw).strip()

        pvid = _int_or_none(pvid_raw)
        if pvid == 0:
            pvid = None

        interfaces.append(
            {
                "name": _interface_label(i, nports, ntrunks),
                "type": "port" if i < nports else ("trunk" if i < nports + ntrunks else "lacp"),
                "number": i + 1 if i < nports else (
                    i - nports + 1 if i < nports + ntrunks else i - nports - ntrunks + 1
                ),
                "configurable": configurable,
                "vlan_aware": _bool_checked(aware_raw) if configurable else None,
                "ingress_filtering": _bool_checked(ingress_raw)
                if str(ingress_raw).strip().lower() != "disabled"
                else None,
                "packet_type": packet_type,
                "pvid": pvid,
                "vlans": memberships,
            }
        )

    vlans = []
    for vid in vids:
        active = [i for i in interfaces if vid in i["vlans"] and i["configurable"]]
        disabled = [i for i in interfaces if vid in i["vlans"] and not i["configurable"]]
        vlans.append(
            {
                "vid": vid,
                "management": vid == management_vid if management_vid is not None else None,
                "members": [i["name"] for i in active],
                "disabled_members": [i["name"] for i in disabled],
                "pvid_interfaces": [i["name"] for i in interfaces if i["pvid"] == vid],
            }
        )

    return {
        "management_vid": management_vid,
        "vids": vids,
        "vlans": vlans,
        "interfaces": interfaces,
    }


def parse_general_report(text: str) -> dict:
    """Parse switchgeneral.txt into a conservative normalized structure."""
    out: dict[str, Any] = {
        "system": {},
        "management": {},
        "ports": [],
        "aggregation": {},
        "mirror": {"destination": None, "sources": []},
    }

    def section_block(start_heading: str, next_headings: tuple[str, ...]) -> str:
        start_match = re.search(
            rf'(?m)^\s*{re.escape(start_heading)}\s*$', text
        )
        if not start_match:
            return ""
        start_pos = start_match.end()
        end_pos = len(text)
        for heading in next_headings:
            hm = re.search(
                rf'(?m)^\s*{re.escape(heading)}\s*$',
                text[start_pos:],
            )
            if hm:
                end_pos = min(end_pos, start_pos + hm.start())
        return text[start_pos:end_pos]

    def block_field(block: str, name: str) -> Optional[str]:
        fm = re.search(
            rf'(?m)^\s*{re.escape(name)}:\s*(.*?)\s*$',
            block,
        )
        return fm.group(1) if fm else None

    system_block = section_block(
        "System Configuration:",
        ("IP Configuration:", "Port Configuration:", "Aggr Configuration:", "Mirror Configuration:"),
    )
    system_map = {
        "name": "Name",
        "software_version": "S/W Version",
        "compile_date": "Compile Date",
        "hardware_version": "H/W Version",
        "mac_address": "MAC address",
        "snmp": "SNMP",
        "trap_ip": "Trap IP",
    }
    for key, label in system_map.items():
        value = block_field(system_block, label)
        if value is not None:
            if key == "snmp":
                value = value.strip().lower() == "enabled"
            out["system"][key] = value

    mgmt_block = section_block(
        "IP Configuration:",
        ("Port Configuration:", "Aggr Configuration:", "Mirror Configuration:"),
    )
    mgmt_map = {
        "address": "Address",
        "subnet_mask": "Subnet Mask",
        "gateway": "Gateway",
        "vid": "VID",
        "mode": "Mode",
        "dhcp": "dhcp",
    }
    for key, label in mgmt_map.items():
        value = block_field(mgmt_block, label)
        if value is not None:
            if key == "vid":
                value = _int_or_none(value)
            elif key == "dhcp":
                value = value.strip().lower() == "enabled"
            out["management"][key] = value

    port_block = section_block(
        "Port Configuration:",
        ("Aggr Configuration:", "Operational Status", "Mirror Configuration:"),
    )
    port_re = re.compile(
        r'^\s*(\d+):\s+(enabled|disabled)\s+(\S+)\s+(enabled|disabled)\s+(\S+)\s+(\d+)\s*$',
        flags=re.M | re.I,
    )
    for m in port_re.finditer(port_block):
        out["ports"].append(
            {
                "port": int(m.group(1)),
                "state": m.group(2).lower(),
                "mode": m.group(3),
                "flow_control": m.group(4).lower() == "enabled",
                "link": m.group(5),
                "max_frame": int(m.group(6)),
            }
        )

    aggr_block = section_block(
        "Aggr Configuration:",
        ("Operational Status", "Mirror Configuration:"),
    )
    if aggr_block:
        group_match = re.search(r'(?m)^\s*Groups:\s*$\n\s*([^\r\n]+)', aggr_block)
        mode_match = re.search(r'(?m)^\s*Mode:\s*(\S+)\s*$', aggr_block)
        if group_match:
            raw = group_match.group(1).strip()
            if raw.lower() != "none":
                out["aggregation"]["members"] = [
                    int(x) for x in re.findall(r'\d+', raw)
                ]
            else:
                out["aggregation"]["members"] = []
        if mode_match:
            out["aggregation"]["mode"] = mode_match.group(1)

    mirror_block = section_block("Mirror Configuration:", ())
    if mirror_block:
        dm = re.search(r'(?m)^\s*Mirror Port:\s*(\d+)\s*$', mirror_block)
        if dm:
            out["mirror"]["destination"] = int(dm.group(1))
        for pm in re.finditer(
            r'(?m)^\s*Port\s+(\d+):\s+(enabled|disabled)\s*$',
            mirror_block,
            re.I,
        ):
            if pm.group(2).lower() == "enabled":
                out["mirror"]["sources"].append(int(pm.group(1)))

    return out

def filename_from_content_disposition(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    m = re.search(r'filename\s*=\s*"?([^";]+)"?', value, flags=re.I)
    if not m:
        return None
    return Path(m.group(1).strip()).name


CONFIG_SCHEMA = "hp1800ctl.config.v1"
STATE_SCHEMA = "hp1800ctl.state.v1"


def dump_data(value: Any, fmt: str = "yaml") -> str:
    if fmt == "json":
        return json.dumps(value, indent=2, sort_keys=False) + "\n"
    return yaml.safe_dump(value, sort_keys=False, default_flow_style=False)


def load_yaml_file(path: Path) -> dict:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise HP1800Error(f"Could not load YAML {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise HP1800Error("Configuration YAML must contain a mapping at the top level.")
    return data


def write_data_file(value: Any, output: Path, fmt: str = "yaml") -> Path:
    dest = Path(output).expanduser()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(dump_data(value, fmt), encoding="utf-8")
    return dest


def _norm_int_key_map(value: Any) -> dict[int, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise HP1800Error("Expected a mapping keyed by integer-like values.")
    out: dict[int, Any] = {}
    for k, v in value.items():
        try:
            out[int(k)] = v
        except (TypeError, ValueError) as exc:
            raise HP1800Error(f"Expected integer-like key, got {k!r}.") from exc
    return out


def state_to_config(state: dict) -> dict:
    ports = {}
    for row in state.get("ports", {}).get("ports", []):
        ports[int(row["port"])] = {
            "speed_duplex": row.get("configured_speed_duplex"),
            "flow_control": bool(row.get("flow_control")),
        }

    vlan_items = {}
    for vlan in state.get("vlans", {}).get("vlans", []):
        vlan_items[int(vlan["vid"])] = {
            "management": bool(vlan.get("management")) if vlan.get("management") is not None else False,
            "members": list(vlan.get("members", [])),
        }

    vlan_interfaces = {}
    for iface in state.get("vlans", {}).get("interfaces", []):
        if not iface.get("configurable"):
            continue
        vlan_interfaces[iface["name"]] = {
            "vlan_aware": bool(iface.get("vlan_aware")),
            "ingress_filtering": bool(iface.get("ingress_filtering")),
            "packet_type": iface.get("packet_type"),
            "pvid": iface.get("pvid"),
        }

    trunk_groups = {
        row["name"]: list(row.get("members", []))
        for row in state.get("trunks", {}).get("groups", [])
    }

    lacp_ports = {}
    for row in state.get("lacp", {}).get("ports", []):
        lacp_ports[int(row["port"])] = {
            "enabled": bool(row.get("enabled")),
            "key": "auto" if row.get("key") == 0 else row.get("key"),
        }

    device = state.get("device", {})
    mgmt = dict(state.get("management", {}))
    return {
        "schema": CONFIG_SCHEMA,
        "metadata": {
            "exported_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "source_url": device.get("url"),
            "model": "J9028B",
            "firmware": device.get("software_version"),
        },
        "system": {
            "name": device.get("name", ""),
            "location": device.get("location", ""),
            "contact": device.get("contact", ""),
        },
        "management": {
            "address": mgmt.get("address"),
            "subnet_mask": mgmt.get("subnet_mask"),
            "gateway": mgmt.get("gateway"),
            "vid": mgmt.get("vid"),
            "dhcp": bool(mgmt.get("dhcp")),
        },
        "ports": {
            "jumbo_frames": bool(state.get("ports", {}).get("jumbo_frames")),
            "settings": ports,
        },
        "trunks": {
            "hash_mode": state.get("trunks", {}).get("hash_mode"),
            "groups": trunk_groups,
        },
        "lacp": {"ports": lacp_ports},
        "vlans": {
            "prune": False,
            "items": vlan_items,
        },
        "vlan_interfaces": vlan_interfaces,
        "mirror": {
            "destination": state.get("mirror", {}).get("destination"),
            "sources": list(state.get("mirror", {}).get("sources", [])),
        },
    }


def interface_name_to_index(name: str, nports: int = 24, ntrunks: int = 12, nlacps: int = 24) -> int:
    m = re.fullmatch(r"\s*(Port|Trunk|LACP)\s+(\d+)\s*", str(name), flags=re.I)
    if not m:
        raise HP1800Error(f"Invalid interface label {name!r}; expected 'Port N', 'Trunk N', or 'LACP N'.")
    kind = m.group(1).lower()
    number = int(m.group(2))
    if kind == "port":
        if not 1 <= number <= nports:
            raise HP1800Error(f"Port number out of range: {number}")
        return number - 1
    if kind == "trunk":
        if not 1 <= number <= ntrunks:
            raise HP1800Error(f"Trunk number out of range: {number}")
        return nports + number - 1
    if not 1 <= number <= nlacps:
        raise HP1800Error(f"LACP number out of range: {number}")
    return nports + ntrunks + number - 1


def _canonical_speed(value: Any) -> str:
    if value is None:
        raise HP1800Error("speed_duplex cannot be null")
    text = str(value).strip()
    if text in SPEED_DUPLEX:
        return SPEED_DUPLEX[text]
    code = SPEED_DUPLEX_REVERSE.get(text.lower())
    if code is None:
        raise HP1800Error(
            f"Unsupported speed_duplex {value!r}; choose Auto, 10HDX, 10FDX, 100HDX, 100FDX, or 1000FDX."
        )
    return SPEED_DUPLEX[code]


def _speed_code(value: Any) -> str:
    canonical = _canonical_speed(value)
    return SPEED_DUPLEX_REVERSE[canonical.lower()]


def validate_config_document(doc: dict) -> None:
    if not isinstance(doc, dict):
        raise HP1800Error("Configuration document must be a mapping.")
    section_names = ("metadata", "system", "management", "ports", "trunks", "lacp", "vlans", "vlan_interfaces", "mirror")
    for section_name in section_names:
        section = doc.get(section_name)
        if section is not None and not isinstance(section, dict):
            raise HP1800Error(f"Configuration section {section_name!r} must be a mapping.")
    if doc.get("schema") != CONFIG_SCHEMA:
        raise HP1800Error(
            f"Unsupported or missing schema {doc.get('schema')!r}; expected {CONFIG_SCHEMA!r}."
        )
    metadata = doc.get("metadata") or {}
    model = metadata.get("model")
    if model not in (None, "J9028B"):
        raise HP1800Error(f"Configuration targets model {model!r}, not J9028B.")

    for section_name in ("system", "management"):
        section = doc.get(section_name) or {}
        for key, value in section.items():
            if value is not None and not isinstance(value, (str, int, float, bool)):
                raise HP1800Error(f"{section_name}.{key} must be a scalar value.")

    ports_section = doc.get("ports") or {}
    if "jumbo_frames" in ports_section and not isinstance(ports_section["jumbo_frames"], bool):
        raise HP1800Error("ports.jumbo_frames must be true or false.")
    ports = ports_section.get("settings") or {}
    for port, cfg in _norm_int_key_map(ports).items():
        if not 1 <= port <= 24:
            raise HP1800Error(f"Port {port} is outside 1..24.")
        if not isinstance(cfg, dict):
            raise HP1800Error(f"Port {port} settings must be a mapping.")
        if "speed_duplex" in cfg:
            _canonical_speed(cfg["speed_duplex"])
        if "flow_control" in cfg and not isinstance(cfg["flow_control"], bool):
            raise HP1800Error(f"Port {port} flow_control must be true or false.")

    trunks = doc.get("trunks") or {}
    for key in ("groups",):
        if key in trunks and trunks[key] is not None and not isinstance(trunks[key], dict):
            raise HP1800Error(f"trunks.{key} must be a mapping.")
    if "hash_mode" in trunks and trunks.get("hash_mode") is not None:
        hm = int(trunks["hash_mode"])
        if hm not in TRUNK_HASH_FALLBACK:
            raise HP1800Error(f"Invalid trunk hash_mode {hm}; expected 0..5.")
    groups = trunks.get("groups") or {}
    seen_ports: set[int] = set()
    for name, members in groups.items():
        m = re.fullmatch(r"T(\d+)", str(name), flags=re.I)
        if not m or not 1 <= int(m.group(1)) <= 12:
            raise HP1800Error(f"Invalid static trunk name {name!r}; expected T1..T12.")
        if not isinstance(members, list):
            raise HP1800Error(f"Static trunk {name} members must be a list.")
        for port in members:
            port = int(port)
            if not 1 <= port <= 24:
                raise HP1800Error(f"Static trunk {name} contains invalid port {port}.")
            if port in seen_ports:
                raise HP1800Error(f"Port {port} appears in more than one static trunk.")
            seen_ports.add(port)

    lacp_section = doc.get("lacp") or {}
    if lacp_section.get("ports") is not None and not isinstance(lacp_section["ports"], dict):
        raise HP1800Error("lacp.ports must be a mapping.")
    lacp = _norm_int_key_map(lacp_section.get("ports") or {})
    for port, cfg in lacp.items():
        if not 1 <= port <= 24:
            raise HP1800Error(f"LACP port {port} is outside 1..24.")
        if not isinstance(cfg, dict):
            raise HP1800Error(f"LACP port {port} settings must be a mapping.")
        if "enabled" in cfg and not isinstance(cfg["enabled"], bool):
            raise HP1800Error(f"LACP port {port} enabled must be true or false.")
        key = cfg.get("key", "auto")
        if key != "auto":
            try:
                key_i = int(key)
            except (TypeError, ValueError) as exc:
                raise HP1800Error(f"LACP port {port} key must be 'auto' or an integer.") from exc
            if not 0 <= key_i <= 65535:
                raise HP1800Error(f"LACP port {port} key {key_i} is outside 0..65535.")

    vlan_section = doc.get("vlans") or {}
    if vlan_section.get("items") is not None and not isinstance(vlan_section["items"], dict):
        raise HP1800Error("vlans.items must be a mapping.")
    vlan_items = _norm_int_key_map(vlan_section.get("items") or {})
    for vid, cfg in vlan_items.items():
        if not 1 <= vid <= 4094:
            raise HP1800Error(f"VLAN {vid} is outside 1..4094.")
        if not isinstance(cfg, dict):
            raise HP1800Error(f"VLAN {vid} settings must be a mapping.")
        if "management" in cfg and not isinstance(cfg["management"], bool):
            raise HP1800Error(f"VLAN {vid} management must be true or false.")
        if "members" in cfg and not isinstance(cfg["members"], list):
            raise HP1800Error(f"VLAN {vid} members must be a list.")
        for member in cfg.get("members", []) or []:
            interface_name_to_index(str(member))

    if (doc.get("vlans") or {}).get("prune"):
        raise HP1800Error(
            "vlans.prune=true is intentionally disabled in v0.3; delete VLANs explicitly after validating PVID/management dependencies."
        )

    if vlan_section.get("prune") is not None and not isinstance(vlan_section["prune"], bool):
        raise HP1800Error("vlans.prune must be true or false.")

    for name, cfg in (doc.get("vlan_interfaces") or {}).items():
        interface_name_to_index(str(name))
        if not isinstance(cfg, dict):
            raise HP1800Error(f"VLAN interface {name!r} must be a mapping.")
        if cfg.get("packet_type") not in (None, "all", "tagged_only"):
            raise HP1800Error(f"{name}: packet_type must be all or tagged_only.")
        for flag in ("vlan_aware", "ingress_filtering"):
            if flag in cfg and not isinstance(cfg[flag], bool):
                raise HP1800Error(f"{name}: {flag} must be true or false.")
        if cfg.get("pvid") is not None:
            pvid = int(cfg["pvid"])
            if not 1 <= pvid <= 4094:
                raise HP1800Error(f"{name}: invalid PVID {pvid}.")

    mirror = doc.get("mirror")
    if mirror is not None:
        if mirror.get("sources") is not None and not isinstance(mirror["sources"], list):
            raise HP1800Error("mirror.sources must be a list.")
        dest = mirror.get("destination")
        if dest is not None and not 1 <= int(dest) <= 24:
            raise HP1800Error(f"Mirror destination {dest} is outside 1..24.")
        for port in mirror.get("sources", []) or []:
            if not 1 <= int(port) <= 24:
                raise HP1800Error(f"Mirror source {port} is outside 1..24.")


def _changes(current: Any, desired: Any, prefix: str = "") -> list[dict]:
    """Compare only keys represented by desired; useful for partial config documents."""
    out: list[dict] = []
    if isinstance(desired, dict) and isinstance(current, dict):
        for key, value in desired.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if key not in current:
                out.append({"path": path, "before": None, "after": value})
            else:
                out.extend(_changes(current[key], value, path))
        return out
    if current != desired:
        out.append({"path": prefix, "before": current, "after": desired})
    return out


class HP1800Client:
    def __init__(self, base_url: str, password: str = "", timeout: float = DEFAULT_TIMEOUT):
        self.base_url = base_url.rstrip("/") + "/"
        self.password = password
        self.timeout = timeout

        # PB.03.10 creates a persistent browser-side cookie in JavaScript:
        #   if (!document.cookie.match(/seid=[^;]+/)) {
        #       document.cookie = "seid=" + Math.floor(Math.random() * 1000000000 + 1);
        #   }
        #
        # requests does not execute that JavaScript, so emulate it explicitly.
        # This identifier stays stable for the full HP1800Client lifetime while
        # the form ?session= token continues to change for each page/apply cycle.
        self.seid = str(random.randint(1, 1_000_000_000))

        self.http = requests.Session()
        self._configure_http_session()
        self.logged_in = False

    def _configure_http_session(self) -> None:
        """Configure common HTTP state and preserve the browser-style seid cookie."""
        self.http.headers.update(
            {
                "User-Agent": f"hp1800ctl/{VERSION} (+local homelab automation)",
                "Accept": "*/*",
            }
        )

        host = urlparse(self.base_url).hostname
        if not host:
            raise HP1800Error(f"Invalid switch URL: {self.base_url}")

        # Scope the cookie to this switch only.  Re-created requests.Session()
        # objects reuse this same seid value rather than generating a new one.
        self.http.cookies.set("seid", self.seid, domain=host, path="/")

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            target = path
        else:
            target = urljoin(self.base_url, path.lstrip("/"))

        base_host = urlparse(self.base_url).netloc
        target_host = urlparse(target).netloc
        if target_host and target_host != base_host:
            raise HP1800Error(
                f"Refusing cross-host request: {target_host!r} != {base_host!r}"
            )
        return target

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = self._url(path)
        try:
            r = self.http.request(method, url, timeout=self.timeout, **kwargs)
            r.raise_for_status()
            return r
        except requests.RequestException as exc:
            raise HP1800Error(f"{method} {url} failed: {exc}") from exc

    def login(self) -> None:
        r = self._request("POST", "/login.html", data={"password": self.password})
        body = r.text.lower()
        if "menu.html" not in body and "<frameset" not in body:
            if "password" in body and "login" in body:
                raise HP1800Error("Login appears to have failed.")
            raise HP1800Error(
                "Login response did not match the observed PB.03.10 main frameset."
            )
        self.logged_in = True

    def ensure_login(self) -> None:
        if not self.logged_in:
            self.login()

    def get_page(self, path: str) -> requests.Response:
        self.ensure_login()
        return self._request("GET", path)

    def status(self) -> dict:
        page = self.get_page("/system/system_name.html")
        info = parse_system_identity(page.text)
        info.update(
            {
                "base_url": self.base_url.rstrip("/"),
                "login": "ok",
                "seid": self.seid,
                "system_form_action": form_action(page.text, page.url),
            }
        )
        return info

    def _fresh_http_session(self) -> None:
        """
        Drop stale PB.03.10 transport state and force a fresh login while keeping
        this client's seid cookie unchanged.
        """
        self.logged_in = False
        try:
            self.http.close()
        except Exception:
            pass
        self.http = requests.Session()
        self._configure_http_session()

    def _post_change_and_verify(
        self,
        *,
        action: str,
        payload: dict[str, str],
        referer: str,
        verify,
        description: str,
        verify_attempts: int = 5,
        settle_seconds: float = 1.0,
    ) -> dict:
        """
        Dispatch one mutating form POST, then verify live state.

        PB.03.10 frequently closes/reset TCP immediately after accepting a form
        POST.  A transport error therefore does NOT prove the mutation failed.

        Safety rule: never blindly replay the write after a reset.  Reconnect and
        verify first.  The caller can rerun the overall desired-state apply if the
        desired state is not observed.
        """
        dispatch_error = None
        try:
            self._request(
                "POST",
                action,
                data=payload,
                headers={
                    "Referer": referer,
                    "Origin": self.base_url.rstrip("/"),
                },
            )
        except HP1800Error as exc:
            dispatch_error = str(exc)

        last_verify_error = None
        for attempt in range(1, max(1, int(verify_attempts)) + 1):
            if dispatch_error or attempt > 1:
                self._fresh_http_session()
            if settle_seconds:
                time.sleep(settle_seconds if attempt == 1 else min(3.0, settle_seconds * attempt))
            try:
                observed = verify()
                if observed:
                    result = {
                        "applied": True,
                        "verified": True,
                        "description": description,
                    }
                    if dispatch_error:
                        result["dispatch_warning"] = (
                            "HTTP connection ended during POST, but desired state "
                            "was verified afterward: " + dispatch_error
                        )
                    return result
            except Exception as exc:
                last_verify_error = str(exc)

        detail = (
            f"{description} could not be verified after POST."
            + (f" Dispatch error: {dispatch_error}." if dispatch_error else "")
            + (f" Last verification error: {last_verify_error}." if last_verify_error else "")
            + " The script did not blindly replay the write; rerun plan-config to inspect live state."
        )
        raise HP1800Error(detail)

    def set_system(
        self,
        *,
        name: Optional[str] = None,
        location: Optional[str] = None,
        contact: Optional[str] = None,
        apply: bool = False,
    ) -> dict:
        page = self.get_page("/system/system_name.html")
        current = parse_system_identity(page.text)
        action = form_action(page.text, page.url)

        desired = {
            "name": current.get("name") if name is None else name,
            "location": current.get("location") if location is None else location,
            "contact": current.get("contact") if contact is None else contact,
        }

        for key, value in desired.items():
            if value is None:
                value = ""
                desired[key] = value
            if len(value) > 24:
                raise HP1800Error(
                    f"{key} is {len(value)} characters; PB.03.10 UI limits it to 24."
                )

        result = {
            "applied": False,
            "action": action,
            "before": current,
            "desired": desired,
        }
        if not apply:
            return result

        payload = {
            "_submit": "Apply",
            "nm": desired["name"],
            "location": desired["location"],
            "contact": desired["contact"],
            "btnSaveSettings": "APPLY",
        }
        def verify_system():
            after = parse_system_identity(self.get_page("/system/system_name.html").text)
            return all(after.get(k) == v for k, v in desired.items())

        post_result = self._post_change_and_verify(
            action=action,
            payload=payload,
            referer=page.url,
            verify=verify_system,
            description="system identity update",
        )
        after = parse_system_identity(self.get_page("/system/system_name.html").text)
        result.update(post_result)
        result["after"] = after
        return result

    def _save_download(
        self,
        response: requests.Response,
        output: Optional[Path],
        fallback_name: str,
    ) -> Path:
        content_type = response.headers.get("Content-Type", "").lower()
        body_start = response.content.lstrip()[:256].lower()
        if "text/html" in content_type or body_start.startswith((b"<!doctype html", b"<html", b"<head", b"<body")):
            raise HP1800Error("Download response looks like an HTML page, not a backup artifact; nothing was saved.")
        if len(response.content) < 16:
            raise HP1800Error("Download response is too small to be a valid backup artifact; nothing was saved.")
        server_name = filename_from_content_disposition(
            response.headers.get("Content-Disposition")
        )
        name = server_name or fallback_name

        if output is None:
            dest = Path.cwd() / name
        else:
            output = Path(output).expanduser()
            if output.exists() and output.is_dir():
                dest = output / name
            elif str(output).endswith(os.sep):
                output.mkdir(parents=True, exist_ok=True)
                dest = output / name
            else:
                dest = output

        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            dest.write_bytes(response.content)
        except OSError as exc:
            raise HP1800Error(f"Could not save download to {dest}: {exc}") from exc
        return dest

    def backup_response(self, retries: int = 4) -> requests.Response:
        """
        Download the binary switch.cfg.

        PB.03.10 can reset the TCP connection on cfgdownload.htm immediately
        after a reboot/factory reset even while normal HTML pages are healthy.
        The operation is read-only, so retry with a fresh login/session and
        prime the Configuration Transfer page first, matching the browser flow
        captured in the HAR.
        """
        last_error: Optional[Exception] = None
        attempts = max(1, int(retries))

        for attempt in range(1, attempts + 1):
            try:
                self.ensure_login()

                # Browser workflow visits this page before submitting the hidden
                # cfgdownload form.  Touch it first so firmware session state is
                # initialized.
                page = self._request("GET", "/system/system_confxfr.html")

                return self._request(
                    "POST",
                    "/system/cfgdownload.htm",
                    data={"_submit": "Apply"},
                    headers={
                        "Referer": page.url,
                        "Origin": self.base_url.rstrip("/"),
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    },
                )

            except HP1800Error as exc:
                last_error = exc
                if attempt >= attempts:
                    break

                self.logged_in = False
                try:
                    self.http.close()
                except Exception:
                    pass

                self.http = requests.Session()
                self._configure_http_session()
                # Give the old embedded web server a little time to recover.
                time.sleep(float(attempt) * 1.5)

        raise HP1800Error(
            f"Binary config backup failed after {attempts} attempts. "
            f"Last error: {last_error}"
        )

    def backup(self, output: Optional[Path] = None) -> Path:
        return self._save_download(self.backup_response(), output, "switch.cfg")

    def support_response(self, kind: str, retries: int = 3) -> requests.Response:
        """
        Fetch one of the PB.03.10 text support reports.

        The 1800-24G occasionally resets the TCP connection on loadsupport.html,
        especially after a factory reset/reboot.  This is a read-only POST, so it
        is safe to retry.  Re-prime the support page and re-login between attempts.
        """
        if kind not in SUPPORT_REPORTS:
            raise HP1800Error(
                f"Unknown support report {kind!r}; choose from "
                + ", ".join(SUPPORT_REPORTS)
            )

        last_error: Optional[Exception] = None
        attempts = max(1, int(retries))
        for attempt in range(1, attempts + 1):
            try:
                self.ensure_login()
                # Prime the UI page first.  The browser does this before posting
                # loadsupport.html, and old PB.03.10 firmware is more reliable
                # when the support page has been touched in the current session.
                try:
                    self._request("GET", "/system/system_support.html")
                except HP1800Error:
                    pass

                return self._request(
                    "POST",
                    "/system/loadsupport.html",
                    data={"R10": SUPPORT_REPORTS[kind], "submit": "APPLY"},
                    headers={
                        "Referer": self._url("/system/system_support.html"),
                        "Origin": self.base_url.rstrip("/"),
                    },
                )
            except HP1800Error as exc:
                last_error = exc
                if attempt >= attempts:
                    break

                # Force a fresh login/session before retrying.  The switch does
                # not use normal cookies, but its web stack still keeps ephemeral
                # per-client state.
                self.logged_in = False
                try:
                    self.http.close()
                except Exception:
                    pass
                self.http = requests.Session()
                self._configure_http_session()
                time.sleep(float(attempt))

        raise HP1800Error(
            f"Support report {kind!r} failed after {attempts} attempts. "
            f"The switch may still be healthy; loadsupport.html is optional for "
            f"planning/apply in v{VERSION}. Last error: {last_error}"
        )

    def support_text(self, kind: str) -> str:
        r = self.support_response(kind)
        # Support files are plain ASCII/ISO-8859-1 on PB.03.10.
        return r.content.decode("latin-1", errors="replace")

    def support(self, kind: str, output: Optional[Path] = None) -> Path:
        return self._save_download(
            self.support_response(kind), output, f"switch-{kind}.txt"
        )

    def general(self) -> dict:
        return parse_general_report(self.support_text("general"))

    def ports(self, general: Optional[dict] = None) -> dict:
        configured = parse_port_config(self.get_page("/ports/ports_config.html").text)
        if general is None:
            try:
                general = self.general()
            except HP1800Error:
                general = {}
        operational = {p["port"]: p for p in general.get("ports", [])}
        merged = []
        for port in configured["ports"]:
            row = dict(port)
            op = operational.get(port["port"])
            if op:
                row.update(
                    {
                        "state": op.get("state"),
                        "link": op.get("link"),
                        "max_frame": op.get("max_frame"),
                        "reported_mode": op.get("mode"),
                    }
                )
            merged.append(row)
        return {"jumbo_frames": configured["jumbo_frames"], "ports": merged}

    def vlans(self) -> dict:
        pconf = self.get_page("/vlans/vlan_pconf.html")
        mconf = self.get_page("/vlans/vlan_mconf.html")
        return parse_vlan_state(pconf.text, mconf.text)

    def trunks(self) -> dict:
        return parse_trunks(self.get_page("/trunks/trunks_mem.html").text)

    def lacp(self) -> dict:
        return parse_lacp(self.get_page("/trunks/lacp.html").text)

    def mirror(self) -> dict:
        return parse_mirror(self.get_page("/ports/ports_mir.html").text)

    def read_state(self) -> dict:
        """
        Collect live desired-state data.

        Support reports are useful for management/operational details but are not
        required for configuration convergence.  If loadsupport.html is flaky,
        continue with the HTML configuration pages and record a warning.
        """
        warnings: list[str] = []
        try:
            general = self.general()
        except HP1800Error as exc:
            general = {}
            warnings.append(f"general support report unavailable: {exc}")

        identity = self.status()

        management = dict(general.get("management", {}))
        # The request URL itself is authoritative for the address we successfully
        # reached.  Do not invent mask/gateway/VID values when the support report
        # is unavailable.
        if not management.get("address"):
            host = urlparse(self.base_url).hostname
            if host:
                management["address"] = host
                management["_partial"] = True

        return {
            "schema": "hp1800ctl.state.v1",
            "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "collection_warnings": warnings,
            "device": {
                "url": self.base_url.rstrip("/"),
                "name": identity.get("name") or general.get("system", {}).get("name"),
                "location": identity.get("location"),
                "contact": identity.get("contact"),
                **general.get("system", {}),
            },
            "management": management,
            "ports": self.ports(general=general),
            "vlans": self.vlans(),
            "trunks": self.trunks(),
            "lacp": self.lacp(),
            "mirror": self.mirror(),
        }

    def export_config(self) -> dict:
        return state_to_config(self.read_state())

    def export_state(self) -> dict:
        return self.read_state()

    def plan_config(self, doc: dict) -> dict:
        validate_config_document(doc)
        state = self.read_state()
        current = state_to_config(state)
        changes: list[dict] = []
        unsupported: list[dict] = []

        # Metadata is informational only and never applied.
        for section in ("system", "ports", "trunks", "lacp", "vlans", "vlan_interfaces", "mirror"):
            if section in doc:
                changes.extend(_changes(current.get(section), doc.get(section), section))

        plan_warnings = list(state.get("collection_warnings") or [])

        if "management" in doc:
            current_mgmt = current.get("management") or {}
            desired_mgmt = doc.get("management") or {}

            # Management mutation is still unsupported, but a flaky support report
            # must not block restoring all of the other switch configuration.
            # Compare only fields we actually know.  The connected URL gives us
            # the address; mask/gateway/VID/DHCP come from switchgeneral.txt.
            known_current = {
                k: v for k, v in current_mgmt.items()
                if k in ("address", "subnet_mask", "gateway", "vid", "dhcp")
                and v is not None
            }
            comparable_desired = {
                k: desired_mgmt.get(k)
                for k in known_current
                if k in desired_mgmt
            }
            mgmt_changes = _changes(known_current, comparable_desired, "management")
            if mgmt_changes:
                unsupported.extend(mgmt_changes)

            missing = [
                k for k in ("subnet_mask", "gateway", "vid", "dhcp")
                if k in desired_mgmt and k not in known_current
            ]
            if missing:
                plan_warnings.append(
                    "Management fields could not be compared because the optional "
                    "support report was unavailable: " + ", ".join(missing)
                )

        return {
            "schema": "hp1800ctl.plan.v1",
            "target": self.base_url.rstrip("/"),
            "changes": changes,
            "unsupported_changes": unsupported,
            "warnings": plan_warnings,
            "safe_to_apply": not unsupported,
        }

    def _post_page_form(self, path: str, data: dict, *, form_name: str = "tF") -> requests.Response:
        page = self.get_page(path)
        action = form_action(page.text, page.url, form_name=form_name)
        return self._request("POST", action, data=data, headers={"Referer": page.url})

    def set_ports_bulk(self, section: dict) -> dict:
        page = self.get_page("/ports/ports_config.html")
        current = parse_port_config(page.text)
        desired_jumbo = bool(section.get("jumbo_frames", current.get("jumbo_frames")))
        desired_settings = _norm_int_key_map(section.get("settings") or {})

        rows = {int(row["port"]): dict(row) for row in current.get("ports", [])}
        converged = bool(current.get("jumbo_frames")) == desired_jumbo
        for port, cfg in desired_settings.items():
            if port not in rows:
                raise HP1800Error(f"Port {port} not present on switch.")
            if not isinstance(cfg, dict):
                raise HP1800Error(f"Port {port} settings must be a mapping.")
            row = rows[port]
            if "speed_duplex" in cfg and _canonical_speed(
                row.get("configured_speed_duplex")
            ) != _canonical_speed(cfg["speed_duplex"]):
                converged = False
            if "flow_control" in cfg and bool(row.get("flow_control")) != bool(
                cfg["flow_control"]
            ):
                converged = False
        if converged:
            return {
                "applied": False,
                "verified": True,
                "reason": "already_converged",
                "after": current,
            }

        for port, cfg in desired_settings.items():
            row = rows[port]
            new_speed = cfg.get("speed_duplex", row.get("configured_speed_duplex"))
            new_flow = cfg.get("flow_control", row.get("flow_control"))
            if row.get("config_locked"):
                if (
                    _canonical_speed(new_speed) != _canonical_speed(row.get("configured_speed_duplex"))
                    or bool(new_flow) != bool(row.get("flow_control"))
                ):
                    raise HP1800Error(
                        f"Port {port} is locked by aggregation; change trunk/LACP membership before port settings."
                    )
            row["configured_speed_duplex"] = _canonical_speed(new_speed)
            row["flow_control"] = bool(new_flow)

        payload: dict[str, str] = {"_submit": "Apply"}
        if desired_jumbo:
            payload["R10"] = "1"
        for port in sorted(rows):
            row = rows[port]
            if row.get("config_locked"):
                continue
            suffix = f"{port:02d}"
            payload[f"S{suffix}"] = _speed_code(row.get("configured_speed_duplex"))
            if row.get("flow_control"):
                payload[f"F{suffix}"] = "on"

        action = form_action(page.text, page.url)

        def verify_ports():
            after = self.ports()
            if bool(after.get("jumbo_frames")) != desired_jumbo:
                return False
            amap = {int(r["port"]): r for r in after.get("ports", [])}
            for port, cfg in desired_settings.items():
                row = amap.get(int(port))
                if row is None:
                    return False
                if "speed_duplex" in cfg and _canonical_speed(row.get("configured_speed_duplex")) != _canonical_speed(cfg["speed_duplex"]):
                    return False
                if "flow_control" in cfg and bool(row.get("flow_control")) != bool(cfg["flow_control"]):
                    return False
            return True

        result = self._post_change_and_verify(
            action=action,
            payload=payload,
            referer=page.url,
            verify=verify_ports,
            description="port configuration update",
        )
        result["after"] = self.ports()
        return result

    def set_trunks_bulk(self, section: dict) -> dict:
        current = self.trunks()
        groups = section.get("groups")
        if groups is None:
            groups = {row["name"]: row["members"] for row in current.get("groups", [])}
        if not isinstance(groups, dict):
            raise HP1800Error("trunks.groups must be a mapping like T1: [17, 18].")
        hash_mode = int(section.get("hash_mode", current.get("hash_mode", 0)))
        if hash_mode not in TRUNK_HASH_FALLBACK:
            raise HP1800Error("trunks.hash_mode must be 0..5.")

        assignment = {port: 0 for port in range(1, 25)}
        for name, members in groups.items():
            m = re.fullmatch(r"T(\d+)", str(name), flags=re.I)
            if not m:
                raise HP1800Error(f"Invalid trunk name {name!r}.")
            tid = int(m.group(1))
            if not 1 <= tid <= 12:
                raise HP1800Error(f"Invalid trunk number T{tid}.")
            for raw_port in members:
                port = int(raw_port)
                if not 1 <= port <= 24:
                    raise HP1800Error(f"Invalid port {port} in {name}.")
                if assignment[port] != 0:
                    raise HP1800Error(f"Port {port} assigned to multiple static trunks.")
                assignment[port] = tid

        page = self.get_page("/trunks/trunks_mem.html")
        payload = {"_submit": "Apply", "R10": str(hash_mode)}
        for port in range(1, 25):
            payload[f"ptc_{port:02d}"] = str(assignment[port])
        action = form_action(page.text, page.url)

        desired_groups = {
            str(name).upper(): sorted(int(p) for p in members)
            for name, members in groups.items()
        }

        def verify_trunks():
            after = self.trunks()
            actual_groups = {
                str(r["name"]).upper(): sorted(int(p) for p in r.get("members", []))
                for r in after.get("groups", [])
            }
            return actual_groups == desired_groups and int(after.get("hash_mode", -1)) == hash_mode

        result = self._post_change_and_verify(
            action=action,
            payload=payload,
            referer=page.url,
            verify=verify_trunks,
            description="static trunk configuration update",
        )
        result["after"] = self.trunks()
        return result

    def set_lacp_bulk(self, port_updates: dict[int, dict]) -> dict:
        page = self.get_page("/trunks/lacp.html")
        current = parse_lacp(page.text)
        rows = {int(row["port"]): dict(row) for row in current.get("ports", [])}

        for port, cfg in port_updates.items():
            if port not in rows:
                raise HP1800Error(f"Unknown LACP port {port}.")
            if not isinstance(cfg, dict):
                raise HP1800Error(f"LACP port {port} settings must be a mapping.")
            row = rows[port]
            requested_enabled = bool(cfg.get("enabled", row.get("enabled")))
            key = cfg.get("key", "auto" if row.get("key") == 0 else row.get("key"))
            key_i = 0 if key == "auto" else int(key)
            if requested_enabled and not row.get("configurable"):
                raise HP1800Error(
                    f"Port {port} cannot enable LACP while assigned to a static trunk."
                )
            row["enabled"] = requested_enabled
            row["key"] = key_i

        payload: dict[str, str] = {"_submit": "Apply"}
        for port in range(1, 25):
            row = rows[port]
            if not row.get("configurable"):
                continue
            if row.get("enabled"):
                payload[f"M{port:02d}"] = "ON"
            key_i = int(row.get("key") or 0)
            payload[f"K{port:02d}"] = f"{key_i:5d}"

        action = form_action(page.text, page.url)

        def verify_lacp():
            after = self.lacp()
            amap = {int(r["port"]): r for r in after.get("ports", [])}
            for port, cfg in port_updates.items():
                row = amap.get(int(port))
                if row is None:
                    return False
                if "enabled" in cfg and bool(row.get("enabled")) != bool(cfg["enabled"]):
                    return False
                if "key" in cfg:
                    want = 0 if cfg["key"] == "auto" else int(cfg["key"])
                    if int(row.get("key") or 0) != want:
                        return False
            return True

        result = self._post_change_and_verify(
            action=action,
            payload=payload,
            referer=page.url,
            verify=verify_lacp,
            description="LACP configuration update",
        )
        result["after"] = self.lacp()
        return result

    def create_vlan(self, vid: int, members: Optional[list[str]] = None) -> dict:
        """
        Create a VLAN using PB.03.10's two-step workflow.

        The first POST (VID=<n>&submit=Add&R10=0) does NOT commit the VLAN.
        It returns a VLAN Member Configuration page with a NEW ?session= token
        in form2.  The second POST to vlan_setup.html?... with submit=Apply
        commits the VLAN and its initial membership.
        """
        vid = int(vid)
        members = list(members or [])

        current = self.vlans()
        if vid in current.get("vids", []):
            return {
                "applied": False,
                "verified": True,
                "reason": "already_exists",
                "vid": vid,
            }
        if not 1 <= vid <= 4094:
            raise HP1800Error(f"Invalid VLAN ID {vid}.")

        # Step 1: Add VLAN.  This is an intermediate transaction only.
        page = self.get_page("/vlans/vlan_mconf.html")
        add_action = form_action(page.text, page.url, form_name="form1")
        add_payload = {"VID": str(vid), "submit": "Add", "R10": "0"}

        try:
            setup = self._request(
                "POST",
                add_action,
                data=add_payload,
                headers={
                    "Referer": page.url,
                    "Origin": self.base_url.rstrip("/"),
                },
            )
        except HP1800Error as exc:
            raise HP1800Error(
                f"VLAN {vid} Add step failed before the firmware returned the "
                f"membership/apply form. Refusing to guess or replay the Add. {exc}"
            ) from exc

        # Firmware must return form2 with a fresh session token.
        setup_action = form_action(setup.text, setup.url, form_name="form2")
        if "vlan_setup.html" not in setup_action:
            raise HP1800Error(
                f"VLAN {vid} Add did not return the expected vlan_setup form: "
                f"{setup_action}"
            )

        nphys = _int_or_none(_js_scalar(setup.text, "nphys")) or 24
        ntrunks = _int_or_none(_js_scalar(setup.text, "ntrunks")) or 12
        nlacps = _int_or_none(_js_scalar(setup.text, "nlacps")) or 24
        availability = _js_array(setup.text, "VlanMember")
        no_static_aggr = _js_array(setup.text, "noStaticAggr")

        desired_indexes = {
            interface_name_to_index(name, nphys, ntrunks, nlacps)
            for name in members
        }

        for idx in desired_indexes:
            if idx >= len(availability):
                raise HP1800Error(
                    f"VLAN {vid}: interface index {idx} is not represented by firmware."
                )
            physically_disabled = (
                idx < nphys
                and idx < len(no_static_aggr)
                and str(no_static_aggr[idx]).strip() == "0"
            )
            if str(availability[idx]).strip() == "0" or physically_disabled:
                raise HP1800Error(
                    f"VLAN {vid}: {_interface_label(idx, nphys, ntrunks)} "
                    f"is disabled for membership in the current topology."
                )

        # Step 2: Apply membership using the NEW form2 session returned above.
        apply_payload: dict[str, str] = {"submit": "Apply"}
        for idx in sorted(desired_indexes):
            field = f"R{0x10 + idx:x}"
            apply_payload[field] = field

        desired_member_names = sorted(set(members))

        def verify_created_vlan():
            after = self.vlans()
            vlan_after = next(
                (v for v in after.get("vlans", []) if v.get("vid") == vid),
                None,
            )
            if vlan_after is None:
                return False
            return sorted(vlan_after.get("members", [])) == desired_member_names

        result = self._post_change_and_verify(
            action=setup_action,
            payload=apply_payload,
            # The HAR shows the Apply transaction using the Add response page as
            # its referer; setup.url is that intermediate transaction URL.
            referer=setup.url,
            verify=verify_created_vlan,
            description=f"create VLAN {vid} and apply initial membership",
            verify_attempts=6,
        )
        result["vid"] = vid
        result["members"] = desired_member_names
        result["add_action"] = add_action
        result["apply_action"] = setup_action
        return result

    def set_vlan_membership(self, vid: int, members: list[str]) -> dict:
        vid = int(vid)
        current = self.vlans()
        vids = current.get("vids", [])
        if vid not in vids:
            raise HP1800Error(f"VLAN {vid} does not exist.")
        if vid == current.get("management_vid") and not members:
            raise HP1800Error("Refusing to remove every member from the management VLAN.")

        mpage = self.get_page("/vlans/vlan_mconf.html")
        maction = form_action(mpage.text, mpage.url, form_name="form1")
        index = vids.index(vid)
        modify = self._request(
            "POST",
            maction,
            data={"VID": "", "R10": str(index), "submit": "Modify"},
            headers={"Referer": mpage.url},
        )
        setup_action = form_action(modify.text, modify.url, form_name="form2")
        nphys = _int_or_none(_js_scalar(modify.text, "nphys")) or 24
        ntrunks = _int_or_none(_js_scalar(modify.text, "ntrunks")) or 12
        nlacps = _int_or_none(_js_scalar(modify.text, "nlacps")) or 24
        availability = _js_array(modify.text, "VlanMember")
        no_static_aggr = _js_array(modify.text, "noStaticAggr")

        desired_indexes = {
            interface_name_to_index(name, nphys, ntrunks, nlacps) for name in members
        }
        for idx in desired_indexes:
            if idx >= len(availability):
                raise HP1800Error(f"Interface index {idx} is not represented by firmware.")
            physically_disabled = (
                idx < nphys
                and idx < len(no_static_aggr)
                and str(no_static_aggr[idx]).strip() == "0"
            )
            if str(availability[idx]).strip() == "0" or physically_disabled:
                raise HP1800Error(
                    f"{_interface_label(idx, nphys, ntrunks)} is disabled for VLAN membership in current topology."
                )

        payload: dict[str, str] = {"submit": "Apply"}
        for idx in sorted(desired_indexes):
            field = f"R{0x10 + idx:x}"
            payload[field] = field
        desired_member_names = sorted(set(members))

        def verify_membership():
            after = self.vlans()
            vlan_after = next((v for v in after.get("vlans", []) if v.get("vid") == vid), None)
            if vlan_after is None:
                return False
            return sorted(vlan_after.get("members", [])) == desired_member_names

        result = self._post_change_and_verify(
            action=setup_action,
            payload=payload,
            referer=modify.url,
            verify=verify_membership,
            description=f"VLAN {vid} membership update",
        )
        after = self.vlans()
        result["vid"] = vid
        result["after"] = next((v for v in after.get("vlans", []) if v.get("vid") == vid), None)
        return result

    def set_vlan_interfaces_bulk(self, updates: dict[str, dict]) -> dict:
        """
        Apply VLAN-aware / ingress-filter / packet-type / PVID settings.

        PB.03.10 form session tokens are effectively single-current-page tokens:
        loading another configuration page can make an older ?session= action
        return 404.  Therefore all validation reads happen first, and the final
        vlan_pconf page is fetched LAST.  No other switch request is made between
        extracting its action URL and submitting the POST.
        """
        # Phase 1: read/validate topology and VLAN membership without retaining
        # a form action that could become stale.
        initial_page = self.get_page("/vlans/vlan_pconf.html")
        initial_list = self.get_page("/vlans/vlan_mconf.html")
        initial = parse_vlan_state(initial_page.text, initial_list.text)
        initial_rows = {row["name"]: dict(row) for row in initial.get("interfaces", [])}

        # Normalize requested interface names against current firmware labels.
        normalized_updates: dict[str, dict] = {}
        for requested_name, cfg in updates.items():
            name = requested_name
            if name not in initial_rows:
                match = next(
                    (k for k in initial_rows if k.lower() == str(requested_name).lower()),
                    None,
                )
                if match is None:
                    raise HP1800Error(f"Unknown VLAN interface {requested_name!r}.")
                name = match

            row = initial_rows[name]
            if not row.get("configurable"):
                raise HP1800Error(
                    f"{name} is not currently configurable for VLAN port settings."
                )

            normalized_updates[name] = dict(cfg)

            if "packet_type" in cfg and cfg["packet_type"] not in ("all", "tagged_only"):
                raise HP1800Error(
                    f"{name}: invalid packet_type {cfg['packet_type']!r}."
                )

            if "pvid" in cfg and cfg["pvid"] is not None:
                wanted_pvid = int(cfg["pvid"])
                memberships = row.get("vlans", [])
                if wanted_pvid not in memberships:
                    raise HP1800Error(
                        f"{name}: PVID {wanted_pvid} is not a VLAN member; "
                        "set VLAN membership first."
                    )

        # Phase 2: fetch a FRESH vlan_pconf page LAST.  From this point until the
        # POST, do not issue any other HTTP request to the switch.
        page = self.get_page("/vlans/vlan_pconf.html")
        current = parse_vlan_state(page.text, None)
        rows = {row["name"]: dict(row) for row in current.get("interfaces", [])}

        # Apply desired changes to the just-fetched page state so unspecified
        # values are preserved exactly as the firmware currently reports them.
        for name, cfg in normalized_updates.items():
            if name not in rows:
                raise HP1800Error(
                    f"{name} disappeared from VLAN interface state before apply."
                )
            row = rows[name]
            if not row.get("configurable"):
                raise HP1800Error(
                    f"{name} became non-configurable before apply; aborting."
                )
            if "vlan_aware" in cfg:
                row["vlan_aware"] = bool(cfg["vlan_aware"])
            if "ingress_filtering" in cfg:
                row["ingress_filtering"] = bool(cfg["ingress_filtering"])
            if "packet_type" in cfg:
                row["packet_type"] = cfg["packet_type"]
            if "pvid" in cfg:
                row["pvid"] = None if cfg["pvid"] is None else int(cfg["pvid"])

        payload: dict[str, str] = {"_submit": "Apply"}
        for idx, observed in enumerate(current.get("interfaces", [])):
            name = observed["name"]
            desired = rows[name]
            if not desired.get("configurable"):
                continue

            if desired.get("vlan_aware"):
                payload[f"R{0x10 + idx:x}"] = "1"

            if desired.get("ingress_filtering"):
                payload[f"R{0x50 + idx:x}"] = "1"

            payload[f"R{0x90 + idx:x}"] = (
                "1" if desired.get("packet_type") == "tagged_only" else "0"
            )
            payload[f"pvid{idx + 1}"] = str(desired.get("pvid") or 0)

        action = form_action(page.text, page.url)

        def verify_vlan_interfaces():
            after = self.vlans()
            amap = {r["name"]: r for r in after.get("interfaces", [])}
            for name, cfg in normalized_updates.items():
                row = amap.get(name)
                if row is None:
                    return False
                if "vlan_aware" in cfg and bool(row.get("vlan_aware")) != bool(cfg["vlan_aware"]):
                    return False
                if "ingress_filtering" in cfg and bool(row.get("ingress_filtering")) != bool(cfg["ingress_filtering"]):
                    return False
                if "packet_type" in cfg and row.get("packet_type") != cfg["packet_type"]:
                    return False
                if "pvid" in cfg:
                    want = None if cfg["pvid"] is None else int(cfg["pvid"])
                    if row.get("pvid") != want:
                        return False
            return True

        result = self._post_change_and_verify(
            action=action,
            payload=payload,
            referer=page.url,
            verify=verify_vlan_interfaces,
            description="VLAN interface/PVID configuration update",
        )
        result["after"] = self.vlans()
        return result

    def set_mirror_bulk(self, section: dict) -> dict:
        current = self.mirror()
        destination = int(section.get("destination", current.get("destination") or 1))
        sources = [int(p) for p in section.get("sources", current.get("sources", []))]
        if not 1 <= destination <= 24:
            raise HP1800Error(f"Invalid mirror destination {destination}.")
        for port in sources:
            if not 1 <= port <= 24:
                raise HP1800Error(f"Invalid mirror source {port}.")
            if port == destination:
                raise HP1800Error("Mirror destination cannot also be a source.")

        page = self.get_page("/ports/ports_mir.html")
        payload: dict[str, str] = {"_submit": "Apply", "Port": str(destination)}
        for port in sorted(set(sources)):
            payload[f"E{port:02d}"] = "1"
        action = form_action(page.text, page.url)

        def verify_mirror():
            after = self.mirror()
            return (
                int(after.get("destination") or 0) == destination
                and sorted(int(p) for p in after.get("sources", [])) == sorted(set(sources))
            )

        result = self._post_change_and_verify(
            action=action,
            payload=payload,
            referer=page.url,
            verify=verify_mirror,
            description="port mirror configuration update",
        )
        result["after"] = self.mirror()
        return result

    def is_factory_default_identity(self) -> bool:
        """
        Conservative test used only to decide whether a failed pre-restore
        binary backup can be tolerated.

        A full reset is considered factory-default only when reached at the
        documented factory address and the identity page has the stock name
        with empty location/contact.
        """
        try:
            ident = self.status()
        except HP1800Error:
            return False

        host = urlparse(self.base_url).hostname
        return (
            host == FACTORY_ADDRESS
            and ident.get("name") == "PROCURVE J9028B"
            and (ident.get("location") or "") == ""
            and (ident.get("contact") or "") == ""
        )

    def apply_config(self, doc: dict, *, apply: bool = False, backup_root: Optional[Path] = None) -> dict:
        validate_config_document(doc)
        plan = self.plan_config(doc)
        if plan["unsupported_changes"]:
            raise HP1800Error(
                "Management-IP/VLAN mutation is not implemented because its exact PB.03.10 POST has not been captured. "
                "Keep the management block equal to live state, or capture that UI workflow first."
            )
        if not apply:
            return {"applied": False, "plan": plan}

        if not plan["changes"]:
            return {"applied": False, "reason": "already_converged", "plan": plan}

        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        root = Path(backup_root).expanduser() if backup_root else Path.cwd()
        backup_dir = root / f"hp1800-preapply-{stamp}"

        factory_recovery = self.is_factory_default_identity()
        try:
            self.snapshot(
                backup_dir,
                require_binary_backup=not factory_recovery,
            )
        except HP1800Error as exc:
            if factory_recovery:
                # This should normally be handled inside snapshot(), but keep a
                # defensive fallback so a factory restore is not blocked solely
                # by the embedded cfgdownload endpoint.
                backup_dir.mkdir(parents=True, exist_ok=True)
                (backup_dir / "snapshot-warnings.json").write_text(
                    json.dumps(
                        {
                            "warnings": [
                                "Pre-apply binary backup unavailable during "
                                f"factory-default recovery: {exc}"
                            ]
                        },
                        indent=2,
                        sort_keys=True,
                    ) + "\n",
                    encoding="utf-8",
                )
            else:
                raise

        results: list[dict] = []
        changed_paths = {change.get("path", "") for change in plan["changes"]}

        def section_changed(section: str) -> bool:
            return any(path == section or path.startswith(section + ".") for path in changed_paths)

        # 1) Ensure referenced VLANs exist before membership/PVID operations.
        vlan_section = doc.get("vlans") or {}
        vlan_items = _norm_int_key_map(vlan_section.get("items") or {})
        if section_changed("vlans"):
            for vid in sorted(vlan_items):
                if vid not in self.vlans().get("vids", []):
                    initial_members = list((vlan_items.get(vid) or {}).get("members") or [])
                    results.append({
                        "operation": f"create_vlan:{vid}",
                        "result": self.create_vlan(vid, members=initial_members),
                    })

        # 2) Static aggregation and LACP interact. Disable LACP only on ports that
        #    are about to become static trunk members, then apply trunks, then final LACP.
        if "trunks" in doc and section_changed("trunks"):
            groups = (doc.get("trunks") or {}).get("groups") or {}
            static_ports = {int(p) for members in groups.values() for p in members}
            current_lacp = self.lacp()
            to_disable = {
                int(row["port"]): {"enabled": False, "key": "auto"}
                for row in current_lacp.get("ports", [])
                if row.get("enabled") and int(row["port"]) in static_ports
            }
            if to_disable:
                results.append({"operation": "preclear_lacp", "result": self.set_lacp_bulk(to_disable)})
            results.append({"operation": "trunks", "result": self.set_trunks_bulk(doc["trunks"])})

        if "lacp" in doc and section_changed("lacp"):
            lacp_updates = _norm_int_key_map((doc.get("lacp") or {}).get("ports") or {})
            if lacp_updates:
                results.append({"operation": "lacp", "result": self.set_lacp_bulk(lacp_updates)})

        # 3) Port settings after aggregation has reached desired ownership.
        if "ports" in doc and section_changed("ports"):
            results.append({"operation": "ports", "result": self.set_ports_bulk(doc["ports"])})

        # 4) VLAN membership then per-interface PVID/filter behavior.
        if vlan_items and section_changed("vlans"):
            for vid, cfg in sorted(vlan_items.items()):
                if "members" in cfg:
                    results.append({
                        "operation": f"vlan_membership:{vid}",
                        "result": self.set_vlan_membership(vid, list(cfg.get("members") or [])),
                    })

        if "vlan_interfaces" in doc and section_changed("vlan_interfaces"):
            results.append({
                "operation": "vlan_interfaces",
                "result": self.set_vlan_interfaces_bulk(doc.get("vlan_interfaces") or {}),
            })

        if "mirror" in doc and section_changed("mirror"):
            results.append({"operation": "mirror", "result": self.set_mirror_bulk(doc["mirror"])})

        if "system" in doc and section_changed("system"):
            syscfg = doc.get("system") or {}
            results.append({
                "operation": "system",
                "result": self.set_system(
                    name=syscfg.get("name"),
                    location=syscfg.get("location"),
                    contact=syscfg.get("contact"),
                    apply=True,
                ),
            })

        final_plan = self.plan_config(doc)
        if final_plan["changes"] or final_plan["unsupported_changes"]:
            raise HP1800Error(
                "Configuration apply completed but verification still reports differences. "
                f"Backup is at {backup_dir}. Remaining plan: {json.dumps(final_plan, sort_keys=True)}"
            )
        return {
            "applied": True,
            "backup": str(backup_dir),
            "factory_recovery_mode": factory_recovery,
            "operations": results,
            "verified": True,
        }

    def factory_reset(
        self,
        *,
        mode: str = "full",
        apply: bool = False,
        confirm: Optional[str] = None,
        backup_root: Optional[Path] = None,
        wait_seconds: int = 180,
    ) -> dict:
        if mode not in ("full", "keep-ip"):
            raise HP1800Error("factory-reset mode must be 'full' or 'keep-ip'.")

        target_after = FACTORY_URL if mode == "full" else self.base_url.rstrip("/")
        result = {
            "applied": False,
            "mode": mode,
            "preserve_current_ip": mode == "keep-ip",
            "target_after_reset": target_after,
            "factory_default_address": FACTORY_ADDRESS,
            "factory_default_netmask": FACTORY_NETMASK,
        }
        if not apply:
            return result
        if confirm != "FACTORY-RESET":
            raise HP1800Error("Refusing factory reset without --confirm FACTORY-RESET.")

        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        root = Path(backup_root).expanduser() if backup_root else Path.cwd()
        backup_dir = root / f"hp1800-prereset-{stamp}"
        self.snapshot(backup_dir)
        result["backup"] = str(backup_dir)

        # The captured Tools page uses one generic system_config form. Its JS sets
        # factory=Yes and R10=0 for entire defaults, or R10=1 to keep current IP.
        page = self.get_page("/system/system_confxfr.html")
        action = form_action(page.text, page.url, form_name="tF")
        # Match the captured browser form exactly.  PB.03.10 uses:
        #   R10=0 -> full factory defaults
        #   R10=1 -> factory defaults while preserving current IP settings
        # The browser also submits upload=on, so include it for compatibility.
        payload = {
            "_submit": "Apply",
            "factory": "Yes",
            "warm": "",
            "tool_sel": "reset",
            "upload": "on",
            "R10": "0" if mode == "full" else "1",
            "btnSaveSettings": "APPLY",
        }

        dispatch_error = None
        try:
            self.http.post(
                action,
                data=payload,
                headers={"Referer": page.url},
                timeout=min(self.timeout, 5.0),
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            # A connection drop is expected if the switch reboots immediately.
            dispatch_error = str(exc)

        result["applied"] = True
        result["dispatch_error"] = dispatch_error
        deadline = time.time() + max(10, int(wait_seconds))
        last_error = None
        while time.time() < deadline:
            try:
                probe = requests.get(urljoin(target_after.rstrip("/") + "/", "login.html"), timeout=2.0)
                if probe.status_code < 500:
                    break
            except requests.RequestException as exc:
                last_error = str(exc)
            time.sleep(3)
        else:
            raise HP1800Error(
                f"Factory reset was dispatched, but {target_after} did not become reachable within {wait_seconds}s. "
                f"Pre-reset backup: {backup_dir}. Last probe: {last_error}"
            )

        verify_password = ""
        verifier = HP1800Client(target_after, password=verify_password, timeout=self.timeout)

        # Do not make factory-reset verification depend on loadsupport.html.
        # Successful login + system page retrieval at the expected address is the
        # critical recovery proof.  Try the richer general report only as optional
        # evidence.
        verified_status = verifier.status()
        result["verified_status"] = verified_status
        try:
            result["verified_state"] = verifier.general()
        except HP1800Error as exc:
            result["verified_state"] = None
            result["verification_warning"] = str(exc)

        if mode == "full":
            reached = urlparse(target_after).hostname
            result["recovery_verified"] = reached == FACTORY_ADDRESS and verified_status.get("login") == "ok"
            if not result["recovery_verified"]:
                raise HP1800Error(
                    f"Switch recovered after reset but was not verified at factory address {FACTORY_ADDRESS}."
                )
        else:
            result["recovery_verified"] = verified_status.get("login") == "ok"
        result["verified"] = False
        result["verification_warning"] = (
            "Management login returned after reset, but reset completion and preserved management settings "
            "were not compared reliably. Treat reset state as unverified and inspect it manually."
        )
        return result

    def snapshot(
        self,
        directory: Optional[Path] = None,
        *,
        require_binary_backup: bool = True,
    ) -> Path:
        self.ensure_login()
        if directory is None:
            stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
            directory = Path.cwd() / f"hp1800-snapshot-{stamp}"
        else:
            directory = Path(directory).expanduser()
        directory.mkdir(parents=True, exist_ok=True)

        snapshot_warnings: list[str] = []

        # switch.cfg is normally the critical rollback artifact.  Immediately
        # after a full factory reset PB.03.10 may refuse cfgdownload.htm even
        # though normal configuration pages work.  Recovery from known factory
        # defaults may explicitly continue without that redundant backup.
        try:
            self.backup(directory)
        except HP1800Error as exc:
            if require_binary_backup:
                raise
            snapshot_warnings.append(
                "binary switch.cfg unavailable but snapshot continued because "
                f"current state is known factory-default recovery state: {exc}"
            )

        # Human-readable support reports are useful but the PB.03.10 report
        # endpoint can transiently reset the connection after reboot/reset.  A
        # missing optional report must not prevent a pre-apply backup or restore.
        for kind in ("general", "vlan", "stats", "protocol"):
            try:
                self.support(kind, directory)
            except HP1800Error as exc:
                snapshot_warnings.append(f"{kind}: {exc}")

        (directory / "status.json").write_text(
            json.dumps(self.status(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        state = self.read_state()
        snapshot_warnings.extend(state.get("collection_warnings") or [])
        config = state_to_config(state)
        (directory / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (directory / "state.yaml").write_text(
            dump_data(state, "yaml"),
            encoding="utf-8",
        )
        (directory / "config.yaml").write_text(
            dump_data(config, "yaml"),
            encoding="utf-8",
        )
        if snapshot_warnings:
            (directory / "snapshot-warnings.json").write_text(
                json.dumps(
                    {"warnings": snapshot_warnings},
                    indent=2,
                    sort_keys=True,
                ) + "\n",
                encoding="utf-8",
            )
        return directory

    def dump_page(self, path: str, output: Path) -> Path:
        self.ensure_login()
        if "://" in path:
            parsed = urlparse(path)
            if parsed.netloc != urlparse(self.base_url).netloc:
                raise HP1800Error("dump-page only permits the configured switch host.")
        r = self.get_page(path)
        content_type = r.headers.get("Content-Type", "")
        if "html" not in content_type.lower() and "<html" not in r.text.lower():
            raise HP1800Error(
                f"Refusing to save non-HTML response as page capture: {content_type}"
            )
        dest = Path(output).expanduser()
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(r.text, encoding="utf-8")
        return dest


def resolve_password(args) -> str:
    if args.password is not None:
        return args.password
    if args.prompt_password:
        return getpass.getpass("Switch password: ")
    return os.environ.get("HP1800_PASSWORD", "")


def print_json(value) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=f"HP ProCurve 1800-24G PB.03.10 web-management client v{VERSION}."
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    p.add_argument("--url", help=f"Switch URL (default: {DEFAULT_URL}; required for factory-reset)")
    p.add_argument(
        "--password",
        help="Switch password. Prefer HP1800_PASSWORD or --prompt-password.",
    )
    p.add_argument(
        "--prompt-password",
        action="store_true",
        help="Prompt for the switch password without echoing it.",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )

    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="Login and show system identity/session-form details.")
    sub.add_parser("show", help="Show normalized combined switch state as JSON.")
    sub.add_parser("ports", help="Show configured and operational port state as JSON.")
    sub.add_parser("vlans", help="Show VLAN, PVID, and membership state as JSON.")
    sub.add_parser("trunks", help="Show static trunk membership/hash state as JSON.")
    sub.add_parser("lacp", help="Show per-port LACP configuration as JSON.")
    sub.add_parser("mirror", help="Show port mirroring destination/source state as JSON.")

    ex = sub.add_parser("export-config", help="Export round-trip desired configuration as YAML or JSON.")
    ex.add_argument("-o", "--output", type=Path, help="Output file; stdout if omitted.")
    ex.add_argument("--format", choices=("yaml", "json"), default="yaml")

    es = sub.add_parser("export-state", help="Export full normalized live state as YAML or JSON.")
    es.add_argument("-o", "--output", type=Path, help="Output file; stdout if omitted.")
    es.add_argument("--format", choices=("yaml", "json"), default="yaml")

    vc = sub.add_parser("validate-config", help="Validate an hp1800ctl YAML configuration file offline.")
    vc.add_argument("file", type=Path)

    pc = sub.add_parser("plan-config", help="Compare YAML desired state to the live switch without changing it.")
    pc.add_argument("file", type=Path)

    ac = sub.add_parser("apply-config", help="Bulk-apply YAML desired state; dry-run unless --apply is supplied.")
    ac.add_argument("file", type=Path)
    ac.add_argument("--apply", action="store_true", help="Actually apply the configuration after taking a snapshot backup.")
    ac.add_argument("--backup-root", type=Path, help="Directory under which pre-apply snapshot is created.")

    fr = sub.add_parser("factory-reset", help="Guarded factory reset; dry-run unless --apply is supplied.")
    fr.add_argument("--mode", choices=("full", "keep-ip"), default="full",
                    help="full returns to 192.168.2.10/24; keep-ip requests factory defaults while retaining current IP.")
    fr.add_argument("--apply", action="store_true", help="Actually issue the factory-reset request.")
    fr.add_argument("--confirm", help="Required with --apply: literal FACTORY-RESET")
    fr.add_argument("--backup-root", type=Path, help="Directory under which pre-reset snapshot is created.")
    fr.add_argument("--wait-seconds", type=int, default=180, help="How long to wait for management to return.")

    b = sub.add_parser("backup", help="Download binary switch.cfg.")
    b.add_argument("-o", "--output", type=Path, help="Destination file or existing directory.")

    s = sub.add_parser("support", help="Download a text support report.")
    s.add_argument("kind", choices=sorted(SUPPORT_REPORTS))
    s.add_argument("-o", "--output", type=Path, help="Destination file or existing directory.")

    snap = sub.add_parser(
        "snapshot",
        help="Download switch.cfg, support reports, JSON state, YAML state, and round-trip config.yaml.",
    )
    snap.add_argument("-d", "--directory", type=Path, help="Snapshot destination directory.")

    ss = sub.add_parser(
        "set-system",
        help="Plan or apply System Name / Location / Contact changes.",
    )
    ss.add_argument("--name")
    ss.add_argument("--location")
    ss.add_argument("--contact")
    ss.add_argument(
        "--apply",
        action="store_true",
        help="Actually POST the change. Without this flag the command is dry-run only.",
    )

    dp = sub.add_parser(
        "dump-page",
        help="Save an authenticated switch HTML page for inspection/reverse engineering.",
    )
    dp.add_argument("path", help="Example: /vlans/vlan_pconf.html")
    dp.add_argument("-o", "--output", type=Path, required=True)
    return p


def main() -> int:
    parser = make_parser()
    args = parser.parse_args()
    if args.command == "factory-reset" and not args.url:
        parser.error("factory-reset requires an explicit --url target.")
    if not args.url:
        args.url = DEFAULT_URL
    password = resolve_password(args)
    client = HP1800Client(args.url, password=password, timeout=args.timeout)

    try:
        if args.command == "status":
            print_json(client.status())
        elif args.command == "show":
            print_json(client.read_state())
        elif args.command == "ports":
            print_json(client.ports())
        elif args.command == "vlans":
            print_json(client.vlans())
        elif args.command == "trunks":
            print_json(client.trunks())
        elif args.command == "lacp":
            print_json(client.lacp())
        elif args.command == "mirror":
            print_json(client.mirror())
        elif args.command == "export-config":
            data = client.export_config()
            if args.output:
                print(write_data_file(data, args.output, args.format))
            else:
                print(dump_data(data, args.format), end="")
        elif args.command == "export-state":
            data = client.export_state()
            if args.output:
                print(write_data_file(data, args.output, args.format))
            else:
                print(dump_data(data, args.format), end="")
        elif args.command == "validate-config":
            doc = load_yaml_file(args.file)
            validate_config_document(doc)
            print_json({"valid": True, "schema": doc.get("schema"), "file": str(args.file)})
        elif args.command == "plan-config":
            doc = load_yaml_file(args.file)
            print_json(client.plan_config(doc))
        elif args.command == "apply-config":
            doc = load_yaml_file(args.file)
            result = client.apply_config(doc, apply=args.apply, backup_root=args.backup_root)
            print_json(result)
            if not args.apply:
                print("\nDRY RUN ONLY. Re-run with --apply to send changes.", file=sys.stderr)
        elif args.command == "factory-reset":
            result = client.factory_reset(
                mode=args.mode,
                apply=args.apply,
                confirm=args.confirm,
                backup_root=args.backup_root,
                wait_seconds=args.wait_seconds,
            )
            print_json(result)
            if not args.apply:
                print("\nDRY RUN ONLY. Re-run with --apply --confirm FACTORY-RESET to reset the switch.", file=sys.stderr)
        elif args.command == "backup":
            print(client.backup(args.output))
        elif args.command == "support":
            print(client.support(args.kind, args.output))
        elif args.command == "snapshot":
            print(client.snapshot(args.directory))
        elif args.command == "set-system":
            result = client.set_system(
                name=args.name,
                location=args.location,
                contact=args.contact,
                apply=args.apply,
            )
            print_json(result)
            if not args.apply:
                print("\nDRY RUN ONLY. Re-run with --apply to send the change.", file=sys.stderr)
        elif args.command == "dump-page":
            print(client.dump_page(args.path, args.output))
        else:
            parser.error(f"Unhandled command: {args.command}")
        return 0
    except HP1800Error as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
