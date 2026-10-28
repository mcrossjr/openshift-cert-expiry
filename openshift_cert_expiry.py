#!/usr/bin/env python3
"""OpenShift TLS expiry scanner.

Reads clusters with ``oc`` and reports when TLS certificates expire. A row is
one certificate, tied back to the workloads that mount it and the Routes (or
Ingresses) in front of those workloads.

Where the bytes come from
  * Secret data that contains a PEM certificate (``kubernetes.io/tls`` and any
    other type — not every cert is labeled as TLS). Private keys are ignored.
  * Route ``spec.tls.certificate``, ``caCertificate``, and
    ``destinationCACertificate``.
  * Route ``spec.tls.externalCertificate`` (OpenShift 4.14+), which points at
    a secret instead of inlining the PEM.
  * Ingress ``spec.tls[].secretName``.
  * ConfigMaps mounted by a workload, when they actually contain a certificate.
  * Optional ``--probe``: a TLS handshake to each route host. This is the only
    way to see the default router certificate, and the way to confirm a
    passthrough route is serving the cert you think it is.

How a deployment is tied to a route
  Workload pod labels  ←  Service selector  ←  Route ``spec.to`` / Ingress
  backend. The secret is tied to the workload by volume, projected volume, or
  env reference, and to a route by ``externalCertificate``.

Requires Python 3.9+ and the standard library. ``oc`` must already be logged
in. Reading secrets is required — the OpenShift ``cluster-reader`` role cannot
list secrets.

Examples
  python3 openshift_cert_expiry.py
  python3 openshift_cert_expiry.py -o cert-expiry.csv
  python3 openshift_cert_expiry.py --all-contexts --threshold-days 45 --probe -o cert-expiry.csv
  python3 openshift_cert_expiry.py -n payments -n identity --csv cert-expiry.csv
  python3 openshift_cert_expiry.py --all-contexts --threshold-days 30 --quiet

The CSV is one row per service certificate, written for people who do not work
with certificates. CA bundles and intermediate certificates are left out.
Columns:

  Service/API/Deployment, Issued CN, SAN, Issued OU,
  Validate Date, Expired Date, Days Left Until Expired

Validate Date is the day the certificate starts working. Expired Date is the
day it stops. -o prints the CLI report and also writes that file. --csv FILE
writes only the file. --csv with no file writes CSV to stdout.

Exit status
  0  no certificate expires inside the window
  1  oc failed, or the arguments are wrong
  2  at least one certificate is expired or inside the window
"""

from __future__ import annotations

import argparse
import base64
import csv
import fnmatch
import hashlib
import json
import re
import socket
import ssl
import subprocess
import sys
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

PEM_RE = re.compile(
    br"-----BEGIN (?:X509 |TRUSTED )?CERTIFICATE-----\s*(.*?)\s*-----END (?:X509 |TRUSTED )?CERTIFICATE-----",
    re.DOTALL,
)

SKIP_SECRET_TYPES = {
    "kubernetes.io/service-account-token",
    "kubernetes.io/dockercfg",
    "kubernetes.io/dockerconfigjson",
    "helm.sh/release.v1",
}

OID_LABEL = {
    "2.5.4.3": "CN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "email",
}

SHORT = {
    "Deployment": "deployment",
    "DeploymentConfig": "deploymentconfig",
    "StatefulSet": "statefulset",
    "DaemonSet": "daemonset",
    "Service": "service",
    "Route": "route",
    "Ingress": "ingress",
    "Secret": "secret",
    "ConfigMap": "configmap",
}

RESOURCES = (
    "secrets",
    "configmaps",
    "services",
    "deployments",
    "statefulsets",
    "daemonsets",
    "deploymentconfigs",
    "routes",
    "ingresses",
)

SERVING_CERT_ANN = "service.beta.openshift.io/serving-cert-secret-name"
ORIGIN_SVC_ANN = "service.beta.openshift.io/originating-service-name"
CERT_MANAGER_ANN = "cert-manager.io/certificate-name"


class ScanError(Exception):
    pass


class CertParseError(Exception):
    pass


@dataclass
class CertInfo:
    serial: str
    fingerprint: str
    subject: str
    issuer: str
    sans: list[str]
    not_before: datetime
    not_after: datetime
    ca: bool
    cn: str = ""
    ou: str = ""


@dataclass
class Finding:
    context: str
    namespace: str
    source: str
    name: str
    key: str
    role: str
    subject: str
    issuer: str
    sans: list[str]
    serial: str
    fingerprint: str
    not_before: datetime
    not_after: datetime
    days_left: int
    not_yet_valid: bool
    ca: bool
    status: str
    cn: str = ""
    ou: str = ""
    workloads: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    routes: list[str] = field(default_factory=list)
    termination: str = ""
    probe: str = "n/a"
    notes: list[str] = field(default_factory=list)

    def location(self) -> str:
        return f"{self.namespace}/{self.name}"


@dataclass
class RouteMeta:
    context: str
    namespace: str
    name: str
    host: str
    termination: str
    secret_names: list[str]
    inline_serials: list[str]
    workloads: list[str]
    services: list[str]
    ref: str


@dataclass
class ClusterSummary:
    context: str
    server: str
    secrets: int
    routes: int
    workloads: int
    certificates: int
    probe_ok: int = 0
    probe_failed: int = 0
    probe_skipped: int = 0
    notes: list[str] = field(default_factory=list)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Report OpenShift TLS certificate expiry for workloads, secrets, and routes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit 2 when any certificate is expired or inside --threshold-days.",
    )
    parser.add_argument("--context", action="append", default=[], help="kubeconfig context. Repeatable. Default: current context.")
    parser.add_argument("--all-contexts", action="store_true", help="Scan every context in the kubeconfig.")
    parser.add_argument("--kubeconfig", help="kubeconfig file passed through to oc.")
    parser.add_argument("--oc", default="oc", help="oc binary. Default: oc on PATH.")
    parser.add_argument("--insecure-skip-tls-verify", action="store_true", help="Pass --insecure-skip-tls-verify to oc.")
    parser.add_argument("-n", "--namespace", action="append", default=[], help="Namespace to scan. Repeatable. Default: all.")
    parser.add_argument("--exclude-namespace", action="append", default=[], help="fnmatch pattern to skip. Repeatable.")
    parser.add_argument("--exclude-system", action="store_true", help="Skip openshift-* and kube-* namespaces. The default router cert usually lives in openshift-ingress.")
    parser.add_argument("--threshold-days", type=int, default=30, help="Warning window. Default: 30.")
    parser.add_argument("--critical-days", type=int, default=14, help="Critical window inside the threshold. Default: 14.")
    parser.add_argument("--probe", action="store_true", help="TLS handshake to each route host and compare the served cert.")
    parser.add_argument("--probe-port", type=int, default=443)
    parser.add_argument("--probe-timeout", type=float, default=4.0)
    parser.add_argument("--probe-workers", type=int, default=8)
    parser.add_argument("--json", action="store_true", help="Write JSON to stdout.")
    parser.add_argument(
        "--csv",
        nargs="?",
        const="-",
        default=None,
        metavar="FILE",
        help="Write CSV. FILE saves it (cert-expiry.csv). Omit FILE, or pass -, to write CSV to stdout. Columns are the service, issued name, and expiry dates.",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Write CSV to FILE and still print the CLI report. Same columns as --csv, including expiration.",
    )
    parser.add_argument("--by-workload", action="store_true", help="Human output grouped by deployment instead of by certificate.")
    parser.add_argument("--quiet", action="store_true", help="Human output: only certificates inside the window.")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--full", action="store_true", help="Do not truncate SAN lists in human output.")
    parser.add_argument("--timeout", type=int, default=180, help="Per oc call timeout in seconds.")
    parser.add_argument(
        "--from-json",
        action="append",
        default=[],
        help="Offline mode. File or directory of `oc get -o json` documents. Prefix with name= to set the context label. Repeatable. oc is not required.",
    )
    parser.add_argument("--context-name", default="local", help="Context label used with a single --from-json that has no name= prefix.")
    parser.add_argument("--now", help="Override the clock (UTC, YYYY-MM-DDTHH:MM:SSZ). For reproducible runs.")
    parser.add_argument("--self-test", action="store_true", help="Parse a built-in certificate and exit.")
    args = parser.parse_args(argv)
    if args.threshold_days < 0 or args.critical_days < 0:
        parser.error("day windows must be >= 0")
    if args.critical_days > args.threshold_days:
        args.critical_days = args.threshold_days
    if args.json and (args.csv or args.output):
        parser.error("pick one of --json or --csv/--output")
    if args.csv and args.csv != "-" and args.output:
        parser.error("pick one of --csv FILE or --output")
    return args


def parse_now(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    text = value.strip().replace("Z", "")
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ScanError(f"cannot parse --now {value!r}; use 2026-10-24T00:00:00Z")


def oc_base(args: argparse.Namespace) -> list[str]:
    cmd = [args.oc]
    if args.kubeconfig:
        cmd += ["--kubeconfig", args.kubeconfig]
    if args.insecure_skip_tls_verify:
        cmd.append("--insecure-skip-tls-verify")
    return cmd


def run_oc(args: argparse.Namespace, context: str | None, extra: list[str]) -> subprocess.CompletedProcess[str]:
    cmd = oc_base(args)
    if context:
        cmd += ["--context", context]
    cmd += extra
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=args.timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ScanError(f"cannot find {args.oc!r}. Install oc or pass --oc.") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"oc timed out after {args.timeout}s: {' '.join(extra)}") from exc


def oc_json(args: argparse.Namespace, context: str | None, resource: str, namespace: str | None) -> list[dict]:
    extra = ["get", resource]
    if namespace:
        extra += ["-n", namespace]
    else:
        extra.append("-A")
    extra += ["-o", "json", "--request-timeout=60s"]
    proc = run_oc(args, context, extra)
    stderr = (proc.stderr or "").strip()
    missing = (
        "the server doesn't have a resource type" in stderr
        or "the server doesn't have a resource type" in stderr.lower()
        or "NotFound" in stderr
        or "no matches for" in stderr
    )
    if proc.returncode != 0 and missing:
        return []
    if proc.returncode != 0:
        hint = ""
        if resource == "secrets" and ("Forbidden" in stderr or "forbidden" in stderr):
            hint = " The account needs get/list on secrets. cluster-reader does not include that."
        raise ScanError(f"oc get {resource} failed.{hint}\n{stderr}")
    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise ScanError(f"oc get {resource} did not return JSON: {exc}") from exc
    return unwrap(payload)


def list_contexts(args: argparse.Namespace) -> list[str]:
    if args.all_contexts:
        proc = run_oc(args, None, ["config", "get-contexts", "-o", "name"])
        if proc.returncode != 0:
            raise ScanError(proc.stderr.strip() or "oc config get-contexts failed")
        names = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        if not names:
            raise ScanError("kubeconfig has no contexts")
        return names
    if args.context:
        return list(args.context)
    proc = run_oc(args, None, ["config", "current-context"])
    if proc.returncode != 0:
        raise ScanError(proc.stderr.strip() or "no current oc context; pass --context or log in")
    name = proc.stdout.strip()
    if not name:
        raise ScanError("no current oc context; pass --context")
    return [name]


def server_url(args: argparse.Namespace, context: str) -> str:
    proc = run_oc(args, context, ["whoami", "--show-server"])
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def unwrap(data: object) -> list[dict]:
    if isinstance(data, list):
        out: list[dict] = []
        for item in data:
            out.extend(unwrap(item))
        return out
    if not isinstance(data, dict):
        return []
    kind = data.get("kind")
    if kind == "List" or (kind in (None, "List") and isinstance(data.get("items"), list)):
        return [item for item in data.get("items") or [] if isinstance(item, dict)]
    if kind:
        return [data]
    return []


def load_offline(spec: str, default_name: str) -> tuple[str, list[dict]]:
    if "=" in spec and not spec.startswith("/") and not spec.startswith("."):
        name, _, path_text = spec.partition("=")
    else:
        name, path_text = default_name, spec
    path = Path(path_text)
    if not path.exists():
        raise ScanError(f"--from-json path not found: {path}")
    files = [path] if path.is_file() else sorted(p for p in path.glob("*.json") if p.is_file())
    if not files:
        raise ScanError(f"no JSON files in {path}")
    objects: list[dict] = []
    for file in files:
        try:
            payload = json.loads(file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ScanError(f"{file}: {exc}") from exc
        objects.extend(unwrap(payload))
    return name, objects


def meta(obj: dict) -> dict:
    value = obj.get("metadata")
    return value if isinstance(value, dict) else {}


def obj_name(obj: dict) -> str:
    return str(meta(obj).get("name") or "")


def obj_ns(obj: dict) -> str:
    return str(meta(obj).get("namespace") or "default")


def annotations(obj: dict) -> dict:
    value = meta(obj).get("annotations")
    return value if isinstance(value, dict) else {}


def short_kind(obj: dict) -> str:
    kind = str(obj.get("kind") or "object")
    return SHORT.get(kind, kind.lower())


def workload_ref(obj: dict) -> str:
    return f"{short_kind(obj)}/{obj_name(obj)}"


def pod_spec(obj: dict) -> dict:
    spec = obj.get("spec") if isinstance(obj.get("spec"), dict) else {}
    template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
    nested = template.get("spec") if isinstance(template.get("spec"), dict) else {}
    return nested


def pod_labels(obj: dict) -> dict:
    spec = obj.get("spec") if isinstance(obj.get("spec"), dict) else {}
    template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
    tmeta = template.get("metadata") if isinstance(template.get("metadata"), dict) else {}
    labels = tmeta.get("labels") if isinstance(tmeta.get("labels"), dict) else {}
    return {str(k): str(v) for k, v in labels.items()}


def selector_matches(selector: dict, labels: dict) -> bool:
    if not selector:
        return False
    return all(labels.get(str(k)) == str(v) for k, v in selector.items())


def _names_from_pod(spec: dict, volume_key: str, env_key: str) -> set[str]:
    names: set[str] = set()
    for volume in spec.get("volumes") or []:
        if not isinstance(volume, dict):
            continue
        direct = volume.get(volume_key)
        if isinstance(direct, dict):
            if volume_key == "secret" and direct.get("secretName"):
                names.add(str(direct["secretName"]))
            if volume_key == "configMap" and direct.get("name"):
                names.add(str(direct["name"]))
        projected = volume.get("projected")
        if isinstance(projected, dict):
            for source in projected.get("sources") or []:
                if not isinstance(source, dict):
                    continue
                inner = source.get(volume_key)
                if isinstance(inner, dict) and inner.get("name"):
                    names.add(str(inner["name"]))
    containers = []
    for key in ("containers", "initContainers", "ephemeralContainers"):
        containers.extend(spec.get(key) or [])
    for container in containers:
        if not isinstance(container, dict):
            continue
        for env in container.get("env") or []:
            if not isinstance(env, dict):
                continue
            ref = (env.get("valueFrom") or {}).get(env_key) if isinstance(env.get("valueFrom"), dict) else None
            if isinstance(ref, dict) and ref.get("name"):
                names.add(str(ref["name"]))
        for env_from in container.get("envFrom") or []:
            if not isinstance(env_from, dict):
                continue
            ref_name = "secretRef" if env_key == "secretKeyRef" else "configMapRef"
            ref = env_from.get(ref_name)
            if isinstance(ref, dict) and ref.get("name"):
                names.add(str(ref["name"]))
    return names


def referenced_secrets(obj: dict) -> set[str]:
    return _names_from_pod(pod_spec(obj), "secret", "secretKeyRef")


def referenced_configmaps(obj: dict) -> set[str]:
    return _names_from_pod(pod_spec(obj), "configMap", "configMapKeyRef")


def namespace_allowed(namespace: str, args: argparse.Namespace) -> bool:
    if args.namespace and namespace not in set(args.namespace):
        return False
    for pattern in args.exclude_namespace:
        if fnmatch.fnmatch(namespace, pattern):
            return False
    if args.exclude_system and (namespace.startswith("openshift-") or namespace.startswith("kube-")):
        return False
    return True


def b64_bytes(value: str) -> bytes | None:
    try:
        return base64.b64decode(value, validate=False)
    except (ValueError, TypeError):
        return None


def extract_ders(blob: bytes) -> list[bytes]:
    if not blob:
        return []
    ders = []
    for match in PEM_RE.findall(blob):
        body = re.sub(br"\s+", b"", match)
        try:
            der = base64.b64decode(body, validate=False)
        except (ValueError, TypeError):
            continue
        if der and der[0] == 0x30:
            ders.append(der)
    if ders:
        return ders
    stripped = blob.strip()
    if stripped.startswith(b"\x30"):
        return [stripped]
    return []


def blobs_from_text(text: str) -> list[bytes]:
    if not text or not isinstance(text, str):
        return []
    raw = text.encode("utf-8", "replace")
    found = extract_ders(raw)
    if found:
        return found
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 64 or not re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        return []
    decoded = b64_bytes(compact)
    if not decoded:
        return []
    return extract_ders(decoded)


def secret_material(obj: dict) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    data = obj.get("data") if isinstance(obj.get("data"), dict) else {}
    string_data = obj.get("stringData") if isinstance(obj.get("stringData"), dict) else {}
    for key, value in list(string_data.items()):
        if isinstance(value, str) and not _skip_key_name(str(key)):
            out[str(key)] = value.encode("utf-8", "replace")
    for key, value in data.items():
        if not isinstance(value, str):
            continue
        key_s = str(key)
        if _skip_key_name(key_s):
            continue
        decoded = b64_bytes(value)
        if decoded is None or len(decoded) > 2_000_000:
            continue
        if decoded.startswith(b"-----BEGIN ") and b"PRIVATE KEY-----" in decoded[:80]:
            continue
        out[key_s] = decoded
    return out


def configmap_material(obj: dict) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    data = obj.get("data") if isinstance(obj.get("data"), dict) else {}
    binary = obj.get("binaryData") if isinstance(obj.get("binaryData"), dict) else {}
    for key, value in data.items():
        if isinstance(value, str):
            out[str(key)] = value.encode("utf-8", "replace")
    for key, value in binary.items():
        if isinstance(value, str):
            decoded = b64_bytes(value)
            if decoded is not None:
                out[str(key)] = decoded
    return out


def _skip_key_name(key: str) -> bool:
    lowered = key.lower()
    if lowered in {"tls.key", "key", "privatekey", "tls.privatekey"}:
        return True
    return lowered.endswith(".key") or lowered.endswith(".key.pem")


def der_read(data: bytes, index: int) -> tuple[int, bytes, int]:
    if index >= len(data):
        raise CertParseError("truncated")
    tag = data[index]
    index += 1
    if index >= len(data):
        raise CertParseError("truncated length")
    length_byte = data[index]
    index += 1
    if length_byte & 0x80:
        count = length_byte & 0x7F
        if count == 0 or count > 4 or index + count > len(data):
            raise CertParseError("bad length")
        length = int.from_bytes(data[index : index + count], "big")
        index += count
    else:
        length = length_byte
    if length < 0 or index + length > len(data):
        raise CertParseError("truncated value")
    return tag, data[index : index + length], index + length


def oid_to_str(raw: bytes) -> str:
    if not raw:
        return ""
    parts = [str(raw[0] // 40), str(raw[0] % 40)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def decode_string(tag: int, raw: bytes) -> str:
    if tag == 0x1E:
        return raw.decode("utf-16-be", "replace")
    if tag == 0x1C:
        return raw.decode("utf-32-be", "replace")
    return raw.decode("utf-8", "replace")


def parse_name_pairs(content: bytes) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    index = 0
    while index < len(content):
        tag, rdn, index = der_read(content, index)
        if tag != 0x31:
            continue
        cursor = 0
        while cursor < len(rdn):
            _, atv, cursor = der_read(rdn, cursor)
            pos = 0
            _, oid_raw, pos = der_read(atv, pos)
            stag, sval, pos = der_read(atv, pos)
            label = OID_LABEL.get(oid_to_str(oid_raw), oid_to_str(oid_raw))
            pairs.append((label, decode_string(stag, sval)))
    return pairs


def format_name(pairs: list[tuple[str, str]]) -> str:
    return ", ".join(f"{label}={value}" for label, value in pairs)


def name_attr(pairs: list[tuple[str, str]], label: str) -> str:
    return "; ".join(value for key, value in pairs if key == label)


def parse_name(content: bytes) -> str:
    return format_name(parse_name_pairs(content))


def parse_time(tag: int, raw: bytes) -> datetime:
    text = raw.decode("ascii", "replace").strip()
    if tag == 0x17:
        if text.endswith("Z") and len(text) == 11:
            text = text[:10] + "00Z"
        if not text.endswith("Z") or len(text) < 13:
            raise CertParseError(f"bad UTCTime {text!r}")
        year = int(text[:2])
        year += 1900 if year >= 50 else 2000
        return datetime.strptime(f"{year}{text[2:12]}", "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    if tag == 0x18:
        body = text[:-1] if text.endswith("Z") else text
        body = body.split(".", 1)[0]
        if len(body) < 14:
            raise CertParseError(f"bad GeneralizedTime {text!r}")
        return datetime.strptime(body[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    raise CertParseError(f"not a time tag {tag}")


def parse_san(content: bytes) -> list[str]:
    if not content:
        return []
    tag, seq, _ = der_read(content, 0)
    if tag != 0x30:
        return []
    names: list[str] = []
    index = 0
    while index < len(seq):
        ntag, nval, index = der_read(seq, index)
        if ntag == 0x82:
            names.append(nval.decode("ascii", "replace"))
        elif ntag == 0x86:
            names.append(nval.decode("ascii", "replace"))
        elif ntag == 0x87:
            names.append(_format_ip(nval))
    return names


def _format_ip(raw: bytes) -> str:
    try:
        if len(raw) == 4:
            return ".".join(str(b) for b in raw)
        if len(raw) == 16:
            return socket.inet_ntop(socket.AF_INET6, raw)
    except OSError:
        pass
    return raw.hex()


def parse_is_ca(content: bytes) -> bool:
    if not content:
        return False
    tag, seq, _ = der_read(content, 0)
    if tag != 0x30 or not seq:
        return False
    ttag, value, _ = der_read(seq, 0)
    if ttag == 0x01:
        return value != b"\x00"
    return False


def parse_extensions(content: bytes | None) -> tuple[list[str], bool]:
    if not content:
        return [], False
    tag, seq, _ = der_read(content, 0)
    if tag != 0x30:
        return [], False
    sans: list[str] = []
    is_ca = False
    index = 0
    while index < len(seq):
        _, ext, index = der_read(seq, index)
        pos = 0
        _, oid_raw, pos = der_read(ext, pos)
        oid = oid_to_str(oid_raw)
        etag, value, nxt = der_read(ext, pos)
        if etag == 0x01:
            etag, value, nxt = der_read(ext, nxt)
        if etag != 0x04:
            continue
        if oid == "2.5.29.17":
            sans = parse_san(value)
        elif oid == "2.5.29.19":
            is_ca = parse_is_ca(value)
    return sans, is_ca


def parse_cert(der: bytes) -> CertInfo:
    tag, body, _ = der_read(der, 0)
    if tag != 0x30:
        raise CertParseError("not a certificate")
    tag, tbs, _ = der_read(body, 0)
    if tag != 0x30:
        raise CertParseError("not a TBSCertificate")
    index = 0
    tag, _, index = der_read(tbs, index)
    if tag == 0xA0:
        tag, _, index = der_read(tbs, index)
    if tag != 0x02:
        raise CertParseError("missing serial")
    serial = _.hex()
    _, _, index = der_read(tbs, index)
    tag, issuer, index = der_read(tbs, index)
    tag, validity, index = der_read(tbs, index)
    tag, subject, index = der_read(tbs, index)
    if index < len(tbs):
        _, _, index = der_read(tbs, index)
    extensions = None
    while index < len(tbs):
        tag, value, index = der_read(tbs, index)
        if tag == 0xA3:
            extensions = value
    vpos = 0
    nb_tag, nb_val, vpos = der_read(validity, vpos)
    na_tag, na_val, vpos = der_read(validity, vpos)
    sans, is_ca = parse_extensions(extensions)
    subject_pairs = parse_name_pairs(subject)
    return CertInfo(
        serial=serial,
        fingerprint=hashlib.sha256(der).hexdigest(),
        subject=format_name(subject_pairs),
        issuer=parse_name(issuer),
        sans=sans,
        not_before=parse_time(nb_tag, nb_val),
        not_after=parse_time(na_tag, na_val),
        ca=is_ca,
        cn=name_attr(subject_pairs, "CN"),
        ou=name_attr(subject_pairs, "OU"),
    )


def days_left(not_after: datetime, now: datetime) -> int:
    seconds = (not_after - now).total_seconds()
    return int(seconds // 86400)


def status_for(days: int, threshold: int, critical: int) -> str:
    if days < 0:
        return "expired"
    if days <= critical:
        return "critical"
    if days <= threshold:
        return "warning"
    return "ok"


def role_for(index: int, info: CertInfo, key: str, source: str) -> str:
    lowered = key.lower()
    if source == "route" and "destinationca" in lowered:
        return "destination-ca"
    if "cacertificate" in lowered and "destination" not in lowered:
        return "ca"
    ca_file = (
        lowered in {"ca.crt", "ca.pem", "cacert", "ca-bundle.crt", "service-ca.crt"}
        or lowered.endswith("ca.crt")
        or "ca-bundle" in lowered
        or ".ca." in lowered
    )
    if ca_file:
        return "ca"
    # tls.crt and route certificates are the leaf even when a homemade
    # self-signed file has CA:TRUE, which `openssl req -x509` sets by default.
    if index == 0:
        return "leaf"
    return "chain"


def _service_names_for_workloads(namespace: str, workload_refs: Iterable[str], services: list[dict], workloads: list[dict]) -> list[str]:
    wanted = set(workload_refs)
    if not wanted:
        return []
    by_ref = {workload_ref(item): item for item in workloads if obj_ns(item) == namespace}
    found: list[str] = []
    for service in services:
        if obj_ns(service) != namespace:
            continue
        selector = (service.get("spec") or {}).get("selector") if isinstance(service.get("spec"), dict) else None
        if not isinstance(selector, dict) or not selector:
            continue
        for ref in wanted:
            workload = by_ref.get(ref)
            if workload and selector_matches(selector, pod_labels(workload)):
                label = f"service/{obj_name(service)}"
                if label not in found:
                    found.append(label)
                break
    return found


def analyze(
    objects: list[dict],
    context: str,
    now: datetime,
    args: argparse.Namespace,
) -> tuple[list[Finding], list[RouteMeta], ClusterSummary, list[str]]:
    errors: list[str] = []
    secrets: list[dict] = []
    configmaps: list[dict] = []
    services: list[dict] = []
    workloads: list[dict] = []
    routes: list[dict] = []
    ingresses: list[dict] = []
    for obj in objects:
        if not isinstance(obj, dict) or not obj.get("kind"):
            continue
        if not namespace_allowed(obj_ns(obj), args):
            continue
        kind = obj.get("kind")
        if kind == "Secret":
            secrets.append(obj)
        elif kind == "ConfigMap":
            configmaps.append(obj)
        elif kind == "Service":
            services.append(obj)
        elif kind in {"Deployment", "DeploymentConfig", "StatefulSet", "DaemonSet"}:
            workloads.append(obj)
        elif kind == "Route":
            routes.append(obj)
        elif kind == "Ingress":
            ingresses.append(obj)

    workloads_by_ns: dict[str, list[dict]] = defaultdict(list)
    for workload in workloads:
        workloads_by_ns[obj_ns(workload)].append(workload)

    secret_users: dict[tuple[str, str], set[str]] = defaultdict(set)
    cm_users: dict[tuple[str, str], set[str]] = defaultdict(set)
    for workload in workloads:
        ref = workload_ref(workload)
        namespace = obj_ns(workload)
        for secret_name in referenced_secrets(workload):
            secret_users[(namespace, secret_name)].add(ref)
        for cm_name in referenced_configmaps(workload):
            cm_users[(namespace, cm_name)].add(ref)

    services_by_key = {(obj_ns(service), obj_name(service)): service for service in services}

    def workloads_for_service(namespace: str, service_name: str) -> list[dict]:
        service = services_by_key.get((namespace, service_name))
        if not service:
            return []
        selector = (service.get("spec") or {}).get("selector") if isinstance(service.get("spec"), dict) else None
        if not isinstance(selector, dict) or not selector:
            return []
        return [
            workload
            for workload in workloads_by_ns.get(namespace, [])
            if selector_matches(selector, pod_labels(workload))
        ]

    serving_services: dict[tuple[str, str], set[str]] = defaultdict(set)
    for service in services:
        secret_name = annotations(service).get(SERVING_CERT_ANN)
        if not secret_name:
            continue
        namespace = obj_ns(service)
        serving_services[(namespace, str(secret_name))].add(obj_name(service))
        for workload in workloads_for_service(namespace, obj_name(service)):
            secret_users[(namespace, str(secret_name))].add(workload_ref(workload))

    route_metas: list[RouteMeta] = []

    for route in routes:
        spec = route.get("spec") if isinstance(route.get("spec"), dict) else {}
        tls = spec.get("tls") if isinstance(spec.get("tls"), dict) else {}
        namespace = obj_ns(route)
        rname = obj_name(route)
        host = str(spec.get("host") or "")
        termination = str(tls.get("termination") or "")
        service_names = _route_service_names(route)
        linked: list[str] = []
        for service_name in service_names:
            for workload in workloads_for_service(namespace, service_name):
                ref = workload_ref(workload)
                if ref not in linked:
                    linked.append(ref)
        mounted: list[str] = []
        for workload in workloads_by_ns.get(namespace, []):
            if workload_ref(workload) not in linked:
                continue
            for secret_name in sorted(referenced_secrets(workload)):
                if secret_name not in mounted:
                    mounted.append(secret_name)
        external_ref = tls.get("externalCertificate")
        if isinstance(external_ref, dict) and external_ref.get("name"):
            external = str(external_ref["name"])
            if external not in mounted:
                mounted.append(external)
            for ref in linked:
                secret_users[(namespace, external)].add(ref)
        ref = _route_label(rname, termination, host)
        inline_serials: list[str] = []
        certificate = tls.get("certificate")
        if isinstance(certificate, str):
            for der in blobs_from_text(certificate):
                try:
                    inline_serials.append(parse_cert(der).serial)
                except CertParseError:
                    continue
                break
        route_metas.append(
            RouteMeta(
                context=context,
                namespace=namespace,
                name=rname,
                host=host,
                termination=termination,
                secret_names=mounted,
                inline_serials=inline_serials,
                workloads=linked,
                services=[f"service/{item}" for item in service_names],
                ref=ref,
            )
        )

    ingress_for_secret: dict[tuple[str, str], set[str]] = defaultdict(set)
    for ingress in ingresses:
        spec = ingress.get("spec") if isinstance(ingress.get("spec"), dict) else {}
        namespace = obj_ns(ingress)
        iname = obj_name(ingress)
        hosts_for_secret: dict[str, list[str]] = defaultdict(list)
        for entry in spec.get("tls") or []:
            if isinstance(entry, dict) and entry.get("secretName"):
                hosts_for_secret[str(entry["secretName"])].extend(str(h) for h in (entry.get("hosts") or []))
        backend_workloads: list[str] = []
        backend_services: list[str] = []
        for rule in spec.get("rules") or []:
            if not isinstance(rule, dict):
                continue
            http = rule.get("http") if isinstance(rule.get("http"), dict) else {}
            for path in http.get("paths") or []:
                if not isinstance(path, dict):
                    continue
                backend = path.get("backend") if isinstance(path.get("backend"), dict) else {}
                service = backend.get("service") if isinstance(backend.get("service"), dict) else {}
                service_name = str(service.get("name") or backend.get("serviceName") or "")
                if not service_name:
                    continue
                if service_name not in backend_services:
                    backend_services.append(service_name)
                for workload in workloads_for_service(namespace, service_name):
                    ref = workload_ref(workload)
                    if ref not in backend_workloads:
                        backend_workloads.append(ref)
        for secret_name, hosts in hosts_for_secret.items():
            host = hosts[0] if hosts else ""
            ref = f"ingress/{iname}" + (f" {host}" if host else "")
            ingress_for_secret[(namespace, secret_name)].add(ref)
            for workload_ref_name in backend_workloads:
                secret_users[(namespace, secret_name)].add(workload_ref_name)

    findings: list[Finding] = []

    def add_ders(
        source: str,
        namespace: str,
        name: str,
        key: str,
        ders: list[bytes],
        workloads_for: list[str],
        services_for: list[str],
        routes_for: list[str],
        termination: str,
        notes: list[str],
    ) -> None:
        for index, der in enumerate(ders):
            try:
                info = parse_cert(der)
            except CertParseError as exc:
                errors.append(f"{context} {namespace}/{name} {key}: {exc}")
                continue
            role = role_for(index, info, key, source)
            not_yet = info.not_before > now
            days = days_left(info.not_after, now)
            finding_notes = list(notes)
            if not_yet:
                finding_notes.append(f"not valid until {info.not_before.strftime('%Y-%m-%d')}")
            if info.ca and role == "leaf":
                finding_notes.append("CA:TRUE on a leaf certificate")
            if source == "route" or role == "leaf":
                route_list = routes_for
            else:
                route_list = []
            findings.append(
                Finding(
                    context=context,
                    namespace=namespace,
                    source=source,
                    name=name,
                    key=key,
                    role=role,
                    subject=info.subject,
                    issuer=info.issuer,
                    sans=info.sans,
                    serial=info.serial,
                    fingerprint=info.fingerprint,
                    not_before=info.not_before,
                    not_after=info.not_after,
                    days_left=days,
                    not_yet_valid=not_yet,
                    ca=info.ca,
                    status=status_for(days, args.threshold_days, args.critical_days),
                    cn=info.cn,
                    ou=info.ou,
                    workloads=list(workloads_for),
                    services=list(services_for),
                    routes=list(route_list),
                    termination=termination,
                    probe="unprobed" if args.probe else "n/a",
                    notes=finding_notes,
                )
            )

    for secret in secrets:
        if str(secret.get("type") or "") in SKIP_SECRET_TYPES:
            continue
        namespace = obj_ns(secret)
        name = obj_name(secret)
        notes = []
        cert_name = annotations(secret).get(CERT_MANAGER_ANN)
        if cert_name:
            notes.append(f"cert-manager Certificate {cert_name}")
        origin = annotations(secret).get(ORIGIN_SVC_ANN)
        if origin:
            notes.append(f"service serving cert for service/{origin}")
        users = sorted(secret_users.get((namespace, name), set()))
        service_labels = [f"service/{item}" for item in sorted(serving_services.get((namespace, name), set()))]
        service_labels.extend(_service_names_for_workloads(namespace, users, services, workloads))
        service_labels = _unique(service_labels)
        route_labels: list[str] = []
        for meta_route in route_metas:
            if meta_route.namespace == namespace and name in meta_route.secret_names:
                route_labels.append(meta_route.ref)
                for service_label in meta_route.services:
                    if service_label not in service_labels:
                        service_labels.append(service_label)
        route_labels.extend(sorted(ingress_for_secret.get((namespace, name), set())))
        route_labels = _unique(route_labels)
        for key, blob in secret_material(secret).items():
            ders = extract_ders(blob)
            if not ders:
                continue
            add_ders("secret", namespace, name, key, ders, users, service_labels, route_labels, "", notes)

    for route, meta_route in zip(routes, route_metas):
        spec = route.get("spec") if isinstance(route.get("spec"), dict) else {}
        tls = spec.get("tls") if isinstance(spec.get("tls"), dict) else {}
        if not tls:
            continue
        fields = (
            ("spec.tls.certificate", tls.get("certificate")),
            ("spec.tls.caCertificate", tls.get("caCertificate")),
            ("spec.tls.destinationCACertificate", tls.get("destinationCACertificate")),
        )
        for key, value in fields:
            if not isinstance(value, str) or not value.strip():
                continue
            ders = blobs_from_text(value)
            if not ders:
                errors.append(f"{context} route {meta_route.namespace}/{meta_route.name} {key}: no certificate parsed")
                continue
            add_ders(
                "route",
                meta_route.namespace,
                meta_route.name,
                key,
                ders,
                list(meta_route.workloads),
                list(meta_route.services),
                [meta_route.ref],
                meta_route.termination,
                [],
            )

    for configmap in configmaps:
        namespace = obj_ns(configmap)
        name = obj_name(configmap)
        users = sorted(cm_users.get((namespace, name), set()))
        if not users:
            continue
        for key, blob in configmap_material(configmap).items():
            ders = extract_ders(blob)
            if not ders:
                continue
            add_ders(
                "configmap",
                namespace,
                name,
                key,
                ders,
                users,
                _service_names_for_workloads(namespace, users, services, workloads),
                [],
                "",
                ["mounted configmap"],
            )

    _annotate_duplicates(findings)
    findings.sort(key=lambda item: (item.days_left, item.context, item.namespace, item.name, item.key, item.role))
    summary = ClusterSummary(
        context=context,
        server="",
        secrets=len(secrets),
        routes=len(routes),
        workloads=len(workloads),
        certificates=len(findings),
    )
    return findings, route_metas, summary, errors


def _unique(items: list[str]) -> list[str]:
    seen: list[str] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def _route_label(name: str, termination: str, host: str) -> str:
    bits = [f"route/{name}"]
    if termination:
        bits.append(termination)
    if host:
        bits.append(host)
    return " ".join(bits)


def _route_service_names(route: dict) -> list[str]:
    spec = route.get("spec") if isinstance(route.get("spec"), dict) else {}
    names: list[str] = []

    def add(target: object) -> None:
        if not isinstance(target, dict):
            return
        if target.get("kind") not in (None, "Service"):
            return
        if target.get("name"):
            names.append(str(target["name"]))

    add(spec.get("to"))
    for alt in spec.get("alternateBackends") or []:
        add(alt)
    return names


def _annotate_duplicates(findings: list[Finding]) -> None:
    by_serial: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        if finding.serial:
            by_serial[finding.serial].append(finding)
    for serial, group in by_serial.items():
        if len(group) < 2:
            continue
        places = [f"{item.source}/{item.namespace}/{item.name}:{item.key}" for item in group]
        for finding in group:
            others = [place for place in places if place != f"{finding.source}/{finding.namespace}/{finding.name}:{finding.key}"]
            if others:
                shown = ", ".join(others[:4])
                extra = "" if len(others) <= 4 else f" (+{len(others) - 4})"
                finding.notes.append(f"same certificate also in {shown}{extra}")


def probe_host(host: str, port: int, timeout: float) -> bytes:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    except (AttributeError, ValueError):
        pass
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as secure:
            der = secure.getpeercert(binary_form=True)
    if not der:
        raise OSError("server did not present a certificate")
    return der


def _probeable(host: str) -> bool:
    if not host or "*" in host or " " in host or "/" in host:
        return False
    return True


def apply_probes(
    findings: list[Finding],
    routes: list[RouteMeta],
    args: argparse.Namespace,
    now: datetime,
    context: str,
) -> tuple[int, int, int, list[str]]:
    serials_by_secret: dict[tuple[str, str], set[str]] = defaultdict(set)
    for finding in findings:
        if finding.context == context and finding.source == "secret":
            serials_by_secret[(finding.namespace, finding.name)].add(finding.serial)

    targets: dict[tuple[str, int], list[RouteMeta]] = defaultdict(list)
    skipped = 0
    for route in routes:
        if route.context != context or not route.termination:
            continue
        if not _probeable(route.host):
            skipped += 1
            continue
        targets[(route.host, args.probe_port)].append(route)

    errors: list[str] = []
    results: dict[tuple[str, int], bytes | str] = {}
    lock = threading.Lock()

    def one(address: tuple[str, int]) -> None:
        host, port = address
        try:
            der = probe_host(host, port, args.probe_timeout)
        except (OSError, ssl.SSLError, socket.timeout, TimeoutError) as exc:
            with lock:
                results[address] = str(exc)
            return
        with lock:
            results[address] = der

    if targets:
        workers = max(1, min(args.probe_workers, len(targets)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(one, address) for address in targets]
            for future in as_completed(futures):
                future.result()

    ok = 0
    failed = 0
    served_groups: dict[str, dict] = {}
    for address, outcome in results.items():
        host_routes = targets[address]
        if isinstance(outcome, str):
            failed += 1
            shown = ", ".join(route.ref for route in host_routes[:3])
            errors.append(f"probe {address[0]}:{address[1]} failed ({shown}): {outcome}")
            continue
        ok += 1
        try:
            info = parse_cert(outcome)
        except CertParseError as exc:
            failed += 1
            errors.append(f"probe {address[0]}: {exc}")
            continue
        for route in host_routes:
            configured: set[str] = set(route.inline_serials)
            for secret_name in route.secret_names:
                configured |= serials_by_secret.get((route.namespace, secret_name), set())
            if configured and info.serial in configured:
                for item in findings:
                    if item.context == context and item.namespace == route.namespace and item.serial == info.serial:
                        item.probe = "match"
                continue
            if configured:
                for item in findings:
                    if (
                        item.context == context
                        and item.namespace == route.namespace
                        and item.serial in configured
                        and item.probe != "match"
                    ):
                        item.probe = "mismatch"
            bucket = served_groups.get(info.serial)
            if bucket is None:
                bucket = {"info": info, "routes": [], "workloads": [], "services": []}
                served_groups[info.serial] = bucket
            if route.ref not in bucket["routes"]:
                bucket["routes"].append(route.ref)
            for workload in route.workloads:
                if workload not in bucket["workloads"]:
                    bucket["workloads"].append(workload)
            for service in route.services:
                if service not in bucket["services"]:
                    bucket["services"].append(service)

    for _serial, bucket in served_groups.items():
        info = bucket["info"]
        days = days_left(info.not_after, now)
        route_refs: list[str] = bucket["routes"]
        namespace = routes_namespace(route_refs, routes)
        findings.append(
            Finding(
                context=context,
                namespace=namespace,
                source="live",
                name=route_refs[0].split()[-1] if route_refs else info.serial[:12],
                key="handshake",
                role="leaf",
                subject=info.subject,
                issuer=info.issuer,
                sans=info.sans,
                serial=info.serial,
                fingerprint=info.fingerprint,
                not_before=info.not_before,
                not_after=info.not_after,
                days_left=days,
                not_yet_valid=info.not_before > now,
                ca=info.ca,
                status=status_for(days, args.threshold_days, args.critical_days),
                cn=info.cn,
                ou=info.ou,
                workloads=list(bucket["workloads"]),
                services=list(bucket["services"]),
                routes=route_refs,
                termination="",
                probe="mismatch",
                notes=["served certificate is not the one stored on the route or its secrets — default router certificate, or a passthrough cert that is not in the cluster objects"],
            )
        )
    findings.sort(key=lambda item: (item.days_left, item.context, item.namespace, item.name, item.key, item.role))
    return ok, failed, skipped, errors


def routes_namespace(route_refs: list[str], routes: list[RouteMeta]) -> str:
    wanted = set(route_refs)
    for route in routes:
        if route.ref in wanted:
            return route.namespace
    return ""


def finding_dict(finding: Finding) -> dict:
    return {
        "context": finding.context,
        "namespace": finding.namespace,
        "source": finding.source,
        "name": finding.name,
        "key": finding.key,
        "role": finding.role,
        "subject": finding.subject,
        "issuer": finding.issuer,
        "sans": finding.sans,
        "serial": finding.serial,
        "fingerprint": finding.fingerprint,
        "notBefore": finding.not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "notAfter": finding.not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "daysLeft": finding.days_left,
        "notYetValid": finding.not_yet_valid,
        "ca": finding.ca,
        "status": finding.status,
        "workloads": finding.workloads,
        "services": finding.services,
        "routes": finding.routes,
        "termination": finding.termination,
        "probe": finding.probe,
        "notes": finding.notes,
    }


def emit_json(
    findings: list[Finding],
    summaries: list[ClusterSummary],
    errors: list[str],
    args: argparse.Namespace,
    now: datetime,
) -> None:
    payload = {
        "version": 1,
        "generatedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "thresholdDays": args.threshold_days,
        "criticalDays": args.critical_days,
        "probe": bool(args.probe),
        "summary": {
            "certificates": len(findings),
            "expired": sum(item.status == "expired" for item in findings),
            "critical": sum(item.status == "critical" for item in findings),
            "warning": sum(item.status == "warning" for item in findings),
            "ok": sum(item.status == "ok" for item in findings),
            "clusters": [
                {
                    "context": item.context,
                    "server": item.server,
                    "secrets": item.secrets,
                    "routes": item.routes,
                    "workloads": item.workloads,
                    "certificates": item.certificates,
                    "probeOk": item.probe_ok,
                    "probeFailed": item.probe_failed,
                    "probeSkipped": item.probe_skipped,
                }
                for item in summaries
            ],
        },
        "findings": [finding_dict(item) for item in _visible(findings, args)],
        "errors": errors,
    }
    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")


def service_label(item: Finding) -> str:
    """Name a non-technical reader can match to the app."""
    kind_label = {
        "deployment": "deployment",
        "deploymentconfig": "deployment",
        "statefulset": "stateful set",
        "daemonset": "daemon set",
        "service": "service",
        "route": "route",
        "ingress": "ingress",
    }

    def one(ref: str) -> str:
        kind, sep, name = ref.partition("/")
        if not sep:
            return ref
        return f"{name} ({kind_label.get(kind, kind)})"

    names: list[str] = []
    for ref in item.workloads:
        label = one(ref)
        if label not in names:
            names.append(label)
    if not names:
        for ref in item.services:
            label = one(ref)
            if label not in names:
                names.append(label)
    if not names:
        for ref in item.routes:
            label = one(ref.split()[0])
            if label not in names:
                names.append(label)
    if not names:
        return item.name
    return "; ".join(names)


def emit_csv(findings: list[Finding], dest) -> int:
    fields = [
        "Service/API/Deployment",
        "Issued CN",
        "SAN",
        "Issued OU",
        "Validate Date",
        "Expired Date",
        "Days Left Until Expired",
    ]
    writer = csv.DictWriter(dest, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    seen: set[tuple[str, ...]] = set()
    written = 0
    for item in findings:
        if item.role != "leaf":
            continue
        row = {
            "Service/API/Deployment": service_label(item),
            "Issued CN": item.cn,
            "SAN": " ".join(item.sans),
            "Issued OU": item.ou,
            "Validate Date": item.not_before.strftime("%Y-%m-%d"),
            "Expired Date": item.not_after.strftime("%Y-%m-%d"),
            "Days Left Until Expired": item.days_left,
        }
        key = tuple(str(row[field]) for field in fields)
        if key in seen:
            continue
        seen.add(key)
        writer.writerow(row)
        written += 1
    return written


def write_csv_file(path_text: str, findings: list[Finding]) -> int:
    path = Path(path_text)
    try:
        with path.open("w", encoding="utf-8", newline="") as handle:
            return emit_csv(findings, handle)
    except OSError as exc:
        raise ScanError(f"cannot write {path}: {exc}") from exc


def _color(text: str, code: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"\033[{code}m{text}\033[0m"


def _status_color(status: str) -> str:
    return {"expired": "31", "critical": "31", "warning": "33", "ok": "32"}.get(status, "0")


def _visible(findings: list[Finding], args: argparse.Namespace) -> list[Finding]:
    if args.quiet:
        return [item for item in findings if item.status != "ok"]
    return findings


def _fmt_sans(sans: list[str], full: bool) -> str:
    if not sans:
        return ""
    if full or len(sans) <= 4:
        return ", ".join(sans)
    return ", ".join(sans[:4]) + f" (+{len(sans) - 4})"


def emit_human(
    findings: list[Finding],
    summaries: list[ClusterSummary],
    errors: list[str],
    args: argparse.Namespace,
    now: datetime,
) -> None:
    color_on = sys.stdout.isatty() and not args.no_color and not args.json
    print(
        f"OpenShift certificate expiry   window {args.threshold_days}d   critical ≤ {args.critical_days}d   as of {now.strftime('%Y-%m-%d %H:%MZ')}"
    )
    for summary in summaries:
        server = f"  {summary.server}" if summary.server else ""
        print(
            f"\n{summary.context}{server}\n"
            f"  secrets {summary.secrets}   routes {summary.routes}   workloads {summary.workloads}   certificates {summary.certificates}"
        )
        if args.probe:
            print(
                f"  probe ok {summary.probe_ok}   failed {summary.probe_failed}   skipped {summary.probe_skipped}"
            )
    counts = {
        "expired": sum(item.status == "expired" for item in findings),
        "critical": sum(item.status == "critical" for item in findings),
        "warning": sum(item.status == "warning" for item in findings),
        "ok": sum(item.status == "ok" for item in findings),
    }
    print(
        "\n"
        + "   ".join(
            _color(f"{name} {count}", _status_color(name), color_on) for name, count in counts.items()
        )
    )
    shown = _visible(findings, args)
    if not findings:
        print(
            "\nNo certificates found. Confirm `oc` can list secrets in these namespaces. cluster-reader cannot."
        )
    elif not shown:
        print("\nNothing expires inside the window.")
    elif args.by_workload:
        _emit_by_workload(shown, args, color_on)
    else:
        print()
        for item in shown:
            _emit_finding(item, args, color_on)
    if errors:
        print("\nNotes", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)


def _emit_finding(item: Finding, args: argparse.Namespace, color_on: bool) -> None:
    when = item.not_after.strftime("%Y-%m-%d")
    label = _color(f"{item.status.upper():<8} {item.days_left:>5}d  {when}", _status_color(item.status), color_on)
    where = f"{item.context}  {item.namespace}/{item.name}  {item.source} {item.key}  {item.role}"
    print(f"{label}  {where}")
    print(f"           {item.subject or '(no subject)'}")
    sans = _fmt_sans(item.sans, args.full)
    if sans:
        print(f"           SAN {sans}")
    if item.workloads:
        print(f"           workloads  {'  '.join(item.workloads)}")
    if item.routes:
        print(f"           routes     {'  |  '.join(item.routes)}")
    if item.services:
        print(f"           services   {'  '.join(item.services)}")
    if item.probe not in {"n/a", "unprobed"}:
        print(f"           probe      {item.probe}")
    for note in item.notes:
        print(f"           note       {note}")


def _emit_by_workload(findings: list[Finding], args: argparse.Namespace, color_on: bool) -> None:
    groups: dict[str, list[Finding]] = defaultdict(list)
    loose: list[Finding] = []
    for item in findings:
        if not item.workloads:
            loose.append(item)
            continue
        for workload in item.workloads:
            groups[f"{item.context}  {item.namespace}  {workload}"].append(item)
    for title in sorted(groups):
        print(f"\n{title}")
        for item in groups[title]:
            _emit_finding(item, args, color_on)
    if loose:
        print("\nNot linked to a workload")
        for item in loose:
            _emit_finding(item, args, color_on)


def worst_status(findings: list[Finding]) -> int:
    if any(item.status in {"expired", "critical", "warning"} for item in findings):
        return 2
    return 0


def scan_context(args: argparse.Namespace, context: str, objects: list[dict], now: datetime) -> tuple[list[Finding], ClusterSummary, list[str]]:
    findings, routes, summary, errors = analyze(objects, context, now, args)
    if args.probe:
        ok, failed, skipped, probe_errors = apply_probes(findings, routes, args, now, context)
        summary.probe_ok = ok
        summary.probe_failed = failed
        summary.probe_skipped = skipped
        errors.extend(probe_errors)
    return findings, summary, errors


def collect_live(args: argparse.Namespace, context: str) -> list[dict]:
    objects: list[dict] = []
    namespaces = args.namespace or [None]
    for resource in RESOURCES:
        for namespace in namespaces:
            if not args.quiet:
                where = namespace or "all namespaces"
                print(f"reading {resource} from {context} ({where})", file=sys.stderr)
            objects.extend(oc_json(args, context, resource, namespace))
    return objects


def run_self_test() -> int:
    pem = """-----BEGIN CERTIFICATE-----
MIIBUTCCARugAwIBAgIBBzANBgkqhkiG9w0BAQsFADBCMScwJQYDVQQDDB5jaGVja291dC5hcHBz
LnByb2QuZXhhbXBsZS5jb20xFzAVBgNVBAoMDkV4YW1wbGUgQWdlbmN5MB4XDTI2MDEwMTAwMDAw
MFoXDTI2MTAzMDEyMDAwMFowQjEnMCUGA1UEAwweY2hlY2tvdXQuYXBwcy5wcm9kLmV4YW1wbGUu
Y29tMRcwFQYDVQQKDA5FeGFtcGxlIEFnZW5jeTAUMA0GCSqGSIb3DQEBAQUAAwMAMACjRDBCMEAG
A1UdEQQ5MDeCHmNoZWNrb3V0LmFwcHMucHJvZC5leGFtcGxlLmNvbYIVY2hlY2tvdXQucGF5bWVu
dHMuc3ZjMA0GCSqGSIb3DQEBCwUAAyEAq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=
-----END CERTIFICATE-----
"""
    ders = extract_ders(pem.encode())
    if len(ders) != 1:
        print("self-test: PEM was not extracted", file=sys.stderr)
        return 1
    info = parse_cert(ders[0])
    expected_after = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
    problems = []
    if info.not_after != expected_after:
        problems.append(f"notAfter {info.not_after} != {expected_after}")
    if "checkout.apps.prod.example.com" not in info.subject:
        problems.append(f"subject {info.subject}")
    if info.sans != ["checkout.apps.prod.example.com", "checkout.payments.svc"]:
        problems.append(f"sans {info.sans}")
    if info.serial != "07":
        problems.append(f"serial {info.serial}")
    now = datetime(2026, 10, 24, 0, 0, tzinfo=timezone.utc)
    if days_left(info.not_after, now) != 6:
        problems.append(f"days {days_left(info.not_after, now)}")
    if problems:
        print("self-test failed:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print("self-test ok")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    now = parse_now(args.now)
    all_findings: list[Finding] = []
    summaries: list[ClusterSummary] = []
    errors: list[str] = []
    try:
        if args.from_json:
            specs = args.from_json
            for index, spec in enumerate(specs):
                default = args.context_name if len(specs) == 1 else f"cluster-{index + 1}"
                context, objects = load_offline(spec, default)
                findings, summary, cluster_errors = scan_context(args, context, objects, now)
                all_findings.extend(findings)
                summaries.append(summary)
                errors.extend(cluster_errors)
        else:
            for context in list_contexts(args):
                objects = collect_live(args, context)
                findings, summary, cluster_errors = scan_context(args, context, objects, now)
                summary.server = server_url(args, context)
                all_findings.extend(findings)
                summaries.append(summary)
                errors.extend(cluster_errors)
    except ScanError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    all_findings.sort(key=lambda item: (item.days_left, item.context, item.namespace, item.name, item.key))
    machine = bool(args.json or args.csv or args.output)
    rows = _visible(all_findings, args) if (machine and args.quiet) else all_findings
    csv_stdout = args.csv == "-"
    csv_path = args.output or (None if args.csv in (None, "-") else args.csv)
    if csv_path:
        try:
            written = write_csv_file(csv_path, rows)
        except ScanError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(f"wrote {written} rows to {csv_path}", file=sys.stderr)
    if args.json:
        emit_json(rows, summaries, errors, args, now)
    elif csv_stdout:
        emit_csv(rows, sys.stdout)
    elif not args.csv:
        emit_human(all_findings, summaries, errors, args, now)
    return worst_status(all_findings)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        sys.exit(130)
