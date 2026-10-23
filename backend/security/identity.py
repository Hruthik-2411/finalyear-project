"""Module 1 - Identity verification.

A local FinSecure Certificate Authority issues every agent an X.509 certificate
(CN = agent id, OU = role, RSA-2048 key). Every envelope is signed with RSA-PSS/SHA-256.
The gateway checks: issued by our CA, not expired, not revoked, signature valid, and that
the role inside the certificate matches the claimed sender. The role is taken from the
certificate, never from the message.
"""
from __future__ import annotations

import base64
import datetime as dt
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from backend.config import DATA_DIR

PKI_DIR = DATA_DIR / "pki"
AGENTS = {
    "orchestrator": "orchestrator",
    "planner": "planner",
    "researcher": "researcher",
    "executor": "executor",
    "auditor": "auditor",
    "gateway": "gateway",      # signs intent tokens
    "ledger": "ledger",        # signs Merkle roots
}
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def _write_key(path: Path, key) -> None:
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))


def _new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@dataclass
class AgentIdentity:
    name: str
    role: str
    key: object
    cert: x509.Certificate

    @property
    def cert_pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def serial(self) -> str:
        return format(self.cert.serial_number, "x")

    def sign(self, data: bytes) -> str:
        return base64.b64encode(self.key.sign(data, PSS, hashes.SHA256())).decode()


@dataclass
class CertCheck:
    ok: bool
    reason: str
    name: str = ""
    role: str = ""
    serial: str = ""


class CertificateAuthority:
    def __init__(self, directory: Path = PKI_DIR) -> None:
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)
        key_p, cert_p = self.dir / "ca_key.pem", self.dir / "ca_cert.pem"
        if key_p.exists() and cert_p.exists():
            self.key = serialization.load_pem_private_key(key_p.read_bytes(), password=None)
            self.cert = x509.load_pem_x509_certificate(cert_p.read_bytes())
        else:
            self.key = _new_key()
            name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FinSecure"),
                              x509.NameAttribute(NameOID.COMMON_NAME, "FinSecure Root CA")])
            now = dt.datetime.now(dt.timezone.utc)
            self.cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                         .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                         .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=3650))
                         .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                         .sign(self.key, hashes.SHA256()))
            _write_key(key_p, self.key)
            cert_p.write_bytes(self.cert.public_bytes(serialization.Encoding.PEM))

    def issue(self, name: str, role: str, days: int = 365, key=None, valid_from: dt.datetime | None = None) -> AgentIdentity:
        key = key or _new_key()
        now = valid_from or dt.datetime.now(dt.timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FinSecure"),
                             x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, role),
                             x509.NameAttribute(NameOID.COMMON_NAME, name)])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(self.cert.subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=days))
                .sign(self.key, hashes.SHA256()))
        return AgentIdentity(name, role, key, cert)

    def load_or_issue(self, name: str, role: str) -> AgentIdentity:
        kp, cp = self.dir / f"{name}_key.pem", self.dir / f"{name}_cert.pem"
        if kp.exists() and cp.exists():
            key = serialization.load_pem_private_key(kp.read_bytes(), password=None)
            cert = x509.load_pem_x509_certificate(cp.read_bytes())
            if cert.not_valid_after_utc > dt.datetime.now(dt.timezone.utc):
                return AgentIdentity(name, role, key, cert)
        ident = self.issue(name, role)
        _write_key(kp, ident.key)
        cp.write_bytes(ident.cert.public_bytes(serialization.Encoding.PEM))
        return ident

    # ------------------------------------------------------------------ verification
    def check_certificate(self, cert_pem: str, revoked: set[str], now: dt.datetime | None = None) -> CertCheck:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode())
        except Exception:
            return CertCheck(False, "certificate could not be parsed")
        serial = format(cert.serial_number, "x")
        try:
            cert.verify_directly_issued_by(self.cert)
        except (ValueError, TypeError, InvalidSignature):
            return CertCheck(False, "certificate not issued by FinSecure CA", serial=serial)
        now = now or dt.datetime.now(dt.timezone.utc)
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            return CertCheck(False, "certificate expired or not yet valid", serial=serial)
        if serial in revoked:
            return CertCheck(False, "certificate revoked", serial=serial)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        return CertCheck(True, "certificate valid", cn[0].value if cn else "", ou[0].value if ou else "", serial)

    @staticmethod
    def verify_signature(cert_pem: str, data: bytes, signature_b64: str) -> bool:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode())
            cert.public_key().verify(base64.b64decode(signature_b64), data, PSS, hashes.SHA256())
            return True
        except Exception:
            return False


class IdentityRegistry:
    """Loads the CA and one identity per agent (generated on first run, kept in data/pki)."""

    def __init__(self) -> None:
        self.ca = CertificateAuthority()
        self.identities = {name: self.ca.load_or_issue(name, role) for name, role in AGENTS.items()}

    def get(self, name: str) -> AgentIdentity:
        return self.identities[name]


_REGISTRY: IdentityRegistry | None = None


def registry() -> IdentityRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = IdentityRegistry()
    return _REGISTRY
