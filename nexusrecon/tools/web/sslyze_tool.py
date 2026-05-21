"""TLS/SSL analysis via sslyze — cipher suites, vulnerabilities, certificate chain."""
from __future__ import annotations

import asyncio
from typing import Any

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


def _run_sslyze_sync(target: str) -> dict[str, Any]:
    """Synchronous sslyze execution (wrapped in asyncio.to_thread)."""
    try:
        from sslyze import (
            Scanner,
            ServerNetworkLocation,
            ServerScanRequest,
        )
        from sslyze.plugins.scan_commands import ScanCommand
    except ImportError:
        return {"error": "sslyze not installed — run: pip install sslyze"}

    try:
        location = ServerNetworkLocation(hostname=target, port=443)
        request = ServerScanRequest(
            server_location=location,
            scan_commands={
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.HEARTBLEED,
                ScanCommand.ROBOT,
                ScanCommand.OPENSSL_CCS_INJECTION,
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.TLS_COMPRESSION,
            },
        )
        scanner = Scanner()
        scanner.queue_scans([request])

        supported_protocols: list[str] = []
        weak_ciphers: list[str] = []
        vulnerabilities: list[str] = []
        cert_chain: dict[str, Any] = {}

        for scan_result in scanner.get_results():
            if scan_result.scan_status.name == "ERROR_NO_CONNECTIVITY":
                return {"error": f"Cannot connect to {target}:443"}

            scan = scan_result.scan_result

            # Protocols
            for cmd, label in [
                (ScanCommand.SSL_2_0_CIPHER_SUITES, "SSLv2"),
                (ScanCommand.SSL_3_0_CIPHER_SUITES, "SSLv3"),
                (ScanCommand.TLS_1_0_CIPHER_SUITES, "TLSv1.0"),
                (ScanCommand.TLS_1_1_CIPHER_SUITES, "TLSv1.1"),
                (ScanCommand.TLS_1_2_CIPHER_SUITES, "TLSv1.2"),
                (ScanCommand.TLS_1_3_CIPHER_SUITES, "TLSv1.3"),
            ]:
                result = getattr(scan, cmd.value, None)
                if result and not isinstance(result, Exception):
                    accepted = getattr(result, "accepted_cipher_suites", [])
                    if accepted:
                        supported_protocols.append(label)
                        if label in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"):
                            for cs in accepted:
                                name = getattr(cs.cipher_suite, "name", str(cs))
                                weak_ciphers.append(f"{label}:{name}")

            # Vulnerabilities
            for cmd, vuln_name in [
                (ScanCommand.HEARTBLEED, "heartbleed"),
                (ScanCommand.ROBOT, "robot"),
                (ScanCommand.OPENSSL_CCS_INJECTION, "ccs_injection"),
            ]:
                r = getattr(scan, cmd.value, None)
                if r and not isinstance(r, Exception):
                    is_vuln = getattr(r, "is_vulnerable_to_heartbleed", None)
                    if is_vuln is None:
                        is_vuln = getattr(r, "robot_result", None)
                        if is_vuln is not None:
                            from sslyze.plugins.robot.implementation import RobotScanResultEnum
                            is_vuln = is_vuln not in (
                                RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE,
                                RobotScanResultEnum.NOT_VULNERABLE_RSA_NOT_SUPPORTED,
                            )
                    if is_vuln is None:
                        is_vuln = getattr(r, "is_vulnerable_to_ccs_injection", None)
                    if is_vuln:
                        vulnerabilities.append(vuln_name)

            # Certificate info
            cert_result = getattr(scan, ScanCommand.CERTIFICATE_INFO.value, None)
            if cert_result and not isinstance(cert_result, Exception):
                try:
                    dep = cert_result.certificate_deployments[0]
                    leaf = dep.verified_certificate_chain[0] if dep.verified_certificate_chain else None
                    if leaf:
                        cert_chain = {
                            "subject": str(leaf.subject.rfc4514_string()),
                            "issuer": str(leaf.issuer.rfc4514_string()),
                            "not_before": str(leaf.not_valid_before_utc),
                            "not_after": str(leaf.not_valid_after_utc),
                            "chain_length": len(dep.verified_certificate_chain),
                        }
                except Exception:
                    pass

        # Compute grade
        if "heartbleed" in vulnerabilities or "ccs_injection" in vulnerabilities:
            grade = "F"
        elif "SSLv2" in supported_protocols or "SSLv3" in supported_protocols:
            grade = "F"
        elif "TLSv1.0" in supported_protocols or "TLSv1.1" in supported_protocols:
            grade = "C"
        elif weak_ciphers:
            grade = "B"
        else:
            grade = "A"

        return {
            "supported_protocols": supported_protocols,
            "weak_ciphers": weak_ciphers[:20],
            "vulnerabilities": vulnerabilities,
            "cert_chain": cert_chain,
            "grade": grade,
        }

    except Exception as exc:
        return {"error": str(exc)}


@register_tool
class SSLyzeTool(OSINTTool):
    name = "sslyze"
    tier = Tier.T1
    category = Category.WEB
    requires_keys = []
    description = "TLS/SSL analysis: cipher suites, legacy protocols, vulnerabilities, certificate info"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        result = await asyncio.to_thread(_run_sslyze_sync, target)
        if "error" in result:
            return ToolResult(success=False, source=self.name, error=result["error"])

        vuln_count = len(result.get("vulnerabilities", [])) + len(result.get("weak_ciphers", []))
        return ToolResult(
            success=True,
            source=self.name,
            data={"target": target, **result},
            result_count=vuln_count,
        )
