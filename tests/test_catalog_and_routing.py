"""Unit tests for Catalog Resolver golden table and Policy Routing planner/verifier."""

from __future__ import annotations

import socket
import sys
import unittest
from pathlib import Path
from typing import Any

SRC_ROOT = Path(__file__).resolve().parent.parent / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from surfshark_lite.catalog import Resolver, parse_clusters
from surfshark_lite.tunnel import build_spec, routing

SAMPLE_CLUSTERS_RAW: list[dict[str, Any]] = [
    {
        "id": "c-us-sfo",
        "connectionName": "us-sfo.prod.surfshark.com",
        "country": "United States",
        "countryCode": "US",
        "location": "San Francisco",
        "load": 22,
        "pubKey": "o07k/2dsaQkLLSR0dCI/FUd3FLik/F/HBBcOGUkNQGo=",
        "tags": ["physical"],
        "type": "generic",
        "coordinates": {"latitude": 37.77, "longitude": -122.41},
    },
    {
        "id": "c-us-nyc",
        "connectionName": "us-nyc.prod.surfshark.com",
        "country": "United States",
        "countryCode": "US",
        "location": "New York",
        "load": 15,
        "pubKey": "o07k/2dsaQkLLSR0dCI/FUd3FLik/F/HBBcOGUkNQGo=",
        "tags": ["physical"],
        "type": "generic",
        "coordinates": {"latitude": 40.71, "longitude": -74.00},
    },
    {
        "id": "c-gb-lon",
        "connectionName": "uk-lon.prod.surfshark.com",
        "country": "United Kingdom",
        "countryCode": "GB",
        "location": "London",
        "load": 18,
        "pubKey": "o07k/2dsaQkLLSR0dCI/FUd3FLik/F/HBBcOGUkNQGo=",
        "tags": ["physical"],
        "type": "generic",
        "coordinates": {"latitude": 51.50, "longitude": -0.12},
    },
    {
        "id": "c-de-fra",
        "connectionName": "de-fra.prod.surfshark.com",
        "country": "Germany",
        "countryCode": "DE",
        "location": "Frankfurt am Main",
        "load": 12,
        "pubKey": "o07k/2dsaQkLLSR0dCI/FUd3FLik/F/HBBcOGUkNQGo=",
        "tags": ["physical"],
        "type": "generic",
        "coordinates": {"latitude": 50.11, "longitude": 8.68},
    },
    {
        "id": "c-jp-tyo",
        "connectionName": "jp-tyo.prod.surfshark.com",
        "country": "Japan",
        "countryCode": "JP",
        "location": "Tokyo",
        "load": 10,
        "pubKey": "o07k/2dsaQkLLSR0dCI/FUd3FLik/F/HBBcOGUkNQGo=",
        "tags": ["physical"],
        "type": "generic",
        "coordinates": {"latitude": 35.68, "longitude": 139.69},
    },
    {
        "id": "c-cr-sjo",
        "connectionName": "cr-sjo.prod.surfshark.com",
        "country": "Costa Rica",
        "countryCode": "CR",
        "location": "San Jose",
        "load": 25,
        "pubKey": "o07k/2dsaQkLLSR0dCI/FUd3FLik/F/HBBcOGUkNQGo=",
        "tags": ["physical"],
        "type": "generic",
    },
    {
        "id": "c-us-sjc",
        "connectionName": "us-sjc.prod.surfshark.com",
        "country": "United States",
        "countryCode": "US",
        "location": "San Jose",
        "load": 30,
        "pubKey": "o07k/2dsaQkLLSR0dCI/FUd3FLik/F/HBBcOGUkNQGo=",
        "tags": ["physical"],
        "type": "generic",
    },
]


class TestCatalogAndRouting(unittest.TestCase):
    def test_resolver_golden_queries(self) -> None:
        clusters = parse_clusters(SAMPLE_CLUSTERS_RAW)
        resolver = Resolver(clusters)

        # 1. Airport/city code 'sfo' -> San Francisco
        r_sfo = resolver.resolve("sfo")
        self.assertIsNotNone(r_sfo.choice)
        assert r_sfo.choice is not None
        self.assertEqual(r_sfo.choice.id, "c-us-sfo")
        self.assertFalse(r_sfo.ambiguous)

        # 2. Country alias 'uk' -> GB (London)
        r_uk = resolver.resolve("uk")
        assert r_uk.choice is not None
        self.assertEqual(r_uk.choice.country_code, "GB")
        self.assertEqual(r_uk.scope, "country")

        # 3. Short city name 'frankfurt' -> 'Frankfurt am Main'
        r_fra = resolver.resolve("frankfurt")
        assert r_fra.choice is not None
        self.assertEqual(r_fra.choice.id, "c-de-fra")

        # 4. 'fastest us' -> picks lowest load or lowest RTT in US
        r_us = resolver.resolve("fastest us", latencies={"us-sfo.prod.surfshark.com": 12.0, "us-nyc.prod.surfshark.com": 75.0})
        assert r_us.choice is not None
        self.assertEqual(r_us.choice.id, "c-us-sfo")

        # 5. 'last' -> resolves to last_cluster_id
        r_last = resolver.resolve("last", last_cluster_id="c-jp-tyo")
        assert r_last.choice is not None
        self.assertEqual(r_last.choice.id, "c-jp-tyo")

        # 6. Ambiguous city 'san jose' (US vs CR)
        r_amb = resolver.resolve("san jose")
        self.assertTrue(r_amb.ambiguous)
        self.assertGreaterEqual(len(r_amb.candidates), 2)

    def test_policy_routing_plan_and_verify(self) -> None:
        clusters = parse_clusters(SAMPLE_CLUSTERS_RAW)
        spec = build_spec(
            cluster=clusters[0],
            private_key="cHJpdi1rZXk=",
            server_ip="198.51.100.10",
            settings={
                "cleanweb": True,
                "ipv6_guard": True,
                "lan_bypass": "lan",
                "fwmark": 300000,
                "route_table": 300000,
                "rule_priority_base": 30000,
            },
            aux_ip="198.51.100.20",
            aux_pubkey="o07k/2dsaQkLLSR0dCI/FUd3FLik/F/HBBcOGUkNQGo=",
        )
        rules4 = routing.plan(spec, socket.AF_INET)
        prios4 = [r.priority for r in rules4]
        self.assertIn(30000, prios4)  # 10.14.0.0/16 tunnel subnet
        self.assertIn(30001, prios4)  # 172.16.0.36/32 aux peer
        self.assertIn(30010, prios4)  # 10.0.0.0/8 LAN bypass
        self.assertIn(30020, prios4)  # suppress_prefixlength 0
        self.assertIn(30021, prios4)  # inverted fwmark 300000 -> table 300000

        rules6 = routing.plan(spec, socket.AF_INET6)
        self.assertEqual(len(rules6), 5)

        # Simulate matching kernel ip -j rule show & route show output
        def _fake_ip_ok(args: list[str]) -> Any:
            is_v6 = "-6" in args
            if "rule" in args:
                planned = rules6 if is_v6 else rules4
                out = []
                for pr in planned:
                    entry: dict[str, Any] = {
                        "priority": pr.priority,
                        "table": "main" if pr.table == 254 else str(pr.table),
                    }
                    if pr.invert:
                        entry["not"] = None
                    if pr.fwmark is not None:
                        entry["fwmark"] = hex(pr.fwmark)
                    if pr.suppress_prefixlength is not None:
                        entry["suppress_prefixlength"] = pr.suppress_prefixlength
                    if pr.to_prefix:
                        addr, plen = pr.to_prefix.split("/")
                        entry["dst"] = addr
                        entry["dstlen"] = int(plen)
                    out.append(entry)
                return out
            if "route" in args:
                return [{"dst": "default", "dev": spec.iface}]
            return []

        drifts_ok = routing.verify(spec, ip_runner=_fake_ip_ok)
        self.assertEqual(drifts_ok, [])

        # Simulate missing table route -> drift detected
        drifts_bad = routing.verify(spec, ip_runner=lambda _a: [])
        self.assertGreater(len(drifts_bad), 0)


if __name__ == "__main__":
    unittest.main()
