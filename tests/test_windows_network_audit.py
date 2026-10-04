"""Stdlib offline tests; only public script/docs and synthetic metadata are used.

Native tests (if PowerShell is available) mock every system query; no real system
inventory, private file/config, network connection, driver or capture operation.
The real read-only smoke is a separate explicit operator action, not this suite.
"""

import base64
import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "windows_network_audit.ps1").read_text(encoding="utf-8")
DOC = (ROOT / "WINDOWS_NETWORK_READINESS.md").read_text(encoding="utf-8")
POWERSHELL = next((path for name in ("powershell.exe", "pwsh", "powershell")
                   if (path := shutil.which(name))), None)
SCRIPT_PATH = str(ROOT / "windows_network_audit.ps1")
if POWERSHELL and POWERSHELL.lower().endswith(".exe") and SCRIPT_PATH.startswith("/mnt/"):
    # WSL-to-Windows path for this public source file only; no private inputs.
    SCRIPT_PATH = SCRIPT_PATH[5].upper() + ":\\" + SCRIPT_PATH[7:].replace("/", "\\")
SCRIPT_PATH = SCRIPT_PATH.replace("'", "''")
SECTIONS = ("elevation", "adapters", "services", "firewall_profiles",
            "firewall_rules", "group_policy", "npcap_driver", "capture_tools")
PRIVATE_SENTINEL = "synthetic-private-name 192.0.2.99 secret-fixture-not-real"


def encoded(value):
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def run_powershell(code):
    script = "$ProgressPreference='SilentlyContinue';" + code
    command = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    result = subprocess.run(
        [POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", command],
        capture_output=True, timeout=90, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"PowerShell exit {result.returncode}: "
                             f"{result.stderr.decode('utf-8', errors='replace')}")
    return json.loads(result.stdout.decode("utf-8-sig").strip())


def fixture():
    profiles = [dict(Name=name, Enabled=True, DefaultOutboundAction="Block",
                     AllowLocalFirewallRules=True, AllowLocalIPsecRules=False)
                for name in ("Domain", "Private", "Public")]
    return dict(
        elevated=False,
        adapters=[dict(InterfaceDescription="Wintun " + PRIVATE_SENTINEL, Status="Up",
                       HardwareInterface=False, Name=PRIVATE_SENTINEL),
                  dict(InterfaceDescription="Ethernet", Status="Disconnected",
                       HardwareInterface=True, Name=PRIVATE_SENTINEL)],
        services=[dict(Name="sing-box", DisplayName=PRIVATE_SENTINEL, Status="Running"),
                  dict(Name="Hiddify", DisplayName=PRIVATE_SENTINEL, Status="Stopped"),
                  dict(Name="MpsSvc", DisplayName="Firewall", Status="Running"),
                  dict(Name="BFE", DisplayName="Filtering Engine", Status="Running")],
        profiles=profiles,
        rules=[dict(Enabled=True, Direction="Outbound", Action="Allow",
                    PolicyStoreSourceType="GroupPolicy", Name=PRIVATE_SENTINEL),
               dict(Enabled=True, Direction="Outbound", Action="Block",
                    PolicyStoreSourceType="Local", Name=PRIVATE_SENTINEL),
               dict(Enabled=False, Direction="Outbound", Action="Allow",
                    PolicyStoreSourceType="Local", Name=PRIVATE_SENTINEL),
               dict(Enabled=True, Direction="Inbound", Action="Allow",
                    PolicyStoreSourceType="Local", Name=PRIVATE_SENTINEL)],
        rsop=[dict(Name="Domain", DefaultOutboundAction="Block",
                   AllowLocalFirewallRules=False, AllowLocalIPsecRules=False)],
        drivers=[dict(Name="npcap", State="Running", PathName=PRIVATE_SENTINEL)],
        pktmon=True,
    )


def audit(data, failures=(), extra=""):
    # Define system mocks before dot-sourcing as an additional no-native-query guard.
    code = """
$ErrorActionPreference='Stop'
$f = ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__DATA__')))
$failures = @(__FAILURES__)
function Assert-MockQuery($Name) {
    if ($failures -contains $Name) { throw '__PRIVATE__' }
}
function Get-NetAdapter {
    [CmdletBinding()]param([switch]$IncludeHidden)
    Assert-MockQuery 'adapters'
    if (-not $IncludeHidden) { throw 'IncludeHidden required' }
    $f.adapters
}
function Get-Service {
    [CmdletBinding()]param()
    Assert-MockQuery 'services'
    $f.services
}
function Get-NetFirewallProfile {
    [CmdletBinding()]param($PolicyStore)
    if ($PolicyStore -eq 'ActiveStore') { Assert-MockQuery 'profiles'; $f.profiles }
    elseif ($PolicyStore -eq 'RSOP') { Assert-MockQuery 'rsop'; $f.rsop }
    else { throw 'Unexpected policy store' }
}
function Get-NetFirewallRule {
    [CmdletBinding()]param($PolicyStore, [switch]$TracePolicyStore)
    Assert-MockQuery 'rules'
    if ($PolicyStore -ne 'ActiveStore' -or -not $TracePolicyStore) { throw 'Wrong rule store' }
    $f.rules
}
function Get-CimInstance {
    [CmdletBinding()]param($ClassName, $Filter, $Property)
    Assert-MockQuery 'drivers'
    if ($ClassName -ne 'Win32_SystemDriver' -or $Filter -ne "Name = 'npcap'") {
        throw 'Unexpected CIM query'
    }
    if (($Property -join ',') -ne 'Name,State') { throw 'Unexpected driver properties' }
    $f.drivers
}
function Get-Command {
    [CmdletBinding()]param($Name, $CommandType)
    Assert-MockQuery 'pktmon'
    if ($Name -ne 'pktmon.exe' -or $CommandType -ne 'Application') { throw 'Unexpected lookup' }
    if ($f.pktmon) { [pscustomobject]@{Name='pktmon.exe';Source='__PRIVATE__'} }
}
. ([scriptblock]::Create([IO.File]::ReadAllText('__SCRIPT_PATH__')))
function Get-AuditElevation {
    Assert-MockQuery 'elevation'
    $f.elevated
}
__EXTRA__
Invoke-WindowsNetworkAudit | ConvertTo-Json -Depth 6 -Compress
"""
    code = (code.replace("__DATA__", encoded(json.dumps(data)))
            .replace("__SCRIPT_PATH__", SCRIPT_PATH)
            .replace("__FAILURES__", ",".join(f"'{item}'" for item in failures))
            .replace("__PRIVATE__", PRIVATE_SENTINEL)
            .replace("__EXTRA__", extra))
    return run_powershell(code)


def assert_sanitized(test, result):
    def walk(value):
        if isinstance(value, dict):
            for child in value.values():
                walk(child)
        else:
            test.assertTrue(value is None or type(value) in (bool, int), repr(value))
            if type(value) is int:
                test.assertGreaterEqual(value, 0)
    walk(result)
    test.assertNotIn(PRIVATE_SENTINEL, json.dumps(result))
    test.assertFalse(result["kill_switch_verified"])
    test.assertFalse(result["packet_paths_verified"])
    test.assertFalse(result["gpo_overrides_ruled_out"])


class OfflineContractTests(unittest.TestCase):
    def test_native_command_allowlist_and_no_mutations_or_connections(self):
        # Lightweight lexical safety regression; native AST verification below is stronger.
        without_comments = re.sub(r"<#.*?#>|(?m:^\s*#.*$)", "", SOURCE, flags=re.S)
        commands = set(re.findall(r"\b[A-Za-z]+-[A-Za-z][A-Za-z0-9-]*\b", without_comments))
        allowed = {
            "ConvertTo-AuditBoolean", "ConvertTo-AuditBlockAction", "Assert-AuditProperties",
            "Invoke-SanitizedQuery", "Get-AuditElevation", "Invoke-WindowsNetworkAudit",
            "New-Object", "Get-NetAdapter", "Get-Service", "Get-NetFirewallProfile",
            "Get-NetFirewallRule", "Get-CimInstance", "Get-Command", "Where-Object", "ConvertTo-Json",
            "sing-box",  # Literal description regex, not a command.
        }
        self.assertLessEqual(commands, allowed)
        self.assertNotRegex(without_comments, r"(?i)Start-Process|Invoke-Expression|Invoke-WebRequest|"
                            r"Get-Content|Get-NetIPAddress|Get-DnsClientServerAddress|Get-NetRoute|"
                            r"Win32_Process|Get-ItemProperty|TcpClient|UdpClient|Download|RunAs")

    def test_fixed_unknown_and_diagnostic_contracts(self):
        self.assertIn("$Unknown['query_succeeded'] = $false", SOURCE)
        self.assertIn("return $null", SOURCE)
        self.assertIn("kill_switch_verified = $false", SOURCE)
        self.assertIn("packet_paths_verified = $false", SOURCE)
        self.assertIn("gpo_overrides_ruled_out = $false", SOURCE)
        self.assertIn("$MyInvocation.InvocationName -ne '.'", SOURCE)
        self.assertNotIn("Write-Error", SOURCE)
        self.assertNotIn("Write-Host", SOURCE)
        self.assertNotIn("$_.Exception", SOURCE)

    def test_documented_precedence_and_unverified_gates(self):
        for text in ("Block beats a conflicting", "Existing outbound allows", "New/changing NICs",
                     "IPv6", "DNS-helper exception", "Traffic-Only", "Full-Tunnel",
                     "disposable", "No persistent kill switch", "NotConfigured"):
            self.assertIn(text, DOC)


@unittest.skipUnless(POWERSHELL, "Native PowerShell unavailable; native offline tests not passed")
class NativeMockTests(unittest.TestCase):
    def test_native_parse_and_ast_command_allowlist(self):
        code = """
$source=[IO.File]::ReadAllText('__SCRIPT_PATH__')
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
$commands=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true) |
    ForEach-Object { $_.GetCommandName() } | Sort-Object -Unique)
$dynamic=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and
    $null -eq $node.GetCommandName()},$true)).Count
[pscustomobject]@{error_count=@($errors).Count;commands=$commands;dynamic_command_count=$dynamic} | ConvertTo-Json -Compress
""".replace("__SCRIPT_PATH__", SCRIPT_PATH)
        result = run_powershell(code)
        self.assertEqual(result["error_count"], 0)
        self.assertEqual(result["dynamic_command_count"], 1)  # Deliberate & $Query helper invocation.
        self.assertEqual(set(result["commands"]), {
            "Assert-AuditProperties", "ConvertTo-AuditBlockAction", "ConvertTo-AuditBoolean",
            "ConvertTo-Json", "Get-AuditElevation", "Get-CimInstance", "Get-Command",
            "Get-NetAdapter", "Get-NetFirewallProfile", "Get-NetFirewallRule", "Get-Service",
            "Invoke-SanitizedQuery", "Invoke-WindowsNetworkAudit", "New-Object", "Where-Object",
        })

    def test_success_counts_are_effective_and_sanitized(self):
        result = audit(fixture())
        assert_sanitized(self, result)
        self.assertTrue(all(result[name]["query_succeeded"] for name in SECTIONS))
        self.assertFalse(result["elevation"]["elevated"])
        self.assertEqual(result["adapters"]["tun_candidate_count"], 1)
        self.assertEqual(result["adapters"]["hardware_count"], 1)
        self.assertEqual(result["services"]["sing_box_running_count"], 1)
        self.assertEqual(result["services"]["hiddify_running_count"], 0)
        self.assertEqual(result["firewall_profiles"]["fully_known_profile_count"], 3)
        self.assertEqual(result["firewall_rules"]["enabled_outbound_allow_count"], 1)
        self.assertEqual(result["firewall_rules"]["enabled_outbound_block_count"], 1)
        self.assertEqual(result["firewall_rules"]["group_policy_source_count"], 1)
        self.assertEqual(result["group_policy"]["local_firewall_merge_disabled_count"], 1)
        self.assertTrue(result["npcap_driver"]["running"])
        self.assertTrue(result["capture_tools"]["pktmon_command_present"])

    def test_all_query_failures_are_unknown_not_false_or_zero(self):
        result = audit(fixture(), ("elevation", "adapters", "services", "profiles",
                                   "rules", "rsop", "drivers", "pktmon"))
        assert_sanitized(self, result)
        for name in SECTIONS:
            section = result[name]
            self.assertFalse(section["query_succeeded"], name)
            def check_unknown(row):
                for key, value in row.items():
                    if key == "query_succeeded":
                        continue
                    if isinstance(value, dict):
                        check_unknown(value)
                    else:
                        self.assertIsNone(value, f"{name}.{key}")
            check_unknown(section)

    def test_one_failure_does_not_hide_other_results_or_create_stale_lookup_error(self):
        data = fixture()
        data["pktmon"] = False
        result = audit(data, ("adapters",))
        assert_sanitized(self, result)
        self.assertFalse(result["adapters"]["query_succeeded"])
        self.assertTrue(result["services"]["query_succeeded"])
        self.assertTrue(result["capture_tools"]["query_succeeded"])
        self.assertFalse(result["capture_tools"]["pktmon_command_present"])

    def test_successfully_empty_inventory_is_known_absence(self):
        data = fixture()
        for name in ("adapters", "services", "rules", "rsop", "drivers"):
            data[name] = []
        data["pktmon"] = False
        result = audit(data)
        assert_sanitized(self, result)
        self.assertEqual(result["adapters"]["total_count"], 0)
        self.assertEqual(result["services"]["sing_box_candidate_count"], 0)
        self.assertFalse(result["services"]["firewall_service_running"])
        self.assertEqual(result["firewall_rules"]["total_count"], 0)
        self.assertEqual(result["group_policy"]["rsop_profile_count"], 0)
        self.assertFalse(result["npcap_driver"]["present"])
        self.assertFalse(result["capture_tools"]["pktmon_command_present"])
        self.assertTrue(all(result[name]["query_succeeded"] for name in SECTIONS))

    def test_notconfigured_values_stay_unknown_and_merge_disabled_is_false(self):
        data = fixture()
        data["profiles"][0]["DefaultOutboundAction"] = "NotConfigured"
        data["profiles"][0]["AllowLocalFirewallRules"] = "NotConfigured"
        data["profiles"][1]["AllowLocalFirewallRules"] = False
        data["profiles"][2]["Enabled"] = "Unrecognized"
        result = audit(data)
        assert_sanitized(self, result)
        section = result["firewall_profiles"]
        self.assertTrue(section["query_succeeded"])
        self.assertIsNone(section["domain"]["default_outbound_block"])
        self.assertIsNone(section["domain"]["local_firewall_rules_allowed"])
        self.assertFalse(section["private"]["local_firewall_rules_allowed"])
        self.assertIsNone(section["public"]["enabled"])
        self.assertEqual(section["fully_known_profile_count"], 1)

    def test_incomplete_native_records_never_count_as_safe(self):
        data = fixture()
        data["profiles"].pop()
        del data["rules"][0]["PolicyStoreSourceType"]
        data["adapters"][0]["HardwareInterface"] = "Unknown"
        del data["drivers"][0]["State"]
        result = audit(data)
        assert_sanitized(self, result)
        for name in ("firewall_profiles", "firewall_rules", "adapters", "npcap_driver"):
            self.assertFalse(result[name]["query_succeeded"], name)
        self.assertTrue(result["services"]["query_succeeded"])

    def test_unknown_rule_and_gpo_classifications_are_not_zero_counts(self):
        data = fixture()
        data["rules"][0]["Action"] = "Unrecognized"
        data["rsop"][0]["AllowLocalFirewallRules"] = "Unrecognized"
        result = audit(data)
        assert_sanitized(self, result)
        self.assertFalse(result["firewall_rules"]["query_succeeded"])
        self.assertIsNone(result["firewall_rules"]["enabled_outbound_allow_count"])
        self.assertFalse(result["group_policy"]["query_succeeded"])
        self.assertIsNone(result["group_policy"]["local_firewall_merge_disabled_count"])

    def test_realistic_command_not_found_is_absence_but_other_lookup_errors_unknown(self):
        for error_id, expected_known in (("CommandNotFoundException", True), ("SyntheticDiscoveryDenied", False)):
            extra = """
function Get-Command {
    [CmdletBinding()]param($Name, $CommandType)
    Write-Error -Message 'synthetic discovery failure' -ErrorId '__ID__' -Category ObjectNotFound
}
""".replace("__ID__", error_id)
            with self.subTest(error_id=error_id):
                result = audit(fixture(), extra=extra)
                assert_sanitized(self, result)
                capture = result["capture_tools"]
                self.assertEqual(capture["query_succeeded"], expected_known)
                if expected_known:
                    self.assertFalse(capture["pktmon_command_present"])
                else:
                    self.assertIsNone(capture["pktmon_command_present"])


if __name__ == "__main__":
    unittest.main()
