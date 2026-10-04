#requires -Version 5.1
<#
Local read-only inventory, NOT a kill switch or connectivity test.
No private files, addresses, command lines, process arguments or packet logs are read.
Run with -NoProfile; dot-sourcing defines functions without executing the audit.
See WINDOWS_NETWORK_READINESS.md for limitations and privileged test gates.
#>

function ConvertTo-AuditBoolean {
    param($Value)
    if ([string]$Value -eq 'True') { return $true }
    if ([string]$Value -eq 'False') { return $false }
    return $null
}

function ConvertTo-AuditBlockAction {
    param($Value)
    if ([string]$Value -eq 'Block') { return $true }
    if ([string]$Value -eq 'Allow') { return $false }
    return $null
}

function Assert-AuditProperties {
    param($Record, [string[]]$Names)
    foreach ($name in $Names) {
        if ($null -eq $Record.$name) { throw 'Incomplete native query result' }
    }
}

function Invoke-SanitizedQuery {
    param([System.Collections.IDictionary]$Unknown, [scriptblock]$Query)
    try {
        $result = & $Query
        if ($result -isnot [System.Collections.IDictionary]) { throw 'Invalid query result' }
        $result['query_succeeded'] = $true
        return [pscustomobject]$result
    } catch {
        # Exception messages can contain paths, account names or addresses. Never emit them.
        $Unknown['query_succeeded'] = $false
        return [pscustomobject]$Unknown
    }
}

function Get-AuditElevation {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } finally {
        $identity.Dispose()
    }
}

function Invoke-WindowsNetworkAudit {
    # Scope these preferences to this invocation, not to the caller's session.
    $ErrorActionPreference = 'Stop'
    $WarningPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'
    $DebugPreference = 'SilentlyContinue'
    $InformationPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'

    $elevation = Invoke-SanitizedQuery -Unknown ([ordered]@{ elevated = $null }) -Query {
        $value = ConvertTo-AuditBoolean (Get-AuditElevation)
        if ($null -eq $value) { throw 'Unknown elevation' }
        [ordered]@{ elevated = $value }
    }

    $adapters = Invoke-SanitizedQuery -Unknown ([ordered]@{
        total_count = $null; up_count = $null; hardware_count = $null
        tun_candidate_count = $null; wintun_description_count = $null
        tun_candidate_up_count = $null
    }) -Query {
        $items = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
        foreach ($item in $items) {
            Assert-AuditProperties $item @('InterfaceDescription', 'Status', 'HardwareInterface')
            if ($null -eq (ConvertTo-AuditBoolean $item.HardwareInterface)) { throw 'Unknown adapter type' }
        }
        # Only description heuristics: names/aliases can be user-defined and are not evidence.
        $tun = @($items | Where-Object { $_.InterfaceDescription -match '(?i)\b(wintun|tun)\b|sing[- ]?box|hiddify' })
        [ordered]@{
            total_count = $items.Count
            up_count = @($items | Where-Object { [string]$_.Status -eq 'Up' }).Count
            hardware_count = @($items | Where-Object { (ConvertTo-AuditBoolean $_.HardwareInterface) -eq $true }).Count
            tun_candidate_count = $tun.Count
            wintun_description_count = @($items | Where-Object { $_.InterfaceDescription -match '(?i)\bwintun\b' }).Count
            tun_candidate_up_count = @($tun | Where-Object { [string]$_.Status -eq 'Up' }).Count
        }
    }

    $services = Invoke-SanitizedQuery -Unknown ([ordered]@{
        sing_box_candidate_count = $null; sing_box_running_count = $null
        hiddify_candidate_count = $null; hiddify_running_count = $null
        firewall_service_running = $null; filtering_engine_service_running = $null
    }) -Query {
        $items = @(Get-Service -ErrorAction Stop)
        foreach ($item in $items) { Assert-AuditProperties $item @('Name', 'DisplayName', 'Status') }
        $sing = @($items | Where-Object { ($_.Name + ' ' + $_.DisplayName) -match '(?i)sing[- ]?box' })
        $hiddify = @($items | Where-Object { ($_.Name + ' ' + $_.DisplayName) -match '(?i)hiddify' })
        [ordered]@{
            sing_box_candidate_count = $sing.Count
            sing_box_running_count = @($sing | Where-Object { [string]$_.Status -eq 'Running' }).Count
            hiddify_candidate_count = $hiddify.Count
            hiddify_running_count = @($hiddify | Where-Object { [string]$_.Status -eq 'Running' }).Count
            firewall_service_running = (@($items | Where-Object { $_.Name -eq 'MpsSvc' -and [string]$_.Status -eq 'Running' }).Count -gt 0)
            filtering_engine_service_running = (@($items | Where-Object { $_.Name -eq 'BFE' -and [string]$_.Status -eq 'Running' }).Count -gt 0)
        }
    }

    $unknownProfiles = [ordered]@{ profile_count = $null; fully_known_profile_count = $null }
    foreach ($name in @('Domain', 'Private', 'Public')) {
        $unknownProfiles[$name.ToLowerInvariant()] = [pscustomobject][ordered]@{
            enabled = $null; default_outbound_block = $null
            local_firewall_rules_allowed = $null; local_ipsec_rules_allowed = $null
        }
    }
    $profiles = Invoke-SanitizedQuery -Unknown $unknownProfiles -Query {
        $items = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
        $result = [ordered]@{ profile_count = $items.Count; fully_known_profile_count = 0 }
        foreach ($name in @('Domain', 'Private', 'Public')) {
            $matches = @($items | Where-Object { [string]$_.Name -eq $name })
            if ($matches.Count -ne 1) { throw 'Incomplete profile inventory' }
            $item = $matches[0]
            $row = [ordered]@{
                enabled = ConvertTo-AuditBoolean $item.Enabled
                default_outbound_block = ConvertTo-AuditBlockAction $item.DefaultOutboundAction
                local_firewall_rules_allowed = ConvertTo-AuditBoolean $item.AllowLocalFirewallRules
                local_ipsec_rules_allowed = ConvertTo-AuditBoolean $item.AllowLocalIPsecRules
            }
            if (@($row.Values | Where-Object { $null -eq $_ }).Count -eq 0) {
                $result['fully_known_profile_count']++
            }
            $result[$name.ToLowerInvariant()] = [pscustomobject]$row
        }
        $result
    }

    $rules = Invoke-SanitizedQuery -Unknown ([ordered]@{
        total_count = $null; enabled_count = $null
        enabled_outbound_allow_count = $null; enabled_outbound_block_count = $null
        group_policy_source_count = $null
    }) -Query {
        # ActiveStore is effective merged policy; PersistentStore alone is insufficient.
        $items = @(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -ErrorAction Stop)
        foreach ($item in $items) {
            Assert-AuditProperties $item @('Enabled', 'Direction', 'Action', 'PolicyStoreSourceType')
            if ($null -eq (ConvertTo-AuditBoolean $item.Enabled)) { throw 'Unknown rule state' }
            if ([string]$item.Direction -notin @('Inbound', 'Outbound') -or
                [string]$item.Action -notin @('Allow', 'Block', 'AllowBypass')) {
                throw 'Unknown rule classification'
            }
        }
        $enabled = @($items | Where-Object { (ConvertTo-AuditBoolean $_.Enabled) -eq $true })
        [ordered]@{
            total_count = $items.Count
            enabled_count = $enabled.Count
            enabled_outbound_allow_count = @($enabled | Where-Object { [string]$_.Direction -eq 'Outbound' -and [string]$_.Action -eq 'Allow' }).Count
            enabled_outbound_block_count = @($enabled | Where-Object { [string]$_.Direction -eq 'Outbound' -and [string]$_.Action -eq 'Block' }).Count
            group_policy_source_count = @($items | Where-Object { [string]$_.PolicyStoreSourceType -eq 'GroupPolicy' }).Count
        }
    }

    $gpo = Invoke-SanitizedQuery -Unknown ([ordered]@{
        rsop_profile_count = $null; outbound_action_configured_count = $null
        local_firewall_merge_disabled_count = $null; local_ipsec_merge_disabled_count = $null
    }) -Query {
        # Local RSOP only: no domain/DC/GPO session or remote CIM connection.
        $items = @(Get-NetFirewallProfile -PolicyStore RSOP -ErrorAction Stop)
        foreach ($item in $items) {
            Assert-AuditProperties $item @('Name', 'DefaultOutboundAction', 'AllowLocalFirewallRules', 'AllowLocalIPsecRules')
            if ([string]$item.DefaultOutboundAction -notin @('Allow', 'Block', 'NotConfigured') -or
                [string]$item.AllowLocalFirewallRules -notin @('True', 'False', 'NotConfigured') -or
                [string]$item.AllowLocalIPsecRules -notin @('True', 'False', 'NotConfigured')) {
                throw 'Unknown policy classification'
            }
        }
        [ordered]@{
            rsop_profile_count = $items.Count
            outbound_action_configured_count = @($items | Where-Object { $null -ne (ConvertTo-AuditBlockAction $_.DefaultOutboundAction) }).Count
            local_firewall_merge_disabled_count = @($items | Where-Object { (ConvertTo-AuditBoolean $_.AllowLocalFirewallRules) -eq $false }).Count
            local_ipsec_merge_disabled_count = @($items | Where-Object { (ConvertTo-AuditBoolean $_.AllowLocalIPsecRules) -eq $false }).Count
        }
    }

    $npcap = Invoke-SanitizedQuery -Unknown ([ordered]@{ present = $null; running = $null }) -Query {
        # Kernel drivers need a driver query, not an application-service inventory.
        $items = @(Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name = 'npcap'" -Property Name, State -ErrorAction Stop)
        foreach ($item in $items) { Assert-AuditProperties $item @('Name', 'State') }
        [ordered]@{
            present = ($items.Count -gt 0)
            running = (@($items | Where-Object { [string]$_.State -eq 'Running' }).Count -gt 0)
        }
    }

    $capture = Invoke-SanitizedQuery -Unknown ([ordered]@{ pktmon_command_present = $null }) -Query {
        # Discover only; never invoke pktmon, start capture, or install Npcap.
        $lookupErrors = @()
        $commands = @(Get-Command -Name pktmon.exe -CommandType Application -ErrorAction SilentlyContinue -ErrorVariable lookupErrors)
        # A lookup miss is known absence; unrelated earlier errors must not affect this query.
        foreach ($lookupError in $lookupErrors) {
            if ($lookupError.FullyQualifiedErrorId -notlike 'CommandNotFoundException*') {
                throw 'Command discovery failed'
            }
        }
        [ordered]@{ pktmon_command_present = ($commands.Count -gt 0) }
    }

    [pscustomobject][ordered]@{
        schema_version = 1
        read_only = $true
        kill_switch_verified = $false
        packet_paths_verified = $false
        gpo_overrides_ruled_out = $false
        elevation = $elevation
        adapters = $adapters
        services = $services
        firewall_profiles = $profiles
        firewall_rules = $rules
        group_policy = $gpo
        npcap_driver = $npcap
        capture_tools = $capture
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-WindowsNetworkAudit | ConvertTo-Json -Depth 6 -Compress
}
