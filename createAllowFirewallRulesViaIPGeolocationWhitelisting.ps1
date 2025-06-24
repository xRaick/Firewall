# ------------------------------
# Global Variables
# ------------------------------
$scriptRoot = "C:\Path\To\Your\Working\Directory"
$logFile     = "$scriptRoot\firewall-update.log"
$tempFile    = "$scriptRoot\delegated-ripencc-extended-latest"
$ripeUrl     = "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"

# Thresholds
$batchSize = 10000

# Target countries
# Note: Ensure the country codes are in uppercase as per RIPE's format
# For example: 'DE' for Germany, 'FR' for France, 'BE', 'LU' for Luxembourg
# Add or remove country codes as necessary
# The list below is for BENELUX countries excluding the Netherlands
# Adjust the list as needed for your specific requirements
$countryCodes = @('DE','FR','BE','LU')

# Internal cache for CIDR conversions
$cidrCache = @{}

# ------------------------------
# Functions
# ------------------------------

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$timestamp $Message" | Out-File -FilePath $logFile -Append -Encoding UTF8
}

function ConvertTo-CIDRBlocks {
    param (
        [string]$startIp,
        [int]$count
    )
    $cacheKey = "$startIp|$count"
    if ($cidrCache.ContainsKey($cacheKey)) {
        return $cidrCache[$cacheKey]
    }

    try {
        $bytes = [System.Net.IPAddress]::Parse($startIp).GetAddressBytes()
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
        $ipAsInt = [BitConverter]::ToUInt32($bytes, 0)
    } catch {
        Write-Log "ERROR: Invalid start IP '$startIp'"
        return @()
    }

    $results = @()
    while ($count -gt 0) {
        $zeroBits     = [math]::Log(($ipAsInt -bxor ($ipAsInt - 1)) + 1, 2)
        $maxBlock     = [math]::Floor([math]::Log($count, 2))
        $prefixLength = [math]::Max(32 - [int]$maxBlock, 32 - [int]$zeroBits)

        # Build CIDR string
        $bytes = [BitConverter]::GetBytes($ipAsInt)
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
        $networkIp = ([System.Net.IPAddress]::new($bytes)).ToString()
        $results += "$networkIp/$prefixLength"

        $blockSize = [math]::Pow(2, 32 - $prefixLength)
        $ipAsInt   += [uint32]$blockSize
        $count     -= [int]$blockSize
    }

    $cidrCache[$cacheKey] = $results
    return $results
}

function Download-RIPEFile {
    try {
        Invoke-WebRequest -Uri $ripeUrl -OutFile $tempFile -UseBasicParsing -ErrorAction Stop
        Write-Log "Downloaded RIPE file to $tempFile"
    } catch {
        Write-Log "ERROR: Failed to download RIPE file: $_"
        throw
    }
}

function Parse-RIPEFile {
    param([string]$filePath)
    $ranges = @{}
    $lines  = Get-Content $filePath | Where-Object { $_ -match '^ripencc\|(' + ($countryCodes -join '|') + ')\|ipv4' }
    foreach ($line in $lines) {
        $parts    = $line -split '\|'
        $country  = $parts[1]
        $startIp  = $parts[3]
        $count    = [int]$parts[4]
        $cidrs    = ConvertTo-CIDRBlocks -startIp $startIp -count $count
        if ($cidrs.Count -gt 0) {
            if (-not $ranges.ContainsKey($country)) { $ranges[$country] = @() }
            $ranges[$country] += $cidrs
        }
    }
    Write-Log "Parsed IP ranges for countries: $($ranges.Keys -join ', ')"
    return $ranges
}

function Update-FirewallRule {
    param (
        [string]$countryCode,
        [string]$ruleNameBase,
        [string[]]$cidrs
    )
    # Clean up old rules
    $pattern = "$ruleNameBase - $countryCode*"
    Get-NetFirewallRule -DisplayName $pattern -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-NetFirewallRule -InputObject $_ -ErrorAction SilentlyContinue
        Write-Log "Removed old rule: $($_.DisplayName)"
    }

    $total = $cidrs.Count
    if ($total -le $batchSize) {
        $ruleName = "$ruleNameBase - $countryCode"
        try {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Inbound `
                -Action Allow `
                -RemoteAddress $cidrs `
                -Protocol TCP `
                -Profile Any `
                -Enabled True
            Write-Log "Created rule: ${ruleName} with $total addresses"
        } catch {
            Write-Log "ERROR: Failed to create rule ${ruleName}: $_"
        }
    } else {
        $batches = [math]::Ceiling($total / $batchSize)
        for ($i = 0; $i -lt $batches; $i++) {
            $start    = $i * $batchSize
            $end      = [math]::Min($start + $batchSize - 1, $total - 1)
            $batch    = $cidrs[$start..$end]
            $ruleName = "$ruleNameBase - $countryCode - Batch $($i + 1)"
            try {
                New-NetFirewallRule -DisplayName $ruleName `
                    -Direction Inbound `
                    -Action Allow `
                    -RemoteAddress $batch `
                    -Protocol TCP `
                    -Profile Any `
                    -Enabled True
                Write-Log "Created rule: ${ruleName} with $($batch.Count) addresses"
            } catch {
                Write-Log "ERROR: Failed to create rule ${ruleName}: $_"
            }
        }
    }
}

function Main {
    Write-Log "--- Starting Firewall Update ---"
    Download-RIPEFile
    $ipRanges = Parse-RIPEFile -filePath $tempFile
    foreach ($cc in $countryCodes) {
        if ($ipRanges.ContainsKey($cc)) {
            Update-FirewallRule -countryCode $cc -ruleNameBase "Allow Country IPs" -cidrs $ipRanges[$cc]
        } else {
            Write-Log "No IP ranges for country code: $cc"
        }
    }
    Write-Log "--- Firewall Update Completed ---"
}

# Execute main
Main
