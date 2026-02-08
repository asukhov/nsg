# Azure NSG Rule Management Script
# This script connects to Azure, searches for NSG rules, and updates or creates them as needed

param(
    # Azure Subscription Parameters
    [Parameter(Mandatory=$false)]
    [string]$SubscriptionId = "",
    
    [Parameter(Mandatory=$false)]
    [string]$SubscriptionName = "",
    
    # NSG Rule Search Parameters
    [Parameter(Mandatory=$true)]
    [string]$RuleName,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("Inbound", "Outbound")]
    [string]$Direction,
    
    # Rule Update/Create Parameters
    [Parameter(Mandatory=$false)]
    [ValidateSet("Allow", "Deny")]
    [string]$Access = "",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Tcp", "Udp", "Icmp", "Esp", "Ah", "*")]
    [string]$Protocol = "",
    
    [Parameter(Mandatory=$false)]
    [string]$SourceAddressPrefixes = "",
    
    [Parameter(Mandatory=$false)]
    [string]$SourcePortRanges = "",
    
    [Parameter(Mandatory=$false)]
    [string]$DestinationAddressPrefixes = "",
    
    [Parameter(Mandatory=$false)]
    [string]$DestinationPortRanges = "",
    
    [Parameter(Mandatory=$false)]
    [int]$Priority = -1,
    
    [Parameter(Mandatory=$false)]
    [string]$Description = "",
    
    # Control Parameters
    [Parameter(Mandatory=$false)]
    [bool]$CreateIfNotExists = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$UpdateExisting = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$DryRun = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$ShowDetails = $true,
    
    # Optional: Filter NSGs by name pattern
    [Parameter(Mandatory=$false)]
    [string]$NSGNameFilter = ""
)

# Function to write colored output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

# Function to check if Azure CLI is installed
function Test-AzureCLI {
    try {
        $null = az --version 2>&1
        return $true
    }
    catch {
        Write-ColorOutput "Azure CLI is not installed or not in PATH" "Red"
        return $false
    }
}

# Function to login to Azure
function Connect-AzureAccount {
    Write-ColorOutput "`nChecking Azure connection..." "Cyan"
    
    $Account = az account show 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-ColorOutput "Not logged in to Azure. Please login..." "Yellow"
        az login
        if ($LASTEXITCODE -ne 0) {
            Write-ColorOutput "Failed to login to Azure" "Red"
            return $false
        }
    }
    else {
        $accountInfo = $Account | ConvertFrom-Json
        Write-ColorOutput "Already logged in as: $($accountInfo.user.name)" "Green"
    }
    return $true
}

# Function to set subscription
function Set-AzureSubscription {
    Write-ColorOutput "`nSetting subscription..." "Cyan"
    
    if ($SubscriptionId) {
        az account set --subscription $SubscriptionId 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-ColorOutput "Failed to set subscription by ID: $SubscriptionId" "Red"
            return $false
        }
        Write-ColorOutput "Subscription set by ID: $SubscriptionId" "Green"
    }
    elseif ($SubscriptionName) {
        az account set --subscription "$SubscriptionName" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-ColorOutput "Failed to set subscription by name: $SubscriptionName" "Red"
            return $false
        }
        Write-ColorOutput "Subscription set by name: $SubscriptionName" "Green"
    }
    else {
        $CurrentSub = az account show --query "[name, id]" -o json | ConvertFrom-Json
        Write-ColorOutput "Using current subscription: $($CurrentSub[0]) (ID: $($CurrentSub[1]))" "Yellow"
    }
    return $true
}

# Function to get all NSGs in subscription
function Get-AllNSGs {
    Write-ColorOutput "`nFetching all NSGs in subscription..." "Cyan"
    
    $NSGs = az network nsg list --query "[].{name:name, resourceGroup:resourceGroup, location:location}" -o json 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-ColorOutput "Failed to fetch NSGs" "Red"
        return $null
    }
    
    $NSGList = $NSGs | ConvertFrom-Json
    
    # Apply NSG name filter if provided
    if ($NSGNameFilter) {
        $NSGList = $NSGList | Where-Object { $_.name -like $NSGNameFilter }
        Write-ColorOutput "Found $($NSGList.Count) NSGs matching filter '$NSGNameFilter'" "Green"
    }
    else {
        Write-ColorOutput "Found $($NSGList.Count) NSGs" "Green"
    }
    
    return $NSGList
}

# Function to check if rule exists in NSG
function Get-NSGRule {
    param(
        [string]$ResourceGroup,
        [string]$NSGName,
        [string]$RuleName
    )
    
    $Rule = az network nsg rule show `
        --resource-group $ResourceGroup `
        --nsg-name $NSGName `
        --name $RuleName `
        -o json 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        return $Rule | ConvertFrom-Json
    }
    return $null
}

# Function to build update command parameters
function Build-UpdateParameters {
    $Params = @()
    
    if ($Access) { $Params += "--access", $Access }
    if ($Protocol) { $Params += "--protocol", $Protocol }
    if ($SourceAddressPrefixes) { 
        $Params += "--source-address-prefixes"
        $Params += $SourceAddressPrefixes.Split(',').Trim()
    }
    if ($SourcePortRanges) {
        $Params += "--source-port-ranges"
        $Params += $SourcePortRanges.Split(',').Trim()
    }
    if ($DestinationAddressPrefixes) {
        $Params += "--destination-address-prefixes"
        $Params += $DestinationAddressPrefixes.Split(',').Trim()
    }
    if ($DestinationPortRanges) {
        $Params += "--destination-port-ranges"
        $Params += $DestinationPortRanges.Split(',').Trim()
    }
    if ($Priority -gt 0) { $Params += "--priority", $Priority }
    if ($Description) { $Params += "--description", "`"$Description`"" }
    
    return $Params
}

# Function to display rule details
function Show-RuleDetails {
    param(
        [object]$Rule,
        [string]$Indent = "  "
    )
    
    Write-ColorOutput "$($Indent)Current Rule Configuration:" "Gray"
    Write-ColorOutput "$($Indent)  Direction: $($Rule.direction)" "Gray"
    Write-ColorOutput "$($Indent)  Access: $($Rule.access)" "Gray"
    Write-ColorOutput "$($Indent)  Protocol: $($Rule.protocol)" "Gray"
    Write-ColorOutput "$($Indent)  Priority: $($Rule.priority)" "Gray"
    if ($Rule.sourceAddressPrefix) {
        Write-ColorOutput "$($Indent)  Source: $($Rule.sourceAddressPrefix)" "Gray"
    }
    if ($Rule.sourceAddressPrefixes) {
        Write-ColorOutput "$($Indent)  Sources: $($Rule.sourceAddressPrefixes)" "Gray"
    }
    if ($Rule.sourcePortRange) {
        Write-ColorOutput "$($Indent)  Source Ports: $($Rule.sourcePortRange)" "Gray"
    }
    if ($Rule.sourcePortRanges) {
        Write-ColorOutput "$($Indent)  Source Ports: $($Rule.sourcePortRanges)" "Gray"
    }
    if ($Rule.destinationAddressPrefix) {
        Write-ColorOutput "$($Indent)  Destination: $($Rule.destinationAddressPrefix)" "Gray"
    }
    if ($Rule.destinationAddressPrefixes) {
        Write-ColorOutput "$($Indent)  Destinations: $($Rule.destinationAddressPrefixes)" "Gray"
    }
    Write-ColorOutput "$($Indent)  Destination Ports: $($Rule.destinationPortRanges)" "Gray"
    if ($Rule.description) {
        Write-ColorOutput "$($Indent)  Description: $($Rule.description)" "Gray"
    }
}

# Function to update existing rule
function Update-NSGRule {
    param(
        [string]$ResourceGroup,
        [string]$NSGName,
        [string]$RuleName,
        [array]$UpdateParams
    )
    
    if ($UpdateParams.Count -eq 0) {
        Write-ColorOutput "  No parameters to update" "Yellow"
        return $true
    }
    
    if ($DryRun) {
        Write-ColorOutput "  [DRY RUN] Would update rule with parameters:" "Magenta"
        for ($i = 0; $i -lt $UpdateParams.Count; $i += 2) {
            if ($i + 1 -lt $UpdateParams.Count) {
                Write-ColorOutput "    $($UpdateParams[$i]): $($UpdateParams[$i+1])" "Gray"
            }
        }
        return $true
    }
    
    Write-ColorOutput "  Updating rule..." "Cyan"
    
    $BaseParams = @(
        "network", "nsg", "rule", "update",
        "--resource-group", $ResourceGroup,
        "--nsg-name", $NSGName,
        "--name", $RuleName
    )
    
    $AllParams = $BaseParams + $UpdateParams
    
    $Result = & az $AllParams 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-ColorOutput "  ✓ Rule updated successfully" "Green"
        return $true
    }
    else {
        Write-ColorOutput "  ✗ Failed to update rule: $Result" "Red"
        return $false
    }
}

# Function to create new rule
function New-NSGRule {
    param(
        [string]$ResourceGroup,
        [string]$NSGName,
        [string]$RuleName
    )
    
    if (-not $CreateIfNotExists) {
        Write-ColorOutput "  Rule creation skipped (CreateIfNotExists = false)" "Yellow"
        return $false
    }
    
    # Check if we have minimum required parameters for creation
    if (-not $Access -or -not $Protocol -or $Priority -le 0) {
        Write-ColorOutput "  Cannot create rule: Missing required parameters (Access, Protocol, Priority)" "Red"
        Write-ColorOutput "  Please provide: -Access, -Protocol, and -Priority (must be > 0)" "Yellow"
        return $false
    }
    
    if ($DryRun) {
        Write-ColorOutput "  [DRY RUN] Would create rule with:" "Magenta"
        Write-ColorOutput "    Direction: $Direction" "Gray"
        Write-ColorOutput "    Access: $Access" "Gray"
        Write-ColorOutput "    Protocol: $Protocol" "Gray"
        Write-ColorOutput "    Priority: $Priority" "Gray"
        if ($SourceAddressPrefixes) {
            Write-ColorOutput "    Source Addresses: $SourceAddressPrefixes" "Gray"
        }
        if ($DestinationPortRanges) {
            Write-ColorOutput "    Destination Ports: $DestinationPortRanges" "Gray"
        }
        return $true
    }
    
    Write-ColorOutput "  Creating new rule..." "Cyan"
    
    $CreateParams = @(
        "network", "nsg", "rule", "create",
        "--resource-group", $ResourceGroup,
        "--nsg-name", $NSGName,
        "--name", $RuleName,
        "--direction", $Direction,
        "--access", $Access,
        "--protocol", $Protocol,
        "--priority", $Priority
    )
    
    # Add optional parameters if provided
    if ($SourceAddressPrefixes) {
        $CreateParams += "--source-address-prefixes"
        $CreateParams += $SourceAddressPrefixes.Split(',').Trim()
    }
    else {
        $CreateParams += "--source-address-prefixes", "*"
    }
    
    if ($SourcePortRanges) {
        $CreateParams += "--source-port-ranges"
        $CreateParams += $SourcePortRanges.Split(',').Trim()
    }
    else {
        $CreateParams += "--source-port-ranges", "*"
    }
    
    if ($DestinationAddressPrefixes) {
        $CreateParams += "--destination-address-prefixes"
        $CreateParams += $DestinationAddressPrefixes.Split(',').Trim()
    }
    else {
        $CreateParams += "--destination-address-prefixes", "*"
    }
    
    if ($DestinationPortRanges) {
        $CreateParams += "--destination-port-ranges"
        $CreateParams += $DestinationPortRanges.Split(',').Trim()
    }
    else {
        $CreateParams += "--destination-port-ranges", "*"
    }
    
    if ($Description) {
        $CreateParams += "--description", "`"$Description`""
    }
    
    $Result = & az $CreateParams 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-ColorOutput "  ✓ Rule created successfully" "Green"
        return $true
    }
    else {
        Write-ColorOutput "  ✗ Failed to create rule: $Result" "Red"
        return $false
    }
}

# Main script execution
function Main {
    Write-ColorOutput "`n========================================" "Cyan"
    Write-ColorOutput "Azure NSG Rule Management Script" "Cyan"
    Write-ColorOutput "========================================" "Cyan"
    
    if ($DryRun) {
        Write-ColorOutput "`n*** DRY RUN MODE - No changes will be made ***" "Magenta"
    }
    
    # Display search criteria
    Write-ColorOutput "`nSearch Criteria:" "Cyan"
    Write-ColorOutput "  Rule Name: $RuleName" "White"
    Write-ColorOutput "  Direction: $Direction" "White"
    if ($NSGNameFilter) {
        Write-ColorOutput "  NSG Filter: $NSGNameFilter" "White"
    }
    
    # Check Azure CLI
    if (-not (Test-AzureCLI)) {
        Write-ColorOutput "`nPlease install Azure CLI from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli" "Yellow"
        return
    }
    
    # Connect to Azure
    if (-not (Connect-AzureAccount)) {
        return
    }
    
    # Set subscription
    if (-not (Set-AzureSubscription)) {
        return
    }
    
    # Get all NSGs
    $NSGs = Get-AllNSGs
    if (-not $NSGs -or $NSGs.Count -eq 0) {
        Write-ColorOutput "`nNo NSGs found in the subscription" "Yellow"
        return
    }
    
    # Build update parameters once
    $UpdateParams = Build-UpdateParameters
    
    # Search for rules in each NSG
    Write-ColorOutput "`nSearching for rule: '$RuleName' (Direction: $Direction)" "Cyan"
    Write-ColorOutput "========================================" "Cyan"
    
    $RulesFound = 0
    $RulesUpdated = 0
    $RulesCreated = 0
    $RulesFailed = 0
    
    foreach ($NSG in $NSGs) {
        if ($ShowDetails) {
            Write-ColorOutput "`nChecking NSG: $($NSG.name)" "White"
            Write-ColorOutput "  Resource Group: $($NSG.resourceGroup)" "Gray"
            Write-ColorOutput "  Location: $($NSG.location)" "Gray"
        }
        
        try {
            $ExistingRule = Get-NSGRule -ResourceGroup $NSG.resourceGroup -NSGName $NSG.name -RuleName $RuleName
            
            if ($ExistingRule) {
                # Check if direction matches
                if ($ExistingRule.direction -eq $Direction) {
                    $RulesFound++
                    Write-ColorOutput "  ✓ Rule found with matching direction" "Green"
                    
                    if ($ShowDetails) {
                        Show-RuleDetails -Rule $ExistingRule
                    }
                    
                    if ($UpdateParams.Count -gt 0 -and $UpdateExisting) {
                        if (Update-NSGRule -ResourceGroup $NSG.resourceGroup -NSGName $NSG.name -RuleName $RuleName -UpdateParams $UpdateParams) {
                            $RulesUpdated++
                        }
                        else {
                            $RulesFailed++
                        }
                    }
                    elseif ($UpdateParams.Count -gt 0 -and -not $UpdateExisting) {
                        Write-ColorOutput "  Rule exists but updates skipped (UpdateExisting = false)" "Yellow"
                    }
                    else {
                        Write-ColorOutput "  No updates requested" "Gray"
                    }
                }
                else {
                    Write-ColorOutput "  ⚠ Rule found but direction mismatch" "Yellow"
                    Write-ColorOutput "    Expected: $Direction, Found: $($ExistingRule.direction)" "Gray"
                }
            }
            else {
                if (-not $ShowDetails) {
                    Write-ColorOutput "`nNSG: $($NSG.name) (RG: $($NSG.resourceGroup))" "White"
                }
                Write-ColorOutput "  Rule not found" "Gray"
                
                if ($CreateIfNotExists) {
                    if (New-NSGRule -ResourceGroup $NSG.resourceGroup -NSGName $NSG.name -RuleName $RuleName) {
                        $RulesCreated++
                    }
                    else {
                        $RulesFailed++
                    }
                }
            }
        }
        catch {
            Write-ColorOutput "  Error processing NSG: $_" "Red"
            $RulesFailed++
        }
    }
    
    # Summary
    Write-ColorOutput "`n========================================" "Cyan"
    Write-ColorOutput "Summary:" "Cyan"
    Write-ColorOutput "========================================" "Cyan"
    Write-ColorOutput "  NSGs checked: $($NSGs.Count)" "White"
    Write-ColorOutput "  Rules found: $RulesFound" "White"
    
    if ($UpdateParams.Count -gt 0) {
        Write-ColorOutput "  Rules updated: $RulesUpdated" $(if ($RulesUpdated -gt 0) { "Green" } else { "White" })
    }
    
    if ($CreateIfNotExists) {
        Write-ColorOutput "  Rules created: $RulesCreated" $(if ($RulesCreated -gt 0) { "Green" } else { "White" })
    }
    
    if ($RulesFailed -gt 0) {
        Write-ColorOutput "  Failed operations: $RulesFailed" "Red"
    }
    
    if ($DryRun) {
        Write-ColorOutput "`n*** DRY RUN COMPLETE - No changes were made ***" "Magenta"
    }
    else {
        $TotalChanges = $RulesUpdated + $RulesCreated
        if ($TotalChanges -gt 0) {
            Write-ColorOutput "`n✓ Successfully modified $TotalChanges rule(s)" "Green"
        }
        elseif ($RulesFound -gt 0 -and $UpdateParams.Count -eq 0) {
            Write-ColorOutput "`n✓ Found $RulesFound rule(s) - no changes requested" "Green"
        }
        elseif ($RulesFound -eq 0 -and -not $CreateIfNotExists) {
            Write-ColorOutput "`nNo matching rules found (creation disabled)" "Yellow"
        }
    }
    
    Write-ColorOutput "`nScript completed!" "Cyan"
}

# Error handling wrapper
try {
    Main
}
catch {
    Write-ColorOutput "`nUnexpected error occurred:" "Red"
    Write-ColorOutput $_.Exception.Message "Red"
    Write-ColorOutput "`nStack trace:" "Gray"
    Write-ColorOutput $_.ScriptStackTrace "Gray"
    exit 1
}