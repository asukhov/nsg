PowerShell script that manages NSG rules in Azure. This script will use Azure CLI commands.

## **Key Features:**

### **Connection & Subscription Management:**
- Connects to Azure tenant automatically
- Can specify subscription by either ID or name
- Falls back to current subscription if none specified

### **Rule Search Capabilities:**
- Searches all NSGs in the subscription
- Looks for specific rule by name
- Filters by direction (Inbound/Outbound)

### **Rule Update Parameters:**
You can update any of these parameters:
- Access (Allow/Deny)
- Protocol (Tcp/Udp/Icmp/*)
- Source Address Prefixes
- Source Port Ranges
- Destination Address Prefixes
- Destination Port Ranges
- Priority
- Description

### **Rule Creation:**
- Creates rules if they don't exist (controlled by `-CreateIfNotExists` parameter)
- Requires minimum parameters: Access, Protocol, and Priority

### **Safety Features:**
- **Dry Run Mode**: Test changes without applying them
- **Verbose Output**: Detailed progress information
- **Color-coded Output**: Easy to read status messages

## **Usage Examples:**

### **1. Update existing rule's destination ports:**
```powershell
az login
.\Invoke-NSGAutomation.ps1 -RuleName "AllowHTTPS" -Direction "Inbound" -DestinationPortRanges "443,8443"
```

### **2. Create rule if not exists with full parameters:**
```powershell
az login
.\Invoke-NSGAutomation.ps1 -RuleName "AllowSSH" -Direction "Inbound" `
    -Access "Allow" -Protocol "Tcp" -Priority 100 `
    -SourceAddressPrefixes "10.0.0.0/24" `
    -DestinationPortRanges "22" `
    -Description "Allow SSH from internal network"
```

### **3. Dry run to see what would change:**
```powershell
az login
.\Invoke-NSGAutomation.ps1 -RuleName "BlockHTTP" -Direction "Outbound" `
    -Access "Deny" -Protocol "Tcp" -Priority 200 `
    -DryRun $true
```

### **4. Update rule in specific subscription:**
```powershell
az login
.\Invoke-NSGAutomation.ps1 -SubscriptionName "Production" `
    -RuleName "AllowRDP" -Direction "Inbound" `
    -SourceAddressPrefixes "192.168.1.0/24,192.168.2.0/24"
```

### **5. Only update existing rules (don't create):**
```powershell
az login
.\Invoke-NSGAutomation.ps1 -RuleName "CustomRule" -Direction "Inbound" `
    -Access "Deny" -CreateIfNotExists $false
```

## **Script Parameters:**

- **SubscriptionId/SubscriptionName**: Target subscription
- **RuleName**: Name of the rule to find/create (required)
- **Direction**: Inbound or Outbound (required)
- **Access**: Allow or Deny
- **Protocol**: Tcp, Udp, Icmp, or *
- **SourceAddressPrefixes**: Comma-separated IP ranges
- **SourcePortRanges**: Comma-separated port ranges
- **DestinationAddressPrefixes**: Comma-separated IP ranges
- **DestinationPortRanges**: Comma-separated port ranges
- **Priority**: Rule priority (100-4096)
- **Description**: Rule description
- **CreateIfNotExists**: Create rule if not found (default: false)
- **DryRun**: Preview changes without applying (default: false)
- **ShowDetails**: Show detailed output (default: true)
- **UpdateExisting**: Update or skip existing rule (default: true)


## **Additional Features Added:**

1. **NSG Name Filtering**: Optional `-NSGNameFilter` parameter to target specific NSGs (supports wildcards)
2. **Enhanced Error Handling**: Try-catch blocks and better error reporting
3. **Rule Details Display**: Shows current rule configuration when found (in verbose mode)
4. **Better Summary**: Color-coded summary with success/failure counts
5. **Improved Parameter Display**: Shows what parameters will be updated in dry-run mode
6. **Progress Indicators**: Visual checkmarks (✓) and crosses (✗) for success/failure

## **Example Usage Scenarios:**

### **1. Update only in NSGs matching a pattern:**
```powershell
az login
.\Invoke-NSGAutomation.ps1 -RuleName "AllowHTTPS" -Direction "Inbound" `
    -DestinationPortRanges "443,8443" `
    -NSGNameFilter "prod-*"
```

### **2. Full verbose dry-run to see exactly what will happen:**
```powershell
az login
.\Invoke-NSGAutomation.ps1 -RuleName "TestRule" -Direction "Inbound" `
    -Access "Allow" -Protocol "Tcp" -Priority 150 `
    -SourceAddressPrefixes "10.0.0.0/8" `
    -DestinationPortRanges "80,443" `
    -Description "Web traffic rule" `
    -DryRun $true -Verbose $true
```

### **3. Update multiple parameters at once:**
```powershell
az login
.\Invoke-NSGAutomation.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -RuleName "CustomApp" -Direction "Inbound" `
    -Access "Allow" `
    -Protocol "Tcp" `
    -SourceAddressPrefixes "192.168.0.0/16,10.0.0.0/8" `
    -DestinationPortRanges "3000-3010,8080,9090" `
    -Priority 300 `
    -Description "Updated custom application ports"
```

### **4. Search only (no updates or creation):**
```powershell
az login
.\Invoke-NSGAutomation.ps1 -RuleName "DatabaseAccess" -Direction "Inbound" `
    -CreateIfNotExists $false
```

### **5. Create rules if they missed but do not update existing ones (even if they are different):**
```powershell
az login
.\Invoke-NSGAutomation.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -RuleName "DenyAnyOutbound" `
    -Direction Outbound `
    -Access Deny  `
    -Priority 4096 `
    -Protocol * `
    -CreateIfNotExists $true `
    -ShowDetails $true `
    -UpdateExisting $false
```