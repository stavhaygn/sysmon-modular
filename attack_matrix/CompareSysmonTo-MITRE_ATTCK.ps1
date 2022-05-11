<#
.Synopsis
    Description: For Sysmon Modular MITRE ATT&CK Management!
.DESCRIPTION
    Requirements: PowerShell 7+ and Windows 10
    This script is useful for checking your Sysmon config for invalid and valid MITRE ATT&CK TTPs. ModularConfig Path is used for recursively looking for all include_* files.  CompiledConfigPath is good for a single .xml file. 
    It also provides a good reference for the MITRE ATT&CK v11.0 and what is found in your Sysmon Config.
.NOTES
    Author: nicpenning, stavhaygn
.LINK
    Source of this script:
    https://github.com/olafhartong/sysmon-modular/pull/80
.EXAMPLE
    .\CompareSysmonTo-MITRE_ATTCK.ps1
.EXAMPLE
    .\CompareSysmonTo-MITRE_ATTCK.ps1 -PrintOutResultsOnScreen
.EXAMPLE
    .\CompareSysmonTo-MITRE_ATTCK.ps1 -ModularConfigPath "C:\Users\blu3teamer\Downloads\sysmon-modular-master"
.EXAMPLE
    .\CompareSysmonTo-MITRE_ATTCK.ps1 -CompiledConfigPath "C:\Users\blu3teamer\Downloads\sysmon-modular-master\sysmonconfig.xml"
.EXAMPLE
    .\CompareSysmonTo-MITRE_ATTCK.ps1 -CompiledConfigPath "C:\Users\blu3teamer\Downloads\sysmon-modular-master\sysmonconfig.xml" -LoadMITREv11FromGitHub
#>

[CmdletBinding()]
[Alias()]
Param
(
    # The location of the Sysmon modular config directory.
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        Position = 0)]
    $ModularConfigPath,
    # The location of the Sysmon compiled config file.
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        Position = 1)]
    $CompiledConfigPath,
    # Whether to load MITRE ATT&CK v11.0 from GitHub.
    [switch]$LoadMITREv11FromGitHub,
    [switch]$PrintOutResultsOnScreen
)

if ($null -eq $ModularConfigPath -and $null -eq $CompiledConfigPath) {
    $runTimePath = Read-Host -Prompt "Please enter the path of a modular directory or merged xml file" 
    if ($runTimePath -match ".xml") {
        Write-Host "This is an XMl file." -ForegroundColor Yellow
        $CompiledConfigPath = $runTimePath
    }
    else {
        Write-Host "Assuming this is a directory since your path did not contain .xml. Recursivley looking for include_*.xml files in your path: $runTimePath." -ForegroundColor Yellow
        $ModularConfigPath = $runTimePath
    }
}

if ($true -eq $LoadMITREv11FromGitHub) {
    $loadMITREv11FromGitHubOption = "y"
}
else {
    $loadMITREv11FromGitHubOption = Read-Host "Would you like to load the MITRE ATT&CK v11.0 from GitHub? (Requires Internet Connectivity) (y or n)"
}

if ($loadMITREv11FromGitHubOption -eq "y") {
    #Get copy of Mitre ATT&CK Framework v11.0
    Write-Host "Getting MITRE ATT&CK Framework v11.0 !" -Foreground Green
    $mitreURL = "https://raw.githubusercontent.com/mitre/cti/ATT&CK-v11.0/enterprise-attack/enterprise-attack.json"
    $mitre = Invoke-RestMethod $mitreURL
    if ($mitre) {
        Write-Host "MITRE ATT&CK Framework loaded and ready for use!" -Foreground Blue
    }
    else {
        Write-Host "Could not download MITRE ATT&CK Framework check your internet connection. Exiting."
        exit
    }
}
elseif ($loadMITREv11FromGitHubOption -eq "n") {
    $mitreLocalFile = Read-Host "Please enter the full path of the enterprise-attck.json file from MITRE's GitHub repo"
    $mitre = Get-Content $mitreLocalFile | ConvertFrom-Json
    if ($mitre) {
        Write-Host "Local MITRE ATT&CK Framework loaded and ready for use!" -Foreground Blue
    }
    else {
        Write-Host "Could not load local MITRE ATT*CK json. Exiting."
        exit
    }
}
else {
    Write-Host "Not a valid option - Please rerun the script with a valid option. Exiting."
    exit
}

$sysmon = [xml]''
$sysmonAll = [xml]''

#Technique Regex
$technique = 'technique_id=(.*),technique_name=(.*)'

############################################################################################################## MITRE ATT&CK ##############################################################################################################
# All of the below commented is for testing and future concepts.

#Tactics
#$mitre.objects | Where-Object {$_.type -eq "x-mitre-tactic"} | Select-Object -Property name, type, modified, created | Out-GridView
#$tactics = $mitre.objects | Where-Object {$_.type -eq "x-mitre-tactic"}

#Techniques (Attack Patterns)
#$mitre.objects | Where-Object {$_.type -eq "attack-pattern"} | Select-Object -Property name, type, external_references, modified, created | Out-GridView

#Techniques (Attack Patterns)
#$mitre.objects | Where-Object {$_.external_references.source_name -eq "mitre-attack"} | Select-Object -Property external_references, name, kill_chain_phases | Out-GridView


$global:techniquesTable = @()
$tacticName = @()
$tacticId = @()
function getV11Techniques {
    $techniques = $mitre.objects | Where-Object { $_.external_references.source_name -eq "mitre-attack" -and $_.type -eq "attack-pattern" -and $null -ne $_.kill_chain_phases.phase_name } | Select-Object -Property external_references, name, kill_chain_phases, x_mitre_is_subtechnique, created, modified, x_mitre_version
    $tactics = $mitre.objects | Where-Object { $_.type -eq "x-mitre-tactic" } | Select-Object -Property external_references, name, x_mitre_shortname
    $techniques | ForEach-Object {
        $tacticName = $(if ($_.kill_chain_phases.phase_name) { $_.kill_chain_phases.phase_name | ForEach-Object { (Get-Culture).TextInfo.ToTitleCase($($_)) } }else {}).Replace("-", " ")
        $tacticId = $tactics | Where-Object -Property name -In $tacticName
        $techniqueID = $($_.external_references | Where-Object { $null -ne $_.external_id } | Select-Object -Property external_id).external_id.split('.')[0]
        $techniqueName = $(if ($null -eq $_.x_mitre_is_subtechnique) { $_.name }else { $techniques | Where-Object { $_.external_references.external_id -eq $techniqueID } | Select-Object name }).name
        $techniqueReference = if ($null -eq $_.x_mitre_is_subtechnique) { $($_.external_references | Where-Object -property source_name -eq "mitre-attack").url }else { $($($techniques | Where-Object { $_.external_references.external_id -eq $techniqueID } | Select-Object external_references).external_references | Where-Object -Property external_id -eq $techniqueId).url }
        $subtechniqueID = if ($_.x_mitre_is_subtechnique -eq $true) { $($_.external_references | Where-Object { $null -ne $_.external_id } | Select-Object -Property external_id).external_id }else {}
        $subtechniqueName = if ($_.x_mitre_is_subtechnique -eq $true) { $_.name }else {}
        $subtechniqueReference = if ($_.x_mitre_is_subtechnique -eq $true) { $($_.external_references | Where-Object -property source_name -eq "mitre-attack").url }else {}
        
        #Create simple object for high level view (out-gridview)
        $global:techniquesTable += [PSCustomObject]@{
            tactic_name            = $tacticName
            tactic_id              = $tacticId.external_references.external_id
            tactic_reference       = $tacticId.external_references.url
            technique_name         = $techniqueName
            technique_id           = $techniqueID
            technique_reference    = $techniqueReference
            subtechnique_name      = $subtechniqueName
            subtechnique_id        = $subtechniqueID
            subtechnique_reference = $subtechniqueReference
            created_at             = $_.created
            modified_at            = $_.modified
            rule_version           = $_.x_mitre_version
        }

    }
}

############################################################################################################## MITRE ATT&CK ##############################################################################################################


function extractTTPsFromRule($ruleDetails) {
    #Get TTPs from Regex hits
    $global:tacticNameMatch = ''
    $global:techniqueIDMatch = ''
    $global:techniqueNameMatch = ''
    $techniquesMatch = $ruleDetails[0] | Select-String -Pattern $technique
    if ($techniquesMatch) {
        $global:techniqueIDMatch = if ($techniquesMatch.Matches.Groups[1].Value) { $techniquesMatch.Matches.Groups[1].Value }
        $global:techniqueNameMatch = if ($techniquesMatch.Matches.Groups[2].Value) { $techniquesMatch.Matches.Groups[2].Value }
    }

    if ($techniqueIDMatch) {
        $tacticNameMatches = ($techniquesTable | Where-Object { $_.technique_id -eq $techniqueIDMatch -or $_.subtechnique_id -eq $techniqueIDMatch } | Select-Object -Unique tactic_name).tactic_name
        if ($tacticNameMatches) {
            $global:tacticNameMatch = [String]::Join(", ", $tacticNameMatches)
        }
    }
    
    #Build custom object with all of the needed details
    $global:sysmonEventToMitre += [PSCustomObject]@{
        event_id         = $ruleDetails[1] # Example: 1
        event_name       = $ruleDetails[2] #Example: Process Create
        sysmon_rule      = $ruleDetails[3] #Example: Parent Image
        sysmon_condition = $_.condition
        sysmon_text      = $_.'#text'
        tactic_name      = $tacticNameMatch
        technique_id     = $techniqueIDMatch
        technique_name   = $techniqueNameMatch
        config_file_name = $configFileName
    }
}

$global:sysmonEventToMitre = @()

function extractMitreTechniques($sysmonAndFileName) {
    $sysmon = $sysmonAndFilename[0]
    #Event ID 1: Process creation
    $eventId = "1"
    $ruleType = "ProcessCreate"
    $subRuleType = "ParentImage"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.$ruleType.$subRuleType | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    $subRuleType = "Original FileName"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ProcessCreate.OriginalFileName | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    $subRuleType = "Command Line"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ProcessCreate.CommandLine | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    $subRuleType = "Image"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ProcessCreate.Image | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    #Event ID 2: A process changed a file creation time
    $eventId = "2"
    $ruleType = "File Create"
    $subRuleType = "Target Filename"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.FileCreate.TargetFilename | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    $subRuleType = "Image"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.FileCreate.Image | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    #Event ID 3: Network connection
    $eventId = "3"
    $ruleType = "Network Connect"
    $subRuleType = "Image"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.NetworkConnect.Image | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    $subRuleType = "Destination Port"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.FileCreate.DestinationPort | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    #Event ID 4: Sysmon service state changed - Skipped #TODO

    #Event ID 5: Process terminated
    $eventId = "5"
    $ruleType = "Process Terminate"
    $subRuleType = "Image"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ProcessTerminate.Image | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    #Event ID 6: Driver loaded - Skipped no Mitre #TODO

    #Event ID 7: Image loaded
    $eventId = "7"
    $ruleType = "Image Loaded"
    $subRuleType = "Image"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ImageLoad.ImageLoaded | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    $subRuleType = "Original FileName"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ImageLoad.OriginalFileName | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    $subRuleType = "Image"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ImageLoad.Rule.Image | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    $subRuleType = "Image Loaded"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ImageLoad.Rule.ImageLoaded | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    #Event ID 8: CreateRemoteThread - Skipped No Mitre #TODO

    #Event ID 9: RawAccessRead - Skipped No Mitre #TODO

    #Event ID 10: ProcessAccess
    $eventId = "10"
    $ruleType = "Process Access"
    $subRuleType = "Call Trace"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.$ruleType.$subRuleType | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    $subRuleType = "Granted Access"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ProcessAccess.GrantedAccess | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    $subRuleType = "Source Image"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ProcessAccess.SourceImage | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    $subRuleType = "Target Image"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ProcessAccess.Rule.TargetImage | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    $subRuleType = "Granted Access"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.ProcessAccess.Rule.GrantedAccess | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    #Event ID 11: FileCreate
    $eventId = "11"
    $ruleType = "File Create"
    $subRuleType = "Target Filename"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.FileCreate.TargetFilename | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    $subRuleType = "Image"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.FileCreate.Image | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    #Event ID 12: RegistryEvent (Object create and delete) + Event ID 13: RegistryEvent (Value Set) + Event ID 14: RegistryEvent (Key and Value Rename)
    $eventId = "12, 13, 14"
    $ruleType = "Registry Event"
    $subRuleType = "Target Object"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.RegistryEvent.TargetObject | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }


    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.RegistryEvent.Rule.TargetObject | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    #Event ID 15:FileCreateStreamHash
    $eventId = "15"
    $ruleType = "File Create Stream Hash"
    $subRuleType = "Target Filename"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.FileCreateStreamHash.TargetFilename | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    #Event ID 16: ServiceConfigurationChange - Skipped

    #Event ID 17: PipeEvent (Pipe Created) + Event ID 18: PipeEvent (Pipe Connected) - Skipped no Mitre #TODO

    #Event ID 19: WmiEvent (WmiEventFilter activity detected) + Event ID 20: WmiEvent (WmiEventConsumer activity detected) + Event ID 21: WmiEvent (WmiEventConsumerToFilter activity detected)
    $eventId = "19, 20, 21"
    $ruleType = "Wmi Event"
    $subRuleType = "Operation"
    $eventDetail = $sysmon.Sysmon.EventFiltering.RuleGroup.WmiEvent.Operation | Where-Object { $_.name -match "technique" }
    if ($eventDetail) { 
        $eventDetail | ForEach-Object {
            extractTTPsFromRule($_.name, $eventId, $ruleType, $subRuleType)
        }
    }

    #Event ID 22: DNSEvent (DNS query) - Skipped no Mitre #TODO

    #Event ID 23: FileDelete (A file delete was detected) - Skipped no Mitre #TODO


}

#Use the compiled file
if ($CompiledConfigPath) {
    #Get the v11.0 Techniques from MITRE
    getV11Techniques

    #Get file name of single xml file
    $xmlFiles = Get-ChildItem $CompiledConfigPath

    #Load single xml file and pass the path name to the function to add the column for what file the TTP was found in.
    Write-Host "Using the file: $xmlFiles for analysis." -ForegroundColor Green
    $sysmon.load($CompiledConfigPath)
    Write-Host "Extracting MITRE ATT&CK Tactics, Techniques, and Subtechniques from your defined SysMon file!"
    extractMitreTechniques $sysmon, $($xmlFiles.Name)
}

#Use the modular files
if ($ModularConfigPath) {
    #Get the v11.0 Techniques from MITRE
    getV11Techniques

    #Grab all xml files in the directory of your choosing. This is recursive!
    $xmlFiles = Get-ChildItem $ModularConfigPath -Recurse | Where-Object {
        $_.Name -match "include_" -and $_.Name -match ".xml"
    }
    $arrayCounter = 0
    if ($xmlFiles) {
        $xmlFiles.FullName | ForEach-Object {
            #Check for valid XML files and let the user know if the file is not valid XML.
            try {
                $sysmonAll.load($_)
            }
            catch {
                Write-Host "Not a valid XML file detected. Possibly due to commented out text. Check this file out: $($xmlFiles.FullName[$arrayCounter])" -ForegroundColor DarkRed
            }
            extractMitreTechniques $sysmonAll, $_
            $arrayCounter++
        }
    }
    else {
        Write-Host "No Sysmon config files starting with include_ have been found. Displaying MITRE ATT&CK Windows Only." -ForegroundColor Yellow
    }
}

#Validate Mitre Lookups to ATT&CK
Write-Host "Checking for valid MITRE in Sysmon rule names." -ForegroundColor Blue
$global:sysmonEventToMitre | ForEach-Object {
    #Check for valid Technique IDs
    if ($_.technique_id -in $global:techniquesTable.technique_id -or $_.technique_id -in $global:techniquesTable.subtechnique_id) {
        #Match Found
        $_ | Add-Member -NotePropertyMembers @{ValidMitreTechnique = "True" } -Force
    }
    elseif ($_.technique_id -notin $global:techniquesTable.technique_id -and $_.technique_id -notin $global:techniquesTable.subtechnique_id) {
        #No Match Found - Invalid
        $_ | Add-Member -NotePropertyMembers @{ValidMitreTechnique = "False" } -Force
    }
}

function exportForMatrix {
    #MITRE ATT&CK Matrix Generator
    #Template to add known techniques to:
    $mitreAttckTemplateObject = @()
    $mitreAttckTemplateObject = [PSCustomObject]@{
        name                          = "Sysmon-modular"
        versions                      = [PSCustomObject]@{
            attack    = "11"
            navigator = "4.6.1"
            layer     = "4.3"
        }
        domain                        = "enterprise-attack"
        description                   = ""
        filters                       = [PSCustomObject]@{
            platforms = @("Windows")
        }
        sorting                       = "0"
        layout                        = [PSCustomObject]@{
            layout   = "side"
            showID   = "false"
            showName = "true"
        }
        hideDisabled                  = "false"
        techniques                    = @()
        gradient                      = [PSCustomObject]@{
            colors   = @("#ff6666", "#ffe766", "#8ec843")
            minValue = "0"
            maxValue = "100"
        }
        legendItems                   = @()
        metadata                      = @()
        showTacticRowBackground       = "false"
        tacticRowBackground           = "#dddddd"
        selectTechniquesAcrossTactics = "true"
        selectSubtechniquesWithParent = "false"
    }

    $global:sysmonEventToMitre | Where-Object { $_.ValidMitreTechnique -eq "true" } | ForEach-Object {
        #Iterate through all tactics as each tactic must be in its own object when exporting to the attack tool for visualizing. Deuplicates may exist when rules are found to hit the same technique multiple times.
        if ($_.tactic_name) {
            Write-Host "Tactic name found! Cleaning up and conforming to ATT&CK naming standard and adding to Attack Navigator file!"
            $splitTactics = $_.tactic_name.Split(", ")
        }
        else {
            Write-Host "Tactic not found, this is likely because the Sysmon config does not contain that tactic name."
        }
        
        for ($i = 0; $i -lt $splitTactics.count; $i++) {
            $mitreAttckTemplateObject.techniques += New-Object -TypeName PSobject -Property @{
                "techniqueID"       = $_.technique_id; 
                "tactic"            = $splitTactics[$i].ToLower().Replace(" ", "-");
                "color"             = "#fd8d3c";
                "comment"           = "";
                "enabled"           = "true";
                "metadata"          = @();
                "showSubtechniques" = "true";
            }
        }
    }

    #Export attack matrix to JSON!
    Write-Host "Exporting MITRE ATT&CK JSON (Sysmon-modular.json) for use in the Attack Navigator found here: https://mitre-attack.github.io/attack-navigator/" -ForegroundColor Blue
    $mitreAttckTemplateObject | ConvertTo-Json -Depth 6 | Out-File "Sysmon-modular.json"

}


#Get copy of Mitre ATT&CK Framework
exportForMatrix

if ($true -eq $PrintOutResultsOnScreen) {
    #Print out the results!
    Write-Host "Printing out tables on screen for analysis. Thanks for using this tool!" -ForegroundColor Green
    $global:sysmonEventToMitre | Out-GridView -Title "SysMon Events that map to MITRE"
    $global:techniquesTable | Out-GridView -Title "MITRE ATT&CK Table with Tactics, Techniques, and Subtechniques"
}
