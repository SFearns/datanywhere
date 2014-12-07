New-TrustAllCertsPolicy

Connect-vDNServer -URL https://192.168.36.50 -LoginID 'sfearns' -Password Password1234
# Disconnect-vDNServer

# Create the ROOTs
#New-vDNRootFolder -RootName Public -UploadEnabled $true -DownloadEnabled $true -RootPath \\dn-test\DatAnywhere_Storage_Area\steve\Public
#New-vDNRootFolder -RootName Private -RootPath \\dn-test\DatAnywhere_Storage_Area\steve\Private

$tr = Get-vDNRootAllFolders
$tw = Get-vDNWorkspaceAll
$tr1 = Get-vDNRootFolders -RootPath \\dn-test\DatAnywhere_Storage_Area\steve\Public
$tr2 = Get-vDNRootFolders -RootPath \\dn-test\DatAnywhere_Storage_Area\steve\Private
#$tw1 = New-vDNWorkspaceItem -RootID $tr1.Data.InfoItem.RootID -RootName $tr1.Data.InfoItem.Name -WorkspaceID 86 -RootType $vDNFolderInfoType.Folder
#$tw2 = New-vDNWorkspaceItem -RootID $tr2.Data.InfoItem.RootID -RootName $tr2.Data.InfoItem.Name -WorkspaceID 86 -RootType $vDNFolderInfoType.Folder
#Get-vDNListOfItems -FolderPath "" -RootID 3
$tloi=Get-vDNChildItem -RootID 3
$tloi.data.Items
#if ($tloi.data.Items.Count -gt 0) {
#    $tloi.data.Items[1]
#    $trci=Remove-vDNChildItem -Path "\" -Name $tloi.data.Items[1].Name -Revision $tloi.data.Items[1].Revision -Type $tloi.data.Items[1].Type -RootID 3
#    $trci
#}
#$nfi=New-vDNFolderItem -RootID 3 -Path "TestFolder"
#$nfi

<#
$tt3Group = Get-vDNIdentities -SearchString 'Domain Users' -QueryFilter 2
$tt3Group2 = Get-vDNIdentities -SearchString 'Domain Admins' -QueryFilter 2
$tt3User = Get-vDNIdentities -SearchString 'Administrator' -QueryFilter 1
$tt3User2 = Get-vDNIdentities -SearchString 'sfearns' -QueryFilter 1
$tt3User3 = Get-vDNIdentities -SearchString 'steve' -QueryFilter 1

$tt3UGRule = @()
$Element1=New-Object -TypeName PSObject
    $Element = @{Operator=0;Users=$tt3User3.Data.DNIdentities;Groups=$null}
    $tt3UGRule+=$Element
#    $Element = @{Operator=0;Users=$tt3User.Data.DNIdentities;Groups=$null}
#    $tt3UGRule+=$Element
#    $Element = @{Operator=0;Users="";Groups=$tt3Group.Data.DNIdentities}
#    $tt3UGRule+=$Element
#    $Element = @{Operator=0;Users=$tt3User2.Data.DNIdentities;Groups=""}
#    $tt3UGRule+=$Element
#    $Element = @{Operator=0;Users=$null;Groups=$tt3Group2.Data.DNIdentities}
#    $tt3UGRule+=$Element
#    $ADPropertyRule = @{"PropId"=7;"Operator"=0;"Values"="My Workspace"}

$tt3 = New-vDNWorkspacePublic -Name SF-Public11 -Description 'Owner & User = steve' -RecipientMatching $vDNRecipientMatching.AND -UserGroupRules $tt3UGRule -CustomOwner $tt3User3.Data.DNIdentities
#>
