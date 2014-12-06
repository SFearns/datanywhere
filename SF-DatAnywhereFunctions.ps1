$Global:CurrentDNServer=New-Object -TypeName PSObject
Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name ClientVersion -Value "2.2.1.54"
Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name DNServiceUser -Value "TESTDOMAIN.local\sfearns"
Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name DNServicePassword -Value "Password1234"
$vDNAccessMask=@{Read=1;Write=2;CreateFolder=4;Delete=8;ShareRead=16;ShareWrite=32;ShareReadWithNested=64;ShareWriteWithNested=128}
$vDNClientTypes=@{Unknown=0;Windows=1;MAC=2;Android=3;iOS=4;Web=5}
$vDNOSType=@{Windows=2;MAC=4;Andoid=8;iPAD=32;iPhone=64}
$vDNRolePermissionMask=@{UserAccess=1;AccessSharedContent=2;Administrator=4;DownloadViaSharedLinks=8;UploadViaSharedLinks=16;InstallDatAnywhereWorkstations=32;ModifyTheProductLicense=64;DownloadResource=128;PublicWorkspaceOwner=256}
$vDNRootState=@{Available=0;Unavailable=1}
$vDNFolderInfoType=@{Folder=1;File=2}
$vDNIdentity=@{User=0;Group=1;DLGroup=2;Property=3;Contact=4;Domain=5}
#$vDNPublicWorkspaceRules=@()
$vDNUserGroupRulesUsers=@{DisplayName=$null;DomainName=$null;Email=$null;SID=$null;Type=$null}
$vDNUserGroupRulesGroups=@{DisplayName=$null;DomainName=$null;SID=$null;Type=$null}
$vDNUserGroupRules=@{Users=$vDNUserGroupRulesUsers;Groups=$vDNUserGroupRulesGroups;Operator=$vDNUserGroupRulesOperator}


function New-TrustAllCertsPolicy {
# http://stackoverflow.com/questions/11696944/powershell-v3-invoke-webrequest-https-error
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

function Connect-vDNServer {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$true)] [string]$URL,
          [Parameter(Mandatory=$true)] [string]$LoginID,
		  [Parameter(Mandatory=$true)] [string]$Password)
    $Body = '[{"Key":"client_type","Value":"1"},{"Key":"client_version","Value":'+$Global:CurrentDNServer.ClientVersion+'}]'
    $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/auth/V2/Begin?userName=$LoginID&clientName=WinClient&Root=1") -Method POST -Body $Body -ContentType 'application/json' -SessionVariable $DNSession
    if ($Part1.ReturnCode -eq 0){
        $Body = @{InputParam=$Password;RootID=0} | ConvertTo-Json
        $Part2 = Invoke-RestMethod -Uri ($URL+"/rest/auth/V2/Continue") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Part1.Data.AuthToken}
        if ($Part2.ReturnCode -eq 0){
            $Part3 = Invoke-RestMethod -Uri ($URL+"/rest/auth/LogonInfo") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Part1.Data.AuthToken}
            if ($Part3.ReturnCode -eq 0){
                Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name AuthToken -Value $Part1.Data.AuthToken
                Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name URL -Value $URL
                Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name User -Value $Part3.Data.User
                Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name UserDisplayName -Value $Part3.Data.UserDisplayName
                Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name UserEmail -Value $Part3.Data.UserEmail
                Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name RolePermissionMask -Value $Part3.Data.RolePermissionMask
                Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name IsDemoLicense -Value $Part3.Data.IsDemoLicense
                Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name Connected -Value $True
                Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1;"Part2"=$Part2;"Part3"=$Part3}
            } else {
                Write-Host "ERROR: Unable to connect (/LogonInfo)" -ForegroundColor Red -BackgroundColor Black
                Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1;"Part2"=$Part2;"Part3"=$Part3}
            }
        } else {
            Write-Host "ERROR: Unable to connect (/Continue)" -ForegroundColor Red -BackgroundColor Black
            Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1;"Part2"=$Part2}
        }
    } else {
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name Connected -Value False
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
        Write-Host "ERROR: Unable to connect (/Begin)" -ForegroundColor Red -BackgroundColor Black
    }
}

function Disconnect-vDNServer {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if ($Global:CurrentDNServer.Connected -eq $True) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/auth/Logout") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -eq 0){
            $Global:CurrentDNServer.Connected=$False
            Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
        } else {
            Write-Host "ERROR: Unable to disconnect (/Logout)" -ForegroundColor Red -BackgroundColor Black
            Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
        }
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
}

function Get-vDNIdentities {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$true)]  [string]$SearchString,
          [Parameter(Mandatory=$false)] [int]$NumOfObjects=100,
          [Parameter(Mandatory=$false)] [int]$QueryFilter=1,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/DNIdentities/All?SearchString=$SearchString&NumOfObjects=$NumOfObjects&QueryFilter=$QueryFilter") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to get Identities (/DNIdentities/All)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Get-vDNCredentials {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/admin/Credentials/All") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to get Credentials (/Credentials/All)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function New-vDNRootFolder {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [boolean]$UploadEnabled=$false,
          [Parameter(Mandatory=$false)] [boolean]$DownloadEnabled=$false,
          [Parameter(Mandatory=$false)] [boolean]$NestedUpload=$UploadEnabled,
          [Parameter(Mandatory=$false)] [boolean]$NestedDownload=$DownloadEnabled,
          [Parameter(Mandatory=$false)] [boolean]$IncludeNested=$true,
          [Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$true)]  [string]$RootName,
          [Parameter(Mandatory=$true)]  [string]$RootPath,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if ($Global:CurrentDNServer.Connected -eq $True) {
        $Result = $false
        $Body = @{"User"=$DNServiceUser;"Password"=$DNServicePassword;"Data"=@{"Name"=$RootName;"Path"=$RootPath;"SyncManagerWid"=1;"ItemType"=1;"IncludeNested"=$IncludeNested;"FilerID"=0;"EnforceSharePermissions"=$true;"PreviewOnly"=$false}} | ConvertTo-Json
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/admin/Root/Add?UploadEnabled=$UploadEnabled&DownloadEnabled=$DownloadEnabled&NestedUpload=$NestedUpload&NestedDownload=$NestedDownload") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -eq 0){
            $Result=$true
        } else {
            Write-Host "ERROR: Unable to make root (/Root/Add)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Result
}

function Remove-vDNRootFolder {
    [CmdletBinding()]
    [OutputType([string])]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$true)]  [string]$RootID,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if ($Global:CurrentDNServer.Connected -eq $True) {
        $Result = $false
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/admin/Root/Remove?RootID=$RootID") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -eq 0){
            $Result=$true
        } else {
            Write-Host "ERROR: Unable to remove root (/Root/Remove)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Result
}

function Set-vDNRootFolder {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$true)]  [boolean]$UploadEnabled,
          [Parameter(Mandatory=$true)]  [boolean]$DownloadEnabled,
          [Parameter(Mandatory=$true)]  [boolean]$NestedUpload,
          [Parameter(Mandatory=$true)]  [boolean]$NestedDownload,
          [Parameter(Mandatory=$true)]  [boolean]$IncludeNested,
          [Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$true)]  [string]$RootName,
          [Parameter(Mandatory=$true)]  [string]$RootPath,
          [Parameter(Mandatory=$true)]  [string]$ID,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if ($Global:CurrentDNServer.Connected -eq $True) {
        $Result = $false
        $Body = @{"User"=$DNServiceUser;"Password"=$DNServicePassword;"Data"=@{"Name"=$RootName;"Path"=$RootPath;"ID"=$ID;"SyncManagerWid"=1;"ItemType"=1;"IncludeNested"=$IncludeNested;"FilerID"=0;"EnforceSharePermissions"=$true;"PreviewOnly"=$false}} | ConvertTo-Json
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/admin/Root/Update?UploadEnabled=$UploadEnabled&DownloadEnabled=$DownloadEnabled&NestedUpload=$NestedUpload&NestedDownload=$NestedDownload") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -eq 0){
            $Result=$true
        } else {
            Write-Host "ERROR: Unable to make root (/Root/Update)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Result
}

function Get-vDNRootFolders {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$true)]  [string]$RootPath,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Body = @{"User"=$DNServiceUser;"Password"=$DNServicePassword} | ConvertTo-Json
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/admin/FolderItem/All?FolderPath=$RootPath&SyncmanagerID=1&RootID=0") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to list roots (/FolderItem/All)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function New-vDNWorkspacePrivate {
    [CmdletBinding()]
    [OutputType([string])]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$true)]  [string]$WorkspaceName,
          [Parameter(Mandatory=$false)] [boolean]$IncludeHomeFolders=$false,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if ($Global:CurrentDNServer.Connected -eq $True) {
        $Result = $false
        $Body = @{"PrivateWorkspaceData"=@{"Name"=$WorkspaceName;"IsIncludeHomeFolders"=$IncludeHomeFolders}} | ConvertTo-Json
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/Workspace/CreatePrivate") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -eq 0){
            $Result=$true
        } else {
            Write-Host "ERROR: Unable to make private workspace (/Workspace/CreatePrivate)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Result
}

function New-vDNWorkspacePublic {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL,
          [Parameter(Mandatory=$true)]  [string]$Name,
          [Parameter(Mandatory=$false)] [string]$Description=$null,
          [Parameter(Mandatory=$false)] [string]$CustomOwner='null',
          [Parameter(Mandatory=$false)] [boolean]$IsForced=$true,
          [Parameter(Mandatory=$false)] [boolean]$IsEveryone=$false,
          [Parameter(Mandatory=$false)] [boolean]$IsIncludeHomeFolders=$false,
          [Parameter(Mandatory=$false)] [int]$RecipientMatching=1,
          [Parameter(Mandatory=$false)] [array]$AdPropertyRules='[]',
          [Parameter(Mandatory=$false)] [array]$UserGroupRules='[]')
    Write-Host "This function is still a WIP - Need to transfer Arrays"
    if ($Global:CurrentDNServer.Connected -eq $True) {
        $Result = $false
        $Body = @{"PublicWorkspaceData"=@{
            "PublicWorkspaceRules"=@{"AdPropertyRules"=$AdPropertyRules;"UserGroupRules"=$UserGroupRules};
            "Name"=$Name;"Description"=$Description;
            "CustomeOwner"=$CustomeOwner;"RecipientMatching"=$RecipientMatching;
            "IsForced"=$IsForced;"IsEveryone"=$IsEveryone;
            "IsIncludeHomeFolders"=$IsIncludeHomeFolders}} | ConvertTo-Json -Depth 10 
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/Workspace/CreatePublic") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -eq 0){
            $Result=$true
        } else {
            Write-Host "ERROR: Unable to make private workspace (/Workspace/CreatePublic)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Result
}

function Get-vDNWorkspaceSingle {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$true)]  [int]$WorkspaceID,
          [Parameter(Mandatory=$false)] [boolean]$WorkspaceItemsList=$true,
          [Parameter(Mandatory=$false)] [boolean]$IncludeOwnerData=$true,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Body = @{"WorkspaceItemsList"=$WorkspaceItemsList;"IncludeOwnerData"=$IncludeOwnerData} | ConvertTo-Json
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/V3/Workspace/ID=$WorkspaceID") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to list workspaces (/Workspace/ID)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Get-vDNWorkspaceAll {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [boolean]$PrivateWorkspace=$true,
          [Parameter(Mandatory=$false)] [boolean]$AcceptedReceivedPublicWorkspace=$true,
          [Parameter(Mandatory=$false)] [boolean]$UnacceptedReceivedPublicWorkspace=$true,
          [Parameter(Mandatory=$false)] [boolean]$AllOwnedPublicWorkspaces=$true,
          [Parameter(Mandatory=$false)] [boolean]$MyOwnedPublicWorkspaces=$true,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Body = @{"PrivateWorkspace"=$PrivateWorkspace;"AcceptedReceivedPublicWorkspace"=$AcceptedReceivedPublicWorkspace;"UnacceptedReceivedPublicWorkspace"=$UnacceptedReceivedPublicWorkspace;"AllOwnedPublicWorkspaces"=$AllOwnedPublicWorkspaces;"MyOwnedPublicWorkspaces"=$MyOwnedPublicWorkspaces} | ConvertTo-Json
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/V3/Workspace/All") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to list workspaces (/Workspace/All)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Get-vDNWorkspacePrivate {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Body = @{"PrivateWorkspace"=$true;"AcceptedReceivedPublicWorkspace"=$true;"MyOwnedPublicWorkspace"=$false} | ConvertTo-Json
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/V3/Workspace/All") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to list workspaces (/Workspace/All)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function New-vDNWorkspaceRoot {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$true)]  [int]$WorkspaceID,
          [Parameter(Mandatory=$true)]  [int]$RootID,
          [Parameter(Mandatory=$false)] [int]$RootType=1,
          [Parameter(Mandatory=$true)]  [string]$RootName,
          [Parameter(Mandatory=$false)] [boolean]$Nested=$true,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Body = @{"WorkspaceID"=$WorkspaceID;"WorkspaceItems"=@{"Name"=$RootName;"Path"="";"RootID"=$RootID;"Type"=$RootType;"IsNested"=$Nested}} | ConvertTo-Json
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/Workspace/AddItems") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to list workspaces (/Workspace/All)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

# WIP
function Remove-vDNWorkspaceFolder {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$true)]  [string]$RootID,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if ($Global:CurrentDNServer.Connected -eq $True) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/admin/Root/Remove?RootID=$RootID") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to remove workspace (/Root/Remove)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Get-vDNConfig {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/admin/Config/All") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to get Credentials (/Config/All)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Get-vDNLanguages {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/Languages/All") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to get Credentials (/Languages/All)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Get-vDNADProperty {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/AdProperties/All") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to get Credentials (/AdProperties/All)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function New-vDNADProperty {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL,
          [Parameter(Mandatory=$true)]  [string]$LDAPName)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/AdProperties/Add?ldapName=$LDAPName") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to get Credentials (/AdProperties/Add)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Set-vDNADProperty {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL,
          [Parameter(Mandatory=$true)]  [int]$ID,
          [Parameter(Mandatory=$true)]  [string]$LDAPName)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/AdProperties/Rename?adPropertyID=$ID&newLdapName=$LDAPName") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to get Credentials (/AdProperties/Rename)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Remove-vDNADProperty {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL,
          [Parameter(Mandatory=$true)]  [int]$ID)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/AdProperties/Remove?adPropertyID=$ID") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to get Credentials (/AdProperties/Remove)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Get-vDNResourceInfo {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL,
          [Parameter(Mandatory=$false)] [string]$ID=$null)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        if ($ID){
            $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/Resource/Info?id=$ID") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        } else {
            $Body = '["WindowsClient", "WindowsClientReleaseNotes", "WindowsClientUserGuide", "MacClient", "MacClientReleaseNotes", "MacClientUserGuide", "AndroidClientReleaseNotes", "AndroidClientUserGuides", "iOsClientReleaseNotes", "iOsClientUserGuide"]'
            $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/Resource/Infos") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        }
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to get Resource Info (/Resource/Info)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Get-vDNResource {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL,
          [Parameter(Mandatory=$false)] [long]$Offset=0,
          [Parameter(Mandatory=$true)]  [string]$ID,
          [Parameter(Mandatory=$true)]  [string]$Version,
          [Parameter(Mandatory=$true)]  [string]$OutFile)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        Invoke-RestMethod -Uri ($URL+"/rest/transfer/Download/Resource?id=$ID&version=$Version&offset=$Offset") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken} -OutFile $OutFile
        if (!(Test-Path -Path $Offset)){
            Write-Host "ERROR: Unable to Download Resource (/Download/Resource)" -ForegroundColor Red -BackgroundColor Black
            Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value "Missing Output file ($OutFile)"
        }
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Get-vDNConfigSingle {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL,
          [Parameter(Mandatory=$true)]  [string]$Key)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/Configuration?key=$Key") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to get Credentials (/Configuration?key)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Set-vDNConfigSingle {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL,
          [Parameter(Mandatory=$true)]  [string]$Key,
          [Parameter(Mandatory=$true)]  [string]$Value)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/admin/Config/Add?Key=$Key&Value=$Value") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to get Credentials (/Config/Add)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Get-vDNInfo {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/license/GetInfo") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to get Resource Info (/license/GetInfo)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Get-vDNToken {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/license/GetToken") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to get Resource Info (/license/GetToken)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Set-vDNUpdateAutomatic {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL,
          [Parameter(Mandatory=$true)]  [string]$eMail,
          [Parameter(Mandatory=$true)]  [string]$Serial)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/license/TryUpdateAutomatic?Email=$eMail&Serial=$Serial") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to get Resource Info (/license/TryUpdateAutomatic)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Set-vDNUpdateManual {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL,
          [Parameter(Mandatory=$true)]  [string]$eMail,
          [Parameter(Mandatory=$true)]  [string]$Serial,
          [Parameter(Mandatory=$true)]  [string]$LicenseKey)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/license/TryUpdateManual?Email=$eMail&Serial=$Serial&LicenseKey=$LicenseKey") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to get Resource Info (/license/TryUpdateManual)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $Part1
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}








