# This is my first attempt at using my own Objects and global variables.
# The idea was that if I use a global variable I can reduce the number of parameters required
# for the functions.
$Global:CurrentDNServer=New-Object -TypeName PSObject
Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name ClientVersion -Value "2.2.1.54"
Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name DNServiceUser -Value "TESTDOMAIN.local\sfearns"
Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name DNServicePassword -Value "Password1234"

# The following are a set of variables which are used by this module or
# are useful for parameter passing.
$vDNAccessMask=@{Read=1;Write=2;CreateFolder=4;Delete=8;ShareRead=16;ShareWrite=32;ShareReadWithNested=64;ShareWriteWithNested=128}
$vDNClientTypes=@{Unknown=0;Windows=1;MAC=2;Android=3;iOS=4;Web=5}
$vDNOSType=@{Windows=2;MAC=4;Andoid=8;iPAD=32;iPhone=64}
$vDNRolePermissionMask=@{UserAccess=1;AccessSharedContent=2;Administrator=4;DownloadViaSharedLinks=8;UploadViaSharedLinks=16;InstallDatAnywhereWorkstations=32;ModifyTheProductLicense=64;DownloadResource=128;PublicWorkspaceOwner=256}
$vDNRootState=@{Available=0;Unavailable=1}
$vDNFolderInfoType=@{Folder=1;File=2}
$vDNIdentity=@{User=0;Group=1;DLGroup=2;Property=3;Contact=4;Domain=5}
$vDNRecipientMatching=@{AND=0;OR=1}
#$vDNPublicWorkspaceRules=@()
$vDNUserGroupRulesOperator=@{Include=0;Exclude=1}
$vDNUserGroupRulesUsers=@{DisplayName=$null;DomainName=$null;Email=$null;SID=$null;Type=$null}
$vDNUserGroupRulesGroups=@{DisplayName=$null;DomainName=$null;SID=$null;Type=$null}
$vDNUserGroupRules=@{Users=$vDNUserGroupRulesUsers;Groups=$vDNUserGroupRulesGroups;Operator=$vDNUserGroupRulesOperator.Include}

# On my 5 user test environment I am using a self signed certificate and the following
# function gets around PowerShell not working with those.
# It is not my code and was borrowed / recycled from:
# http://stackoverflow.com/questions/11696944/powershell-v3-invoke-webrequest-https-error
function New-TrustAllCertsPolicy {
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
<# 
.SYNOPSIS
    Connect to a DatAnywhere Server
.DESCRIPTION
    Connect to a DatAnywhere Server.

    Required Parameters are:
        -URL                 [string]
        -LoginID             [string]
        -Password            [string]

    Optional Parameters are:
        None
.NOTES
    File Name  : SF-DatAnywhereFunctions.ps1 
    Author     : Stephen Fearns - http://uk.linkedin.com/in/stephenfearns
.LINK
    More information on this can be found in the Varonis DatAnywhere API manual
    http://www.varonis.com
.EXAMPLE
    Connect-vDNServer -URL https://192.168.36.50 -LoginID 'sfearns' -Password Password1234
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory=$true)] [string]$URL,
          [Parameter(Mandatory=$true)] [string]$LoginID,
		  [Parameter(Mandatory=$true)] [string]$Password)
    $Body = '[{"Key":"client_type","Value":"1"},{"Key":"client_version","Value":'+$Global:CurrentDNServer.ClientVersion+'}]'
    $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/auth/V2/Begin?userName=$LoginID&clientName=WinClient&Root=1") -Method POST -Body $Body -ContentType 'application/json' -SessionVariable $DNSession
    if ($Part1.ReturnCode -eq 0){
        $Body = @{InputParam=$Password;RootID=0} | ConvertTo-Json -Compress -Depth 10
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
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
        Write-Host "ERROR: Unable to connect (/Begin)" -ForegroundColor Red -BackgroundColor Black
    }
}

function Disconnect-vDNServer {
<# 
.SYNOPSIS
    Disconnect from a previously connected server
.DESCRIPTION
    Disconnect from a previously connected server


    Required Parameters are:
        None

    Optional Parameters are:
        -DNServiceUser       [string] Defaults to $Global:CurrentDNServer.DNServiceUser
        -DNServicePassword   [string] Defaults to $Global:CurrentDNServer.DNServicePassword
        -URL                 [string] Defaults to the last connected server
.NOTES
    File Name  : SF-DatAnywhereFunctions.ps1 
    Author     : Stephen Fearns - http://uk.linkedin.com/in/stephenfearns
.LINK
    More information on this can be found in the Varonis DatAnywhere API manual
    http://www.varonis.com
.EXAMPLE
    Disconnect-vDNServer
    Disconnect-vDNServer -URL http://192.168.1.50
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if ($Global:CurrentDNServer.Connected -eq $True) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/auth/Logout") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -eq 0){
            $Global:CurrentDNServer.Connected=$False
            Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
        } else {
            Write-Host "ERROR: Unable to disconnect (/Logout)" -ForegroundColor Red -BackgroundColor Black
            Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
        }
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
}

function Get-vDNIdentities {
<# 
.SYNOPSIS
    Returns DatAnywhere identities which can be users, groups or AD attributes.
.DESCRIPTION
    Returns DatAnywhere identities which can be users, groups or AD attributes.

    Required Parameters are:
        -SearchString        [string]

    Optional Parameters are:
        -DNServiceUser       [string] Defaults to $Global:CurrentDNServer.DNServiceUser
        -DNServicePassword   [string] Defaults to $Global:CurrentDNServer.DNServicePassword
        -NumOfObjects        [int]    Defaults to 100 objects returned
        -QueryFilter         [int]    Defaults to 1 (User)
        -URL                 [string] Defaults to the last connected server
.NOTES
    File Name  : SF-DatAnywhereFunctions.ps1 
    Author     : Stephen Fearns - http://uk.linkedin.com/in/stephenfearns
.LINK
    More information on this can be found in the Varonis DatAnywhere API manual
    http://www.varonis.com
.EXAMPLE
    Get-vDNIdentities -SearchString sfearns
#>
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
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Get-vDNCredentials {
<# 
.SYNOPSIS
    Returns the current users credentials.
.DESCRIPTION
    Returns the current users credentials.

    Required Parameters are:
        None

    Optional Parameters are:
        -URL                 [string] Defaults to the last connected server
.NOTES
    File Name  : SF-DatAnywhereFunctions.ps1 
    Author     : Stephen Fearns - http://uk.linkedin.com/in/stephenfearns
.LINK
    More information on this can be found in the Varonis DatAnywhere API manual
    http://www.varonis.com
.EXAMPLE
    Get-vDNIdentities -SearchString sfearns
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/admin/Credentials/All") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to get Credentials (/Credentials/All)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
        $Body = @{"User"=$DNServiceUser;"Password"=$DNServicePassword;"Data"=@{"Name"=$RootName;"Path"=$RootPath;"SyncManagerWid"=1;"ItemType"=1;"IncludeNested"=$IncludeNested;"FilerID"=0;"EnforceSharePermissions"=$true;"PreviewOnly"=$false}} | ConvertTo-Json -Compress -Depth 10
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/admin/Root/Add?UploadEnabled=$UploadEnabled&DownloadEnabled=$DownloadEnabled&NestedUpload=$NestedUpload&NestedDownload=$NestedDownload") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -eq 0){
            $Result=$true
        } else {
            Write-Host "ERROR: Unable to make root (/Root/Add)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
        $Body = @{"User"=$DNServiceUser;"Password"=$DNServicePassword;"Data"=@{"Name"=$RootName;"Path"=$RootPath;"ID"=$ID;"SyncManagerWid"=1;"ItemType"=1;"IncludeNested"=$IncludeNested;"FilerID"=0;"EnforceSharePermissions"=$true;"PreviewOnly"=$false}} | ConvertTo-Json -Compress -Depth 10
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/admin/Root/Update?UploadEnabled=$UploadEnabled&DownloadEnabled=$DownloadEnabled&NestedUpload=$NestedUpload&NestedDownload=$NestedDownload") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -eq 0){
            $Result=$true
        } else {
            Write-Host "ERROR: Unable to make root (/Root/Update)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Result
}

function Get-vDNRootAllFolders {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/admin/Root/All?BaseUNCPath=") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to list roots (/Root/All)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Get-vDNRootFolders {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$DNServiceUser=$Global:CurrentDNServer.DNServiceUser,
          [Parameter(Mandatory=$false)] [string]$DNServicePassword=$Global:CurrentDNServer.DNServicePassword,
          [Parameter(Mandatory=$true)]  [string]$RootPath,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Body = @{"User"=$DNServiceUser;"Password"=$DNServicePassword} | ConvertTo-Json -Compress -Depth 10
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/admin/FolderItem/All?FolderPath=$RootPath&SyncmanagerID=1&RootID=0") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to list roots (/FolderItem/All)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
        $Body = @{"PrivateWorkspaceData"=@{"Name"=$WorkspaceName;"IsIncludeHomeFolders"=$IncludeHomeFolders}} | ConvertTo-Json -Compress -Depth 10
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/Workspace/CreatePrivate") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -eq 0){
            $Result=$true
        } else {
            Write-Host "ERROR: Unable to make private workspace (/Workspace/CreatePrivate)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
          [Parameter(Mandatory=$false)] [array]$CustomOwner=$null,
          [Parameter(Mandatory=$false)] [boolean]$IsForced=$true,
          [Parameter(Mandatory=$false)] [boolean]$IsEveryone=$false,
          [Parameter(Mandatory=$false)] [boolean]$IsIncludeHomeFolders=$false,
          [Parameter(Mandatory=$false)] [int]$RecipientMatching=$vDNRecipientMatching.AND,
          [Parameter(Mandatory=$false)] [array]$AdPropertyRules=$null,
          [Parameter(Mandatory=$true)]  [array]$UserGroupRules)
    $Result = $false
    # Validate some of the parameters
    if (!$vDNRecipientMatching.ContainsValue($RecipientMatching)) {
        Write-Host "ERROR: Parameter -RecipientMatching is invalid" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
        return $Result
    }
    if ($Global:CurrentDNServer.Connected -eq $True) {
        $Body = '{"PublicWorkspaceData":{"PublicWorkspaceRules":{"AdPropertyRules":'
        if ($AdPropertyRules) {
            $Body += ($UserGroupRules | ConvertTo-Json -Depth 10) + ',"UserGroupRules":'
        } else {
            $Body += '[],"UserGroupRules":'
        }
        if ($UserGroupRules.Count -eq 1) {
            $Body += '[' + ($UserGroupRules | ConvertTo-Json -Depth 10 -Compress) + ']},"Name":'
        } else {
            $Body += ($UserGroupRules | ConvertTo-Json -Depth 10 -Compress) + '},"Name":'
        }
        $Body += ($Name | ConvertTo-Json -Depth 10 -Compress) + ',"Description":' + ($Description | ConvertTo-Json -Depth 10 -Compress) + ',"CustomeOwner":'
        if ($CustomOwner.Count -eq 0) {
            $Body += 'null,"RecipientMatching":'
        } else {
            $Body += ($CustomOwner | ConvertTo-Json -Depth 10 -Compress) + ',"RecipientMatching":'
        }
        $Body += ($RecipientMatching | ConvertTo-Json -Depth 10 -Compress) + ',"IsForced":' + ($IsForced | ConvertTo-Json -Depth 10 -Compress) + ',"IsEveryone":' + ($IsEveryone | ConvertTo-Json -Depth 10 -Compress) + ',"IsIncludeHomeFolders":' + ($IsIncludeHomeFolders | ConvertTo-Json -Depth 10 -Compress) + '}}'

        # Corrections needed for some items
        $Body = $Body.Replace('"Groups":""','"Groups":[]').Replace('"Groups":null','"Groups":[]').Replace('"Users":""','"Users":[]').Replace('"Users":null','"Users":[]')
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/Workspace/CreatePublic") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -eq 0){
            $Result=$true
        } else {
            Write-Host "ERROR: Unable to make private workspace (/Workspace/CreatePublic)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
        $Body = @{"WorkspaceItemsList"=$WorkspaceItemsList;"IncludeOwnerData"=$IncludeOwnerData} | ConvertTo-Json -Compress -Depth 10
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/V3/Workspace/ID=$WorkspaceID") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to list workspaces (/Workspace/ID)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
          [Parameter(Mandatory=$false)] [boolean]$UnacceptedReceivedPublicWorkspace=$false,
          [Parameter(Mandatory=$false)] [boolean]$AllOwnedPublicWorkspace=$false,
          [Parameter(Mandatory=$false)] [boolean]$MyOwnedPublicWorkspace=$true,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Body = @{"PrivateWorkspace"=$PrivateWorkspace;"AcceptedReceivedPublicWorkspace"=$AcceptedReceivedPublicWorkspace;"MyOwnedPublicWorkspace"=$MyOwnedPublicWorkspace;"UnacceptedReceivedPublicWorkspace"=$UnacceptedReceivedPublicWorkspace;"AllOwnedPublicWorkspace"=$AllOwnedPublicWorkspace} | ConvertTo-Json -Compress -Depth 10
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/V3/Workspace/All") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to list workspaces (/Workspace/All)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
        $Body = @{"PrivateWorkspace"=$true;"AcceptedReceivedPublicWorkspace"=$true;"MyOwnedPublicWorkspace"=$false} | ConvertTo-Json -Compress -Depth 10
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/V3/Workspace/All") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to list workspaces (/Workspace/All)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function New-vDNWorkspaceItem {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$true)]  [int]$WorkspaceID,
          [Parameter(Mandatory=$true)]  [int]$RootID,
          [Parameter(Mandatory=$false)] [int]$RootType=$vDNFolderInfoType.Folder,
          [Parameter(Mandatory=$true)]  [string]$RootName,
          [Parameter(Mandatory=$false)] [boolean]$Nested=$true,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    # Validate some of the parameters
    if (!$vDNFolderInfoType.ContainsValue($RootType)) {
        Write-Host "ERROR: Parameter -RootType is invalid" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
        return $Result
    }
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Body = @{"WorkspaceID"=$WorkspaceID;"WorkspaceItems"=@{"Name"=$RootName;"Path"="";"RootID"=$RootID;"Type"=$RootType;"IsNested"=$Nested}} | ConvertTo-Json -Compress -Depth 10
        $Body = $Body.Replace('"WorkspaceItems":{','"WorkspaceItems":[{').Replace('},"WorkspaceID":','}],"WorkspaceID":')
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/Workspace/AddItems") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to add item to workspace (/Workspace/AddItems)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Remove-vDNWorkspaceFolder {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$true)]  [string]$RootID,
          [Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL)
    if ($Global:CurrentDNServer.Connected -eq $True) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/admin/Root/Remove?RootID=$RootID") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to remove workspace (/Root/Remove)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
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
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Get-vDNChildItem {
<# 
.SYNOPSIS
    Get a list of items contained within a specific folder
.DESCRIPTION
    Get a list of items contained within a specific folder

    Required Parameters are:
        -FolderPath  [string]
        -RootID      [int]

    Optional Parameters are:
        -URL         [string]
.NOTES
    File Name  : SF-DatAnywhereFunctions.ps1 
    Author     : Stephen Fearns - http://uk.linkedin.com/in/stephenfearns
.LINK
    More information on this can be found in the Varonis DatAnywhere API manual
    http://www.varonis.com
.EXAMPLE
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL,
          [Parameter(Mandatory=$false)] [string]$FolderPath='',
          [Parameter(Mandatory=$true)]  [int]$RootID)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/Folder/Items?FolderPath=$folderPath&Root=$RootID") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to get Resource Info (/Folder/Items)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function Remove-vDNChildItem {
<# 
.SYNOPSIS
    Remove an item contained within a specific folder
.DESCRIPTION
    Remove an item contained within a specific folder

    Required Parameters are:
        -Path        [string]
        -Name        [string]
        -RootID      [int]
        -Revision    [long]
        -Type        [int]

    Optional Parameters are:
        -URL         [string]
.NOTES
    File Name  : SF-DatAnywhereFunctions.ps1 
    Author     : Stephen Fearns - http://uk.linkedin.com/in/stephenfearns
.LINK
    More information on this can be found in the Varonis DatAnywhere API manual
    http://www.varonis.com
.EXAMPLE
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL,
          [Parameter(Mandatory=$true)]  [string]$Path,
          [Parameter(Mandatory=$true)]  [string]$Name,
          [Parameter(Mandatory=$true)]  [long]$Revision,
          [Parameter(Mandatory=$true)]  [int]$Type,
          [Parameter(Mandatory=$true)]  [int]$RootID)
    if (!$vDNFolderInfoType.ContainsValue($Type)) {
        Write-Host "ERROR: Invalid Type (/Item/Delete)" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
        Return $null
    }
    if (($Path -eq '\') -or ($Path -eq '.')) {
        $FolderPath=''+$Name
    } else {
        $FolderPath=($Path+'\'+$Name).Replace('\\','\')
    }
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/V2/Item/Delete?rootID=$RootID&type=$Type&revision=$Revision&path=$FolderPath") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to get Resource Info (/Item/Delete)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function New-vDNFolderItem {
<# 
.SYNOPSIS
    Create a new folder within the RootID
.DESCRIPTION
    Create a new folder within the RootID

    Required Parameters are:
        -Path        [string]
        -RootID      [int]

    Optional Parameters are:
        -URL         [string]
.NOTES
    File Name  : SF-DatAnywhereFunctions.ps1 
    Author     : Stephen Fearns - http://uk.linkedin.com/in/stephenfearns
.LINK
    More information on this can be found in the Varonis DatAnywhere API manual
    http://www.varonis.com
.EXAMPLE
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL,
          [Parameter(Mandatory=$true)]  [string]$Path,
          [Parameter(Mandatory=$true)]  [int]$RootID)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/client/Folder/Create?FolderPath=$Path&Root=$RootID") -Method POST -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to crrreate folder (/Folder/Create)" -ForegroundColor Red -BackgroundColor Black
        }
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}

function New-vDNChildItem {
<# 
.SYNOPSIS
    Upload a file to a RootID & Path
.DESCRIPTION
    Upload a file to a RootID & Path

    Required Parameters are:
        -SourcePath           [string]
        -Path                 [string]
        -FileName             [string]
        -RootID               [int]

    Optional Parameters are:
        -URL                  [string]
        -DiffFileSize         [long]      Default is $null
        -FileSize             [long]      Default is -1 (Unknown Length)
        -Revision             [long]      Default is 0  (New File)
        -TransferCompleteFile [int]       Default is 1
.NOTES
    File Name  : SF-DatAnywhereFunctions.ps1 
    Author     : Stephen Fearns - http://uk.linkedin.com/in/stephenfearns
.LINK
    More information on this can be found in the Varonis DatAnywhere API manual
    http://www.varonis.com
.EXAMPLE
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false)] [string]$URL=$Global:CurrentDNServer.URL,
          [Parameter(Mandatory=$true)]  [string]$SourcePath,
          [Parameter(Mandatory=$true)]  [string]$TargetPath,
          [Parameter(Mandatory=$true)]  [string]$FileName,
          [Parameter(Mandatory=$false)] [long]$DiffFileSize=$null,
          [Parameter(Mandatory=$false)] [long]$FileSize=-1,
          [Parameter(Mandatory=$false)] [long]$Revision=0,
          [Parameter(Mandatory=$false)] [int]$TransferCompleteFile=1,
          [Parameter(Mandatory=$true)]  [int]$RootID)
    if (($Global:CurrentDNServer.Connected -eq $True)-and($URL -ne $null)) {
        $CreateTime = (Get-ChildItem $SourcePath).CreationTime.Ticks
        $Body = @{"Revision"=$Revision;"FilePath"=$TargetPath;"FileName"=$FileName;"FileSize"=$FileSize;"CreateTime"=$CreateTime}
        if ($DiffFileSize){$Body+=@{"DiffFileSize"=$DiffFileSize}}
        $Body = ($Body | ConvertTo-Json -Compress -Depth 10)
        $Part1 = Invoke-RestMethod -Uri ($URL+"/rest/transfer/V2/Upload/Query?root=$RootID&type=$TransferCompleteFile") -Method POST -Body $Body -ContentType 'application/json' -Headers @{"AuthorizationToken"=$Global:CurrentDNServer.AuthToken}
        if ($Part1.ReturnCode -ne 0){
            Write-Host "ERROR: Unable to start the upload (/Upload/Query)" -ForegroundColor Red -BackgroundColor Black
            Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1}
        } else {
            Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value @{"Part1"=$Part1;"Part2"=$Part2;"Part3"=$Part3}
        }
    } else {
        Write-Host "ERROR: Not connected to a DN Server" -ForegroundColor Red -BackgroundColor Black
        Add-Member -InputObject $Global:CurrentDNServer -Force -MemberType NoteProperty -Name VaronisRESTReply -Value $null
    }
    Return $Part1
}




