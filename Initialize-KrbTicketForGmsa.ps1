#!/usr/bin/pwsh -command

<#
.PARAM LdapHost
Specifies the LDAP server (e.g. AD Controller) to query against

.PARAM LdapDnsSrvName
Specifies a SRV-type DNS record NAME which will return one or more LDAP servers to query against.
For MSAD environments, this record will typically look something like:
`_kerberos._tcp.dc._msdcs.YOUR_DOMAIN_NAME`

.PARAM UseKeyTab
Enables the use of an intermediate keytab file to capture gMSA credential instead of piping
the credential directly to kinit.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingPlainTextForPassword',
    'ManagedPasswordCS',
    Justification = 'Path to CS file, does not contain a secret value'
)]
param(
    [Parameter(Mandatory)]
    [string]$Username,
    [Parameter(Mandatory)]
    [string]$LdapSearchBase="DC=((REDACTED)),DC=((REDACTED))",

    [Parameter(ParameterSetName='LdapHost')]
    [string]$LdapHost,

    [Parameter(ParameterSetName='LdapDnsSrvName')]
    [string]$LdapDnsSrvName,

    [switch]$UseKeyTab,

    ## Path to the C# type definition for ManagedPassword
    ## used to parse the ManagedPassword BLOB structure
    [string]$ManagedPasswordCS="$PSScriptRoot/lib/ManagedPassword.cs",
    ## Path to the LdifHelper assembly for parsing LDIF
    ## structured responses from the AD/LDAP server
    [string]$LdifHelperAsm="$PSScriptRoot/lib/LdifHelper.dll",
    ## Path to the Kerberos.NET assembly for managing
    ## KeyTab files needed to pass credentials to kinit
    [string]$KerberosAsm="$PSScriptRoot/lib/Kerberos.NET.dll",

    ## The root directory where temporary files will be
    ## generated; when using a KeyTab this path *MUST*
    ## be accessible by the gMSA user account
    [string]$TempRoot='/tmp',
    ## If true, will *not* remove the temporary LDIF and
    ## raw password files, which is the default behavior
    [switch]$KeepTempFiles,
    ## For debugging and troubleshotting, dump the
    ## raw password to a temp file -- you ALSO MUST
    ## specify $KeepTempFiles or it will be deleted
    [switch]$DumpRawPassword
)

$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

if ($LdapDnsSrvName) {
    ## We query DNS to resolve the LDAP Hosts (Domain Controller(s)) for the current domain
    $srv = & /usr/bin/dig $LdapDnsSrvName -t srv +short
    if (!$srv) {
        Write-Error "Failed to resolve LDAP Host by SRV records"
        return -1
    }
    $kdc = ($srv | Select-Object -First 1) -split ' ' | Select-Object -Last 1
}
else {
    $kdc = $LdapHost
}

if (!$kdc) {
    Write-Error "Could not resolve KDC host"
    return -1
}
Write-Information "Resolved KDC host as [$kdc]"

## We need to populate some intermediate temp files
## as we query for and resolve the gMSA password and
## then pass it along to the kinit for ticket renewal
$tmp = "$TempRoot/$([Guid]::NewGuid())-$Username"
$tmpLdif = "$($tmp).ldif"  ## LDAP query result
$tmpKTab = "$($tmp).ktab"  ## Kerberos keytab
$tmpPass = "$($tmp).raw"   ## Raw, decoded password (Unicode)


try {
    ## Search for and dump the ManagedPassword BLOB from AD into a file
    & /usr/bin/ldapsearch -Y GSSAPI -H "ldap://$kdc" -b $LdapSearchBase "(sAMAccountName=$Username)" `
        -o ldif-wrap=no -L -L -L msDS-ManagedPassword > $tmpLdif

    ## Load up the LDIF parser and parse the query results
    Add-Type -Path  $LdifHelperAsm
    $sreader = [System.IO.StreamReader]::new($tmpLdif)
    $ldifCR = [LdifHelper.LdifReader]::Parse($sreader)
    $ldifCRList = [System.Collections.Generic.List[LdifHelper.IChangeRecord]]::new($ldifCR)
    $ldifCR.Dispose()
    $sreader.Dispose()
    if (!$ldifCRList -or !$ldifCRList.Count) {
        Write-Error "Failed to parse or find any LDIF search results"
        return -1
    }
    $mpBytes = $ldifCRList[0].AttributeValues
    if (!$mpBytes) {
        Write-Error "Failed to resolve Managed Password BLOB from LDIF search results"
        return -1
    }

    ## Load up the ManagedPassword structure definition and parse MP BLOB
    $mpcs = Get-Content -Raw $ManagedPasswordCS
    Add-Type -Language CSharp -TypeDefinition $mpcs
    $mp = [GmsaSync.ManagedPassword]::new($mpBytes)
    if (!$mp -or !($mp.CurrentPassword)) {
        Write-Error "Failed to parse Manage Password BLOB from LDIF content"
        return -1
    }

    if ($DumpRawPassword) {
        Set-Content -Path $tmpPass -Value $mp.CurrentPassword
    }

    if ($UseKeyTab) {
        ## Load up Kerberos.NET so we can create a KeyTab to store the credential
        ## temporarily for usage -- we used to pass the password directly to kinit
        ## via STDIN but that ran into an issue which is described in BAD_PASSWORD.md
        Add-Type -Path $KerberosAsm
        $domainName = (& /usr/bin/hostname --domain).ToUpper()
        $namesList = [System.Collections.Generic.List[string]]::new()
        $namesList.Add($Username)

        $princName = [Kerberos.NET.Entities.PrincipalName]::new(
            [Kerberos.NET.Entities.PrincipalNameType]::NT_PRINCIPAL,
            $domainname,
            $namesList)
        
        $krbKey = [Kerberos.NET.Crypto.KerberosKey]::new(
            $mp.CurrentPassword, ## string password,
            $princName,          ## PrincipalName principalName = null,
            $null,               ## string host = null,
            $null,               ## string salt = null,
            $null,               ## byte[] saltBytes = null,
            [Kerberos.NET.Crypto.EncryptionType]::AES256_CTS_HMAC_SHA1_96 ## EncryptionType etype = 0,
                                    ## SaltType saltType = SaltType.ActiveDirectoryService,
                                    ## byte[] iterationParams = null,
                                    ## int? kvno = null
        )
        $keyTab = [Kerberos.NET.Crypto.KeyTable]::new($krbKey)
        $ktStream = [System.IO.File]::OpenWrite($tmpKTab)
        $ktWriter = [System.IO.BinaryWriter]::new($ktStream)
        $keyTab.Write($ktWriter)
        $ktWriter.Dispose()
        $ktStream.Dispose()

        Write-Host "Generated temporary keytab for kinit"
        & /usr/bin/sudo -u $Username /usr/bin/kinit -k -t $tmpKTab $Username
    }
    else {
        ## This was the previous approach before we ran into BAD_PASSWORD problem
        Write-Host "Piping password to kinit STDIN"
        $mp.CurrentPassword | & /usr/bin/sudo -u $Username /usr/bin/kinit
    }

    return 0
}
finally {
    if (-not $KeepTempFiles) {
        Write-Host "Removing temporary work files"
        ## Be sure to clean up the temporary LDIF and
        ## raw password files regardless of the outcome
        if (Test-Path $tmpLdif) { /usr/bin/rm $tmpLdif }
        if (Test-Path $tmpKTab) { /usr/bin/rm $tmpKTab }
        if (Test-Path $tmpPass) { /usr/bin/rm $tmpPass }
    }
    else {
        Write-Host "Skipping removal of temporary work files"
    }
}
