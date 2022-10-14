
# Bad Password in gMSA Account

We discovered on 10/10/2022 that a _Bad Password_ was preventing the Init GMSA script from renewing KRB tickets.

This is the LDIF that was pulled for account ((REDACTED))$@((REDACTED)):

```ldif
dn: CN=((REDACTED)),OU=((REDACTED)),DC=((REDACTED)),DC=((REDACTED)),DC=((REDACTED))
msDS-ManagedPassword:: AQAAACQCAAAQABIBFAIcAoZd8Y2UCqAK2NJItzNHqqnQ+SEttwxiRMsyOPqDCqepYofTybkNZ1vNvb84wa6AW17zZQEphKkzfqS4NNUCyP3jwi4qpYuZMH1xdGUxQgtqnI7NhOvvsfPRMk89jtSN3yX+XeVePtTgSm2eM2XrUcEwHvj9w5jo7tLgG83DipL31SHkAS+CQDwg2KDlx51b6dBjX9EslHn+fgrFGkEspx49ZgHhPqW810sX++aXDP4bRRYvvRCi8SELfN0W7svF0G3XH59xnLb9MxIlgJAJtoNTL8R6JEYn4IekpZCifLW4lsoQ5QoAEY+0yhv2vVKwurCfTvWxBqtYwHs5+V8GZJIAALLRYyaYKk06d5+ZwJOgAPZKtdBwYkic60YGvGOlasHuPhhn9FcHNH7moc2C0NEXfWJG+taFeFr5AVNnHJLs4y2iHd5iEkPUNCrlyEPxc0eJEr2WdnvBuZk0i+oQKGDngm9KxJOoEd44HG0LLWdmEcKBJqaRoFZONxi1PS3W/fnSlpjuz7NV8AHD8Ev6e2Wocpn8mAznVU0xvT9fmtfZgHFSTgxHIT+Ldfhz9WxDX3mEcS0rK5UVT56WmrrX3yLaJS5DWpjPt3AnX/wPEZdExV7R/6FtxVJMAr1PG2RCrH+chb7u933pzHnXrR6R66MwZ1YzLPNO3roZOE/9niDJyDUAAKEdDTWWDwAAob88gpUPAAA=

```

## Analysis

It turns out this password had the Unicode character value of `0x0A` within.
In our first implementation of the `Initialize-KrbTicketForGmsa.ps1` script we were simply
using CLI tooling to initialize the Kerberos ticket (`kinit`) and passing the password
to it by streaming through its STDIN.  This of course bombed when it encountered the
Unicode value of 10, thinking it was the carriage return and ending the password input.

To address this, we needed to create a KeyTab file with the credential and then invoke
`kinit` with the KeyTab file instead.  But generating the KeyTab file with the conventional
tools found on Linux (`ktadmin`) would yield the same problem, as inputing a password is
still accomplished via the STDIN stream.

So instead, we use the Kerberos.NET library which has native support for reading and writing
KeyTab files, and we can pass the password value safely through by sending it to the class's
necessary properties and methods needed to construct the KeyTab file and persist it to disk.

## "Show Your Work"

```pwsh
## The following code snippet ***ASSUMES*** that $mp variable
## already contains the ManagedPassword instance resolved within
## the Initialize-KrbTicketForGmsa.ps1 script.

Add-Type -Path ./Kerberos.NET.dll

$fs = [System.IO.FileStream]::new('/etc/krb5.keytab', [System.IO.FileMode]::Open)
$kt = [Kerberos.NET.Crypto.KeyTable]::new($fs)
$fs.Dispose()
$kt.Entries
$kt.Entries.Count
$kt.Entries.Principal.FullyQualifiedName
$kt.Entries[0].EncryptionType
$kt.Entries[0].Key


$ntprincipal = [Kerberos.NET.Entities.PrincipalNameType]::NT_PRINCIPAL
$names = [System.Collections.Generic.List[string]]::new()
$names.Add('gmsa-acct-name$')
$pn = [Kerberos.NET.Entities.PrincipalName]::new($ntprincipal, 'EXAMPLE.COM', $names)

$kk = [Kerberos.NET.Crypto.KerberosKey]::new(
    $mp.CurrentPassword, ## string password,
    $pn,                 ## PrincipalName principalName = null,
    $null,               ## string host = null,
    $null,               ## string salt = null,
    $null,               ## byte[] saltBytes = null,
    [Kerberos.NET.Crypto.EncryptionType]::AES256_CTS_HMAC_SHA1_96 ## EncryptionType etype = 0,
                         ## SaltType saltType = SaltType.ActiveDirectoryService,
                         ## byte[] iterationParams = null,
                         ## int? kvno = null
)
$kk = [Kerberos.NET.Crypto.KerberosKey]::new($mp.CurrentPassword, $pn, $null, $null, $null, [Kerberos.NET.Crypto.EncryptionType]::AES256_CTS_HMAC_SHA1_96)


$kt = [Kerberos.NET.Crypto.KeyTable]::new($kk)
$kt.Entries
$kt.Entries[0]

$fs = [System.IO.File]::OpenWrite("$PWD/kt2.keytab")
$bw = [System.IO.BinaryWriter]::new($fs)
$kt.Write($bw)
$bw.Close()
$bw.Dispose()
$fs.Close()
$fs.Dispose()

```
