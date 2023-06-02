# BouncyPowershellPGP
My Simple PGP Powershell Module/Wrapper of BouncyCastle PGP.  
I made it because I was having issues with https://github.com/EvotecIT/PSPGP in my use case.  

It's not better, but it only depends on BouncyCastle's .net binding. 

## Examples
`Decrypt-EncryptedPGPFolder` - Attempts decryption of all files in a folder using a specified secret key & passphrase.  

*TODO: maybe add a regex filter functionality / recursive option?*

```pwsh
#I tend to store secure strings in secret vaults, and use Get-Secret, a cmdlet from Microsoft's https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.secretmanagement module.


$params = @{
    SecretKeyFilePath = "C:\folder\pgpkey.asc"
    EncryptedFolderName = "C:\encryptedfolder\"
    SecurePassphrase = [System.Security.SecureString] $PGPPassphraseSecureString
    OutputFolderPath = "C:\DecryptedFolder"
    AppendDefaultSuffix = $true
    DefaultSuffix = ".CSV"
}
Decrypt-EncryptedPGPFolder @params
```
`ConvertFrom-EncryptedPGPFile` - Attempts decryption of a specified file using a secret key & passphrase.

```pwsh
$params = @{
    SecretKeyFilePath = "C:\folder\pgpkey.asc"
    EncryptedFileName = "C:\encryptedfolder\encryptedfile.xyz"
    SecurePassphrase = [System.Security.SecureString] $PGPPassphraseSecureString
    OutputFolderPath = "C:\OutputFolder"
    AppendDefaultSuffix = $true
    DefaultSuffix = ".CSV"
    AppendDate = $true
}

ConvertFrom-EncryptedPGPFile @params
```
## Install / Using
It will probably only work on Windows for now because I have no reason to test it on Linux/Mac.  
Install a specific version:
 * `Install-Module BouncyPowerShellPGP -Version 0.0.3`  

Install the latest published version:
 * `Install-Module BouncyPowerShellPGP` 
## Generating the Module
The easiest way is to run `GeneratePGPModuleDefinition.ps1`, it populates the metadata etc.
### Publishing to PowerShellGallery, Common Issues
The one-liner to publish is as follows, it will likely only work if you're me (Unless you're forking to a new module name)
Navigate to the root of the repository, then run the following:
```pwsh
 Publish-Module -Name ..\BouncyPowershellPGP -NuGetApiKey "APIKey Goes here"
```

If you get an obscure nuget error talking about **"The target framework 'netcoreapp2.0' is out of support and will not receive security updatesin the future. (etc)"**, the following snippet will download a workable version of `nuget` and once you start a new PowerShell session, you should be able to publish.

```pwsh
Invoke-WebRequest -Uri https://dist.nuget.org/win-x86-commandline/latest/nuget.exe -OutFile "$env:LOCALAPPDATA\Microsoft\Windows\PowerShell\PowerShellGet\NuGet.exe"
```
## References
https://www.bouncycastle.org/csharp/
