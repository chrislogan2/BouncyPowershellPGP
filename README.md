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
## References
https://www.bouncycastle.org/csharp/
