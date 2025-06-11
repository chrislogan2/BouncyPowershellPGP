$modname = "BouncyPowershellPGP"
$Params = @{ 
    "Path" 				= ".\$modname.psd1"
    "Author" 			= 'Christopher Logan' 
    "CompanyName" 			= 'OSCO IT' 
    "RootModule" 			= "$modname.psm1" 
    "CompatiblePSEditions" 		= @('Desktop','Core') 
    "FunctionsToExport" 		= @('ConvertFrom-EncryptedPGPFile','Decrypt-EncryptedPGPFolder') 
    "CmdletsToExport" 		= @() 
    "VariablesToExport" 		= '' 
    "AliasesToExport" 		= @() 
    "RequiredAssemblies" = @(".\lib\net6.0\BouncyCastle.Cryptography.dll")
    "ModuleVersion" = "0.0.5"
    "PowerShellVersion" = 5.1
    "Description" = 'A Basic Wrapper to Decrypt PGP Files / Folders with BouncyCastle' 
    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    "PrivateData" = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @("gpg", "pgp","encrypt", "encryption", "decryption", "decrypt", "windows")

            # A URL to the license for this module.
            # LicenseUri = ''

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/chrislogan2/BouncyPowershellPGP'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            ReleaseNotes = 'Add output filename to decryption cmdlet. Make metadata better. '

            # Prerelease string of this module
            # Prerelease = ''

            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            RequireLicenseAcceptance = $false

            # External dependent modules of this module
            # ExternalModuleDependencies = @()
    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    # HelpInfoURI = ''

} 
New-ModuleManifest @Params

Test-ModuleManifest .\BouncyPowershellPGP.psd1
