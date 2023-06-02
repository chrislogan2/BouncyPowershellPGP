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
    "ModuleVersion" = "0.0.4"
    "PowerShellVersion" = 5.1
    "Description" = 'A Basic Wrapper to Decrypt PGP Files / Folders with BouncyCastle' 
} 
New-ModuleManifest @Params

Test-ModuleManifest .\BouncyPowershellPGP.psd1