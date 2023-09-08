#add-type -LiteralPath "E:\Scripts\Modules\net6.0\BouncyCastle.Cryptography.dll"
# adapted (stolen) from this https://stackoverflow.com/questions/6987699/pgp-encryption-and-decryption-using-bouncycastle-c-sharp
# OSCO IT 2022
# Major change from above code is that it's been ported to PowerShell with minor changes. 
# No significant wrapping has been done.
# include options to decrypt single file, and attempt all files in folder. might add regex as an option.
function Find-SecretKey {
    param([Org.BouncyCastle.Bcpg.OpenPgp.PgpSecretKeyRingBundle]$pgpSec, [long]$keyID, [string] $pass)
    [Org.BouncyCastle.Bcpg.OpenPgp.PgpSecretKey]$pgpSecretKey = $pgpSec.GetSecretKey($keyID)
    if ($null -eq $pgpSecretKey ) {
        return $null
    }
    return $pgpSecretKey.ExtractPrivateKey($pass);

}
function ConvertFrom-EncryptedPGPFile {
    [CmdLetbinding(DefaultParameterSetName='SecureParamSet')]
    <#
     In the function's code, you can either test for whether $A and/or $B are null, or check $PSBoundParameters.ContainsKey('A'), or check $PSCmdlet.ParameterSetName to see whether it
    is set to 'By_A' or 'By_B'
    #>
    param( [Parameter(Mandatory=$true,ParameterSetName='PlainParamSet')][Parameter(Mandatory=$true,ParameterSetName='SecureParamSet')][System.String]$SecretKeyFilePath, `
    [Parameter(Mandatory=$true,ParameterSetName='PlainParamSet')][Parameter(Mandatory=$true,ParameterSetName='SecureParamSet')][System.String]$EncryptedFileName, `
    [Parameter(Mandatory=$true,ParameterSetName='PlainParamSet')][Parameter(Mandatory=$true,ParameterSetName='SecureParamSet')][System.String]$OutputFolderPath, `
    [Parameter(Mandatory=$false,ParameterSetName='PlainParamSet')][Parameter(Mandatory=$false,ParameterSetName='SecureParamSet')][switch]$AppendDate = $false, `
    [Parameter(Mandatory=$false,ParameterSetName='PlainParamSet')][Parameter(Mandatory=$false,ParameterSetName='SecureParamSet')][switch]$AppendDefaultSuffix = $false, `
    [Parameter(Mandatory=$false,ParameterSetName='PlainParamSet')][Parameter(Mandatory=$false,ParameterSetName='SecureParamSet')][System.String]$DefaultSuffix = ".csv", `
    [Parameter(Mandatory=$false,ParameterSetName='PlainParamSet')][Parameter(Mandatory=$false,ParameterSetName='SecureParamSet')][System.String]$DefaultFilePrefix = "File-Decrypted-", `
    [Parameter(Mandatory=$true,ParameterSetName='PlainParamSet')][System.String]$PlainTextPassphrase, `
    [Parameter(Mandatory=$true,ParameterSetName='SecureParamSet')][System.Security.SecureString]$SecurePassphrase)

    if ($PSCmdlet.ParameterSetName -eq "SecureParamSet") {
        $gpgpassword = ([System.Management.Automation.PSCredential]::new("dummyuser",$SecurePassphrase)).GetNetworkCredential().Password
    }else {
        $gpgpassword = $PlainTextPassphrase
    }
    $keyin = [system.io.file]::openread($SecretKeyFilePath)
    $filein = [system.io.file]::openread($EncryptedFileName)
    $decoderstream = [Org.BouncyCastle.Bcpg.OpenPgp.PgpUtilities]::GetDecoderStream($filein)

    [Org.BouncyCastle.Bcpg.OpenPgp.PgpObjectFactory]$pgpF = [Org.BouncyCastle.Bcpg.OpenPgp.PgpObjectFactory]::new($decoderstream)
    
    
   # [Org.BouncyCastle.Bcpg.OpenPgp.PgpEncryptedDataList]$pgpenclist;
    
    [Org.BouncyCastle.Bcpg.OpenPgp.PgpObject]$pgpObj = $pgpF.NextPgpObject();
    #
    # the first object might be a PGP marker packet.
    #
    if($pgpObj -is [Org.BouncyCastle.Bcpg.OpenPgp.PgpEncryptedDataList]) {
        [Org.BouncyCastle.Bcpg.OpenPgp.PgpEncryptedDataList]$pgpenclist = [Org.BouncyCastle.Bcpg.OpenPgp.PgpEncryptedDataList]$pgpObj
    } else {
        [Org.BouncyCastle.Bcpg.OpenPgp.PgpEncryptedDataList]$pgpenclist = [Org.BouncyCastle.Bcpg.OpenPgp.PgpEncryptedDataList]$pgpF.NextPgpObject();
    }


    #now we find the secret key
    # Must make sure it's SANE
    # SANE looks like a block of random characters with NO EXTRA LINE BREAKS and NO Pub key garbage!
    # with bad line spacing error is:
    #  MethodInvocationException: Exception calling ".ctor" with "1" argument(s): "unknown object in stream 21"
    # Error with pub key still included: 
    # MethodInvocationException: Exception calling ".ctor" with "1" argument(s): "Org.BouncyCastle.Bcpg.OpenPgp.PgpPublicKeyRing found where PgpSecretKeyRing expected"
    # The newline between "Version: GnuPG v2" MUST be there
    # there must be no newlines between BEGIN block and Version: line
    # or this error:
    # MethodInvocationException: Exception calling "GetDecoderStream" with "1" argument(s): "invalid armor header"
    <#

    -----BEGIN PGP PRIVATE KEY BLOCK-----
    Version: GnuPG v2

    lQO+BGMh5ZYBCADB/MJ3ITMZasfggQqkUqVtlLhrkK59JdTJQ5BqIBdr9kyEIn6
    ...
    ...
    (more lines like above)
    ...
    zBjZKwHU2YIYb1hcYmTxD3z7d+IcdFNuFKsKkIKzaYy8XQ==
    =FtiY
    -----END PGP PRIVATE KEY BLOCK-----
    #>
    [Org.BouncyCastle.Bcpg.OpenPgp.PgpPrivateKey]$skey = $null
    [Org.BouncyCastle.Bcpg.OpenPgp.PgpPublicKeyEncryptedData]$pbe = $null
    [Org.BouncyCastle.Bcpg.OpenPgp.PgpSecretKeyRingBundle]$pgpsec = `
        [Org.BouncyCastle.Bcpg.OpenPgp.PgpSecretKeyRingBundle]::new([Org.BouncyCastle.Bcpg.OpenPgp.PgpUtilities]::GetDecoderStream($keyin))


    foreach ( $pked in $pgpenclist.GetEncryptedDataObjects()) {
        [Org.BouncyCastle.Bcpg.OpenPgp.PgpPrivateKey]$sKey = [Org.BouncyCastle.Bcpg.OpenPgp.PgpPrivateKey](Find-SecretKey -pgpsec $pgpSec -keyid $pked.KeyId -pass $gpgpassword)
        if (-not ( $null -eq $skey)) {
            [Org.BouncyCastle.Bcpg.OpenPgp.PgpPublicKeyEncryptedData]$pbe = $pked
        }
    }
    if($null -eq $skey) {
        throw [System.ArgumentException]::New("secret key for message $($EncryptedFileName) not found.")
    }
    [System.io.stream]$clear = $pbe.GetDataStream($skey)
    
    [Org.bouncycastle.bcpg.openpgp.PgpObjectFactory]$plainfactory = [Org.bouncycastle.bcpg.openpgp.PgpObjectFactory]::new($clear)
    [Org.bouncycastle.bcpg.openpgp.PgpObject]$message = $plainfactory.NextPgpObject()
    

    if($message -is [Org.BouncyCastle.Bcpg.OpenPgp.PgpCompressedData]) {
        [Org.BouncyCastle.Bcpg.OpenPgp.PgpCompressedData]$cdata = [Org.BouncyCastle.Bcpg.OpenPgp.PgpCompressedData]$message
        [Org.BouncyCastle.Bcpg.OpenPgp.PgpObjectFactory]$pgpfact = [Org.BouncyCastle.Bcpg.OpenPgp.PgpObjectFactory]::new($cdata.GetDataStream())
        $message  = $pgpFact.NextPgpObject();
    }
    

    if($message -is [Org.BouncyCastle.Bcpg.OpenPgp.PgpLiteralData]) {
        [Org.BouncyCastle.Bcpg.OpenPgp.PgpLiteralData]$ld = [Org.BouncyCastle.Bcpg.OpenPgp.PgpLiteralData]$message
        [System.String]$outfilename = $ld.filename;
        if(-not(test-path -Path $OutputFolderPath -PathType Container)){
            Write-debug "Destination folder does not exist, attempting create destination directory $OutputFolderPath"
            new-item -Path $OutputFolderPath -ItemType Directory

        }
        if ($outfilename.Length -eq 0) {
            write-error "File Name Not Specified, Using Default prefix+timestamp"
            $outfilename = "$outputfolderpath\$defaultfileprefix$(get-date -format FileDateTimeUniversal)$(if($AppendDefaultSuffix){$DefaultSuffix})"
        }
        [system.io.stream]$fout = [system.io.file]::create("$OutputFolderPath\$outfilename$(if($AppendDate){get-date -format FileDateUniversal})$(if($AppendDefaultSuffix){$DefaultSuffix})")
        [system.io.stream]$unc = $ld.getinputstream();
        [Org.BouncyCastle.Utilities.io.Streams]::pipeall($unc, $fout);
        $OutputFileData = $fout.Name
        $fout.close();
    }elseif($message -is [Org.BouncyCastle.Bcpg.OpenPgp.PgpOnePassSignatureList]) {
        throw  [Org.BouncyCastle.Bcpg.OpenPgp.PgpException]::new("encrypted message contains a signed message - not literal data.");
    }else {
        Throw [Org.BouncyCastle.Bcpg.OpenPgp.PgpException]::new("message is not a simple encrypted file - type unknown.");
    }
    
    if($pbe.IsIntegrityProtected()){
        if(-not($pbe.Verify())) {
            write-error "message failed integrity check"
        } else {
            write-debug "message integrity check passed"
        }
    } else {
        Write-error "no message integrity check"
    }
    $keyin.close()
    $filein.close()
    return $OutputFileData
}
function Decrypt-EncryptedPGPFolder {
    [CmdLetbinding(DefaultParameterSetName='SecureParamSet')]
    <#
     In the function's code, you can either test for whether $A and/or $B are null, or check $PSBoundParameters.ContainsKey('A'), or check $PSCmdlet.ParameterSetName to see whether it
    is set to 'By_A' or 'By_B'
    #>
    param( [Parameter(Mandatory=$true,ParameterSetName='PlainParamSet')][Parameter(Mandatory=$true,ParameterSetName='SecureParamSet')][System.String]$SecretKeyFilePath, `
    [Parameter(Mandatory=$true,ParameterSetName='PlainParamSet')][Parameter(Mandatory=$true,ParameterSetName='SecureParamSet')][System.String]$EncryptedFolderName, `
    [Parameter(Mandatory=$true,ParameterSetName='PlainParamSet')][Parameter(Mandatory=$true,ParameterSetName='SecureParamSet')][System.String]$OutputFolderPath, `
    [Parameter(Mandatory=$false,ParameterSetName='PlainParamSet')][Parameter(Mandatory=$false,ParameterSetName='SecureParamSet')][switch]$AppendDate = $false, `
    [Parameter(Mandatory=$false,ParameterSetName='PlainParamSet')][Parameter(Mandatory=$false,ParameterSetName='SecureParamSet')][switch]$AppendDefaultSuffix = $false, `
    [Parameter(Mandatory=$false,ParameterSetName='PlainParamSet')][Parameter(Mandatory=$false,ParameterSetName='SecureParamSet')][System.String]$DefaultSuffix = ".csv", `
    [Parameter(Mandatory=$false,ParameterSetName='PlainParamSet')][Parameter(Mandatory=$false,ParameterSetName='SecureParamSet')][System.String]$DefaultFilePrefix = "File-Decrypted-", `
    [Parameter(Mandatory=$true,ParameterSetName='PlainParamSet')][System.String]$PlainTextPassphrase, `
    [Parameter(Mandatory=$true,ParameterSetName='SecureParamSet')][System.Security.SecureString]$SecurePassphrase)

    $CHILDITEMS = Get-ChildItem $EncryptedFolderName | WHERE-OBJECT { -NOT $_.PSISCONTAINER}
    write-debug "$($Childitems.count) files to decrypt in $ENcryptedFolderName"
    $CHILDITEMS | ForEach-Object {
        if($PSCmdlet.ParameterSetName -eq "SecureParamSet"){
            try {
            ConvertFrom-EncryptedPGPFile -SecretKeyFilePath $SecretKeyFilePath -EncryptedFileName $_.Fullname `
            -SecurePassphrase $SecurePassphrase -OutputFolderPath $outputfolderpath `
            -AppendDate:$AppendDate -DefaultFilePrefix $DefaultFilePrefix `
            -AppendDefaultSuffix:$AppendDefaultSuffix -DefaultSuffix $DefaultSuffix
            } catch {
                write-error "Failed to securely decrypt $($_.FullName)"
            }

        }else{
            try {
            ConvertFrom-EncryptedPGPFile -SecretKeyFilePath $SecretKeyFilePath -EncryptedFileName $_.Fullname `
            -PlainTextPassphrase $PlainTextPassphrase -OutputFolderPath $outputfolderpath `
            -AppendDate:$AppendDate -DefaultFilePrefix $DefaultFilePrefix `
            -AppendDefaultSuffix:$AppendDefaultSuffix -DefaultSuffix $DefaultSuffix
            }catch {
                write-error "Failed to securely decrypt $($_.FullName)"
            }
        }
    }
}
