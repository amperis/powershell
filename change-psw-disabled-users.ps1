function New-RandomPassword2 {
    param(
        [Parameter()]
        [int]$MinimumPasswordLength = 12,
        [Parameter()]
        [int]$MaximumPasswordLength = 13,
        [Parameter()]
        [int]$NumberOfAlphaNumericCharacters = 1,
        [Parameter()]
        [switch]$ConvertToSecureString
    )
    
    Add-Type -AssemblyName 'System.Web'
    $length = Get-Random -Minimum $MinimumPasswordLength -Maximum $MaximumPasswordLength
    $password = [System.Web.Security.Membership]::GeneratePassword($length,$NumberOfAlphaNumericCharacters)
    if ($ConvertToSecureString.IsPresent) {
        ConvertTo-SecureString -String $password -AsPlainText -Force
    } else {
        $password
    }
}

$usuarios = Get-ADUser -Filter {Enabled -eq $false}

$i=0
foreach($usuario in $usuarios) {
   $i++
   $psw = New-RandomPassword2 
   write-host "$($usuario.SamAccountName) [ $($psw) ]"
   Set-ADAccountPassword -Identity $usuario.SamAccountName -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "$psw" -Force)
}

write-host "--------------"
write-host "$($i) usuarios encontrados"
