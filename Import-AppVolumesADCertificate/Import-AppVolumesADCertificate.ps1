
Function Import-AppVolumesADCertificate  
{
  <#
      .SYNOPSIS
      Import-AppVolumesADCertificate tries to get root LDAP certificates and store them to adCA.pem file used by App Volumes Manager

      .DESCRIPTION
      Import-AppVolumesADCertificate tries to get root LDAP certificates and store them to adCA.pem file used by App Volumes Manager

      .PARAMETER domainNames
      comma-separated list of domains or domain controllers

      .PARAMETER OutToScreen
      Write output to the screen instead of writing to a file

      .EXAMPLE
      Import-AppVolumesADCertificate -domainNames corp.vmware.test -OutToScreen
      Extracts CA certificates for corp.vmware.test and writes output to the screen

      .NOTES
      adCA.pem is a list of root CA certificates 

      .LINK
      https://docs.vmware.com/en/VMware-App-Volumes/index.html

      .INPUTS
      comma-separated list of domain controllers

      .OUTPUTS
      root CA certificates in base64 encoding
  #>


  param( 
    [parameter(ValueFromPipeline = $true)][string[]]$domainNames,
    [bool]$OutToScreen 
  )

  begin
  {
    $ErrorActionPreference = 'SilentlyContinue'
    if ($domainNames -eq $null)
    {
      Write-Output  -InputObject "domainNames not specified, defaulting output to $env:USERDNSDOMAIN"
      $domainNames = $env:USERDNSDOMAIN
    }
  } # begin
  process
  {
    if (-not $OutToScreen)  
    {
      $servicePath = (Get-ItemProperty -Path HKLM:\SYSTEM\ControlSet001\Services\svmanager -Name ImagePath -ErrorAction SilentlyContinue).ImagePath 
   
      if($servicePath -eq $null)
      {
        Write-Output  -InputObject 'App Volumes Manager directory not found, defaulting output to screen'
        $OutToScreen = $true
      }
      else
      {
        try
        {
          $ManagerPath = ( $servicePath|ForEach-Object -Process {
              [IO.FileInfo]::new($_.replace('"',''))
          }).Directory.Parent
        }
        catch
        {
          throw ("Failed to retrieve App Volumes manager path` because {0}" -f $_)
        }
      }
      if($ManagerPath -ne $null)
      {
        $adCAPath = Join-Path -Path $ManagerPath.FullName -ChildPath 'config\adCA.pem'
        if ([IO.File]::Exists($adCAPath))
        {
          $adCA = Get-Content -Path $adCAPath | Out-String
        }
      }
    }
    $cacertnew = [Text.StringBuilder]::new()
    
    if($adCA -ne $null)
    {
      $null = $cacertnew.Append($adCA)
    }

    foreach ($domainName in $domainNames)
    {
      try 
      {
        $tcpclient = New-Object -TypeName System.Net.Sockets.tcpclient
        $tcpclient.Connect($domainName, 636)
        $sslstream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList $tcpclient.GetStream(), $false, {
          $true
        }
        $sslstream.AuthenticateAsClient($domainName)
        $cert = [Security.Cryptography.X509Certificates.X509Certificate2]($sslstream.remotecertificate)
        $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
        $chainBuilt = $chain.Build($cert)
      }
      catch 
      {
        throw ("Failed to retrieve remote certificate from {0}` because {1}" -f $domainName, $_)
      }
      finally 
      {
        #cleanup
        if ($sslstream) 
        {
          $sslstream.close()
        }
        if ($tcpclient) 
        {
          $tcpclient.close()
        }        
      }
      if($chainBuilt)
      {
        for($i = $chain.ChainElements.Count-1; $i -gt 0;$i--)
        {
          $sb = [Text.StringBuilder]::new()
          $null = $sb.AppendLine('-----BEGIN CERTIFICATE-----')
         
          $thisCert = $chain.ChainElements[$i].Certificate
          $null = $sb.AppendLine([Convert]::ToBase64String($thisCert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert), 'InsertLineBreaks'))
          $null = $sb.AppendLine('-----END CERTIFICATE-----')
          $cacert = $sb.ToString()
      
          if( -not $cacertnew.ToString().Contains($cacert))
          {
            $null = $cacertnew.AppendLine()
            $null = $cacertnew.AppendLine(('{0}' -f $thisCert.Subject.ToString()))
            $null = $cacertnew.AppendLine('==================')
            $null = $cacertnew.Append($cacert)
          }
        }
        if (-not $OutToScreen)
        {
          Set-Content -Path $adCAPath -Value $cacertnew.ToString()
        }
        else 
        {
          Write-Output  -InputObject $cacertnew.ToString()
        }
      }
    }
  }
}

     
     

