
Function Import-AppVolumesVsphereCertificate  
{
  <#
      .SYNOPSIS
      Import-AppVolumesVsphereCertificate tries to get vSphere CA certificates and store them to cacerts.pem file used by App Volumes Manager

      .DESCRIPTION
      Import-AppVolumesVsphereCertificate tries to get root LDAP certificates and store them to cacerts.pem file used by App Volumes Manager

      .PARAMETER vSphereHosts
      comma-separated list of vSphere hosts or ESXi servers

      .PARAMETER OutToScreen
      Write output to the screen instead of writing to a file

      .EXAMPLE
      Import-AppVolumesVsphereCertificate -vSphereHosts vc01.corp.vmware.test -OutToScreen
      Extracts CA certificates for vc01.corp.vmware.test and writes output to the screen

      .NOTES
      cacerts.pem is a list of root CA certificates 

      .LINK
      https://docs.vmware.com/en/VMware-App-Volumes/index.html

      .INPUTS
      comma-separated list of domain controllers

      .OUTPUTS
      root CA certificates in base64 encoding
  #>


  param( 
    [parameter(ValueFromPipeline = $true)][string[]]$vSphereHosts,
    [bool]$OutToScreen 
  )

  begin
  {
    $ErrorActionPreference = 'SilentlyContinue'
    
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
        $caCertsPath = Join-Path -Path $ManagerPath.FullName -ChildPath 'config\cacert.pem'
        if ([IO.File]::Exists($caCertsPath))
        {
          $caCerts = Get-Content -Path $caCertsPath | Out-String
        }
      }
    }
    $cacertnew = [Text.StringBuilder]::new()
    
    if($caCerts -ne $null)
    {
      $null = $cacertnew.Append($caCerts)
    }
    
    Add-Type  -TypeDefinition @'
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {
        return true;
    }
}

'@ 
    $AllProtocols = [Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
    [Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    [Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {
      $true
    }
       
    $webclient = New-Object -TypeName System.Net.WebClient
        
    foreach ($vSphereHost in $vSphereHosts)
    {
      $tempfile = [IO.Path]::GetTempFileName()
        
      try
      {
        $webclient.DownloadFile('https://'+$vSphereHost+'/certs/download.zip',$tempfile)
        $downloadok = $true
      }
      catch
      {
        $downloadok = $false
      }
      if(!$downloadok) 
      {
        try
        {
          $webclient.DownloadFile('https://'+$vSphereHost+'/certs/download',$tempfile)
          $downloadok = $true
        }
        catch
        {
          $downloadok = $false
        }
      }
      if (-not $downloadok)
      {
        throw ('Unable to download certificate {0}' -f $_)
      }
        
      Add-Type -AssemblyName System.IO.Compression.FileSystem
      $parent = [IO.Path]::GetTempPath()
      [string] $name = [Guid]::NewGuid()
      $tempFolder = New-Item -ItemType Directory -Path (Join-Path -Path $parent -ChildPath $name)
      [IO.Compression.ZipFile]::ExtractToDirectory($tempfile, $tempFolder)
      $Dir = Get-ChildItem -Path $tempFolder -Recurse
      $List = $Dir | Where-Object -FilterScript {
        $_.extension -eq '.0'
      }
      
     
     
      
      
      foreach( $file in $List)
      {
        $sb = [Text.StringBuilder]::new()
        $null = $sb.AppendLine('-----BEGIN CERTIFICATE-----')
         
        $thisCert = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromCertFile($file.FullName)
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
      Remove-Item $tempFolder -Force -Recurse
      Remove-Item $tempfile -Force

      if (-not $OutToScreen)
      {
        Set-Content -Path $caCertsPath -Value $cacertnew.ToString()
      }
      else 
      {
        Write-Output  -InputObject $cacertnew.ToString()
      }
    }
  }
}

     
     

Import-AppVolumesVsphereCertificate -vSphereHosts $args