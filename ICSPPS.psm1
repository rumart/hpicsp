function Invoke-I2ICSPAPIRequest{
    [CmdletBinding()]
    param(
        $ICServer,
        [string]
        $Path,
        [string]
        $Protocol = "https",
        [int]
        $Port = 443,
        [Parameter(Mandatory=$false)]
        [ValidateSet("GET","POST","PUT")]
        [string]
        $Method = "GET",
        $Resource,
        $Body,
        $Query,
        $SessionKey = $Global:icsp_sessionkey
    )

    if($Resource -notlike "/rest/*"){
        $Resource = "/rest/" + $Resource
    }

    $Path += $Resource
        
    $URIBuilder = New-Object System.UriBuilder -ArgumentList @($Protocol, $ICServer, $Port, $Path)
    $Uribuilder.Query = $query

    if($SessionKey){
        Write-Verbose "Building Header with session key $sessionkey"
        $headers = @{} 
        $headers["Auth"] = $sessionkey
        $headers["X-Api-Version"] = "200"
    }

    
    Write-Verbose "Invoking REST request"
        
    if($Method -eq "GET"){
        Invoke-RestMethod -Method $Method -Uri $URIBuilder.Uri -Body $Body -Headers $headers -ContentType "application/json" #-Verbose
    }
    else{
        Invoke-RestMethod -Method $Method -Uri $URIBuilder.Uri -Body $Body -Headers $headers -ContentType "application/json" #-Verbose
    }
    

}

function New-I2ICSPSessionKey{
[CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $Server,
        [Parameter(Mandatory=$true, ValueFromPipeline=$false)]
        $Username,
        [Parameter(Mandatory=$true, ValueFromPipeline=$false)]
        $Password,
        [Parameter(Mandatory=$false, ValueFromPipeline=$false)]
        $LoginDomain
    )

add-type @" 
    using System.Net; 
    using System.Security.Cryptography.X509Certificates; 
    public class TrustAllCertsPolicy : ICertificatePolicy { 
        public bool CheckValidationResult( 
            ServicePoint srvPoint, X509Certificate certificate, 
            WebRequest request, int certificateProblem) { 
            return true; 
        } 
    } 
"@  
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

    $global:icspserver = $server

    $decryptPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

$body = @"
{
    "authLoginDomain":"$LoginDomain",
    "userName":"$username",
    "password":"$decryptPassword"
}
"@

    Write-Verbose $body

    $response = Invoke-I2ICSPAPIRequest -Method Post -Resource "login-sessions" -Body $body #-Verbose

    $sessionkey = $response.sessionid
    $global:icsp_sessionkey = $sessionkey


}

function Connect-I2ICSP{
<#
    .SYNOPSIS
        Creates a connection to a ICSP server
    .DESCRIPTION
        Connects to the specified HPE Insight Control Server Provisioning server and creates a session key for later use
    .NOTES
        Info
        Author : Rudi Martinsen / Intility AS
        Date : 28/08-2016
        Version : 0.9
        Revised : 
    .PARAMETER ICSPServer
        The ICSP server to connect to
    .PARAMETER Username
        Username for the connection
    .PARAMETER Password
        Password for the given user
    .PARAMETER Directory
        Directory for the connection, local or Active Directory domain
    .EXAMPLE
        Connect-I2ICSP -ICSPServer icserver001 -Username user01 -Password (Read-Host -AsSecurestring)

        Connects to the OVSERVER001 Oneview server with the given username and password
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $ICSPServer,
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, HelpMessage="Please provide username")]
        $Username,
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, HelpMessage="Please provide password")]
        [SecureString]
        $Password
    )

    New-I2ICSPSessionKey -Server $ICSPServer -Username $Username -Password $Password -LoginDomain "i04.local" #-Verbose
}

function Get-I2ICSPServer{
<#
    .SYNOPSIS
        Gets a server from ICSP
    .DESCRIPTION
        Connects to the specified HPE Insight Control Server Provisioning server and searches for one or more servers
    .NOTES
        Info
        Author : Rudi Martinsen / Intility AS
        Date : 28/08-2016
        Version : 0.9
        Revised : 
    .PARAMETER Serial
        Serial number of the server to search for
    .PARAMETER ILOIp
        ILO IP address of the server to search for
    .EXAMPLE
        Get-I2ICSPServer

        Lists all servers from the connected ICSP server
    .EXAMPLE
        Get-I2ICSPServer -Serial ABCDE12345

        Searchs for a server with the given serial number on the connected ICSP server

#>
    [CmdletBinding(DefaultParameterSetName="none")]
    param(
        [Parameter(Mandatory=$false,ParameterSetName="serial")]
        $Serial,
        [Parameter(Mandatory=$false,ParameterSetName="ilo")]
        $ILOIp
    )

    
    Write-Verbose "Invoking REST request"
        
    if($Serial){
        $SrcResource = "index/resources"
        $SrcQuery = "category=osdserver&query=osdServerSerialNumber=" + $serial
        $search = Invoke-I2ICSPAPIRequest -Resource $SrcResource -Query $SrcQuery

        if($search){
            Write-Verbose "Found $($search.members.count) results"
            if($search.members.count -gt 1){
                throw "Multiple results found"
            }
            
            $result = Invoke-I2ICSPAPIRequest -Resource $search.members.uri
            $result
        }
       
    }
    else{

        $Resource = "os-deployment-servers"

        Write-Verbose "Pulling all servers"        
        $response = Invoke-I2ICSPAPIRequest -Resource $Resource 

        if($ILOIp){
            Write-Verbose "Filtering on iLO IP"
            $results = $response.members #| where {$_.peerIP -eq $Server -or $_.serialnumber -eq $Server}
            foreach($res in $results){
                $result = Invoke-I2ICSPAPIRequest -Resource $res.uri
                if($result.ilo[0].ipAddress -eq $ILOIp){
                    $result
                }
            
            }
        }
        else{
            $result = $response.members
            $result
        }
    }
}

function New-I2ICSPServer{
<#
    .SYNOPSIS
        Creates a server in ICSP
    .DESCRIPTION
        Creates a new server resource on the connected ICSP server
    .NOTES
        Info
        Author : Rudi Martinsen / Intility AS
        Date : 28/08-2016
        Version : 0.9
        Revised : 
    .PARAMETER ILOIp
        ILO IP address of the server to create
    .PARAMETER ILOPort
        ILO Port of the server to create
    .PARAMETER ILOUser
        ILO User with admin credentials on the server to create
    .PARAMETER ILOPassword
        Password for the ILO User account
    .EXAMPLE
        New-I2ICSPServer -ILOIp 1.1.1.1 -ILOUser admin01

        Prompts for the password of user admin01 and creates a resource on the connected ICSP server
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $ILOIP,
        [Parameter(Mandatory=$false)]
        $ILOPort = 443,
        [Parameter(Mandatory=$true)]
        $ILOUser,
        [Parameter(Mandatory=$true)]
        [SecureString]
        $ILOPassword
    )
    
    $decryptPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ILOPassword))

    $body = @{}
    $body["ipAddress"] = $ILOIP
    $body["port"] = $ILOPort
    $body["username"] = $ILOUser
    $body["password"] = $decryptPassword

    $body = $body | ConvertTo-Json
    Write-Verbose "Body $body"

    Write-Verbose "Invoking REST request"
    $response = Invoke-I2ICSPAPIRequest -Method POST -Resource "os-deployment-servers" -Body $body #-Verbose

    $response

}

function Get-I2ICSPJob{
<#
    .SYNOPSIS
        Gets a job from ICSP
    .DESCRIPTION
        Connects to the specified HPE Insight Control Server Provisioning server and searches for one or more jobs
    .NOTES
        Info
        Author : Rudi Martinsen / Intility AS
        Date : 26/09-2016
        Version : 0.9
        Revised : 05.10-2016
    .PARAMETER Job
        Serial number of the server to search for
    .EXAMPLE
        Get-I2ICSPJob

        Lists all jobs on the connected ICSP server
    .EXAMPLE
        Get-I2ICSPJob -Job 123456

        Gets the job with the specified Job ID

#>
    [CmdletBinding()]
    param(
        $Job
    )
        
    if($Job -is [object] -and $job.category -eq "os-deployment-jobs"){
        Write-Verbose "Job object received"
        $Resource = $job.uri
    }
    elseif($Job -is [pscustomobject] -and $job.uri -ne $null){
        $Resource = $job.uri
    }
    elseif($Job -is [int]){
        $Resource = "os-deployment-jobs/" + $job
    }
    else{
        $Resource = "os-deployment-jobs"
    }

    try{
        Write-Verbose "Invoking REST request"
        $response = Invoke-I2ICSPAPIRequest -Resource $Resource
    }
    catch{
    }

    if($response.category -eq "os-deployment-jobs"){
        $response
    }
    else{
        $response.members
    }
    
}

function Wait-I2ICSPJobCompletion{
<#
    .SYNOPSIS
        Waits for a ICSP job to complete
    .DESCRIPTION
        Connects to the specified HPE Insight Control Server Provisioning server, searches for one or more jobs
        and waits for it to complete
    .NOTES
        Info
        Author : Rudi Martinsen / Intility AS
        Date : 26/09-2016
        Version : 0.9
        Revised : 05.10-2016
    .PARAMETER Job
        Serial number of the server to search for
    .EXAMPLE
        Get-I2ICSPJob 123456 | Wait-I2ICSPJobCompletion

        Gets the job with the specified Job ID and waits for the job to complete
    .EXAMPLE
        Wait-I2ICSPJobCompletion -Job 123456

        Gets the job with the specified Job ID and waits for the job to complete

#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [object]
        $Job
    )

    if($job -is [object] -and $job.category -eq "os-deployment-jobs"){
        Write-Verbose $job.category
        $newStatus = Get-I2ICSPJob -Job $Job
    }
    else{
        throw "Operation not allowed. Please provide a ICSP Job object"
    }

    $currJob = $null
    
    while($newStatus.running -eq "true"){

        if($currJobProg -ne $newStatus.jobProgress[0].currentStepName){
            $currJobProg = $newStatus.jobProgress[0].currentStepName
            Write-Output "$(get-date) Last update: $($newStatus.modified) : $($newStatus.nameOfJobType) - $($newStatus.jobProgress[0].currentStepName)"
        }
        else{
            Write-Host "." -NoNewline
        }

        start-sleep -Seconds 5
        
        $newStatus = Get-I2ICSPJob -Job $Job

    }

    Write-Verbose "Job finished"
    
    $newStatus

}

function Get-I2ICSPBuildPlan{
<#
    .SYNOPSIS
        Gets a OS Buildplan from ICSP
    .DESCRIPTION
        Connects to the specified HPE Insight Control Server Provisioning server and searches for one or more buildplans
    .NOTES
        Info
        Author : Rudi Martinsen / Intility AS
        Date : 28/08-2016
        Version : 0.9.1.0
        Revised : 05/10-2016
    .PARAMETER BuildPlan
        Serial number of the server to search for
    .PARAMETER Name
        ILO IP address of the server to search for
    .PARAMETER Os
        ILO IP address of the server to search for
    .EXAMPLE
        Get-I2ICSPBuildPlan

        Lists all buildplans from the connected ICSP server
    .EXAMPLE
        Get-I2ICSPBuildPlan -Name Buildplan01

        Outputs the buildplan "Buildplan01"

#>
    [CmdletBinding(DefaultParameterSetName="None")]
    param(
        [Parameter(Mandatory=$false,ParameterSetName="BuildPlan")]
        [object]
        $BuildPlan,
        [Parameter(Mandatory=$false,ParameterSetName="Name")]
        $Name,
        [Parameter(Mandatory=$false,ParameterSetName="Os")]
        $Os
    )

    if($BuildPlan){
        if($builPlan -is [object] -and $BuildPlan.category -eq "os-deployment-build-plans"){
            $Resource = $BuildPlan.uri
        }
        else{
            throw "Operation not supported. Input object not a build plan object"
        }
    }
    else{
        $Resource = "os-deployment-build-plans"
    }
    
    $response = Invoke-I2ICSPAPIRequest -Resource $Resource
    
    if($Name){
        $result = $response.members | where {$_.name -like "*" + $Name + "*"}
    }
    elseif($Os){
        $result = $response.members | where {$_.os -like "*" + $Os + "*"}
    }
    else{
        $result = $response.members
    }

    $result


}

function New-I2ICSPDeploymentJob{
<#
    .SYNOPSIS
        Creates a deploymentjob in ICSP
    .DESCRIPTION
        Connects to the specified HPE Insight Control Server Provisioning server and creates a deploymentjob
    .NOTES
        Info
        Author : Rudi Martinsen / Intility AS
        Date : 28/08-2016
        Version : 0.9.1.0
        Revised : 05/10-2016
    .PARAMETER Server
        ICSP Server object to create deployment job for
    .PARAMETER BuildPlan
        ICSP BuildPlan object to create deployment job for
    .PARAMETER IP
        IP address of the server
    .PARAMETER SubnetPrefix
        Network mask of IP subnet. If omitted a subnet prefix of 24 is used
    .PARAMETER IPGateway
        Gateway address of the server. If omitted the IP's .1 address is used
    .PARAMETER VlanId
        Vlan that the IP belongs to
    .PARAMETER Hostname
        Hostname of the server
    .PARAMETER DNSServers
        DNS servers to use for the server
    .PARAMETER DNSSearch
        DNS Search suffix
    .EXAMPLE
        New-I2ICSPBuildPlan -Server $server01 -Buildplan $plan01 -IP 10.10.10.10 -SubnetSuffix 24 -IPGateway 10.10.10.1 -VlanId 10 -Hostname SERVER01 -DNSServers "8.8.8.8","9.9.9.9"

        Creates and runs a new deployment job with the given parameters
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]
        $Server,
        [Parameter(Mandatory=$true)]
        [object]
        $BuildPlan,
        [Parameter(Mandatory=$false)]
        [string]
        $IP,
        [Parameter(Mandatory=$false)]
        [int]
        $SubnetPrefix,
        [Parameter(Mandatory=$false)]
        [string]
        $IPGateway,
        [Parameter(Mandatory=$false)]
        [int]
        $VlanId = 198,
        [Parameter(Mandatory=$false)]
        [string]
        $Hostname,
        [Parameter(Mandatory=$false)]
        [string[]]
        $DNSServers,
        [Parameter(Mandatory=$false)]
        [string[]]
        $DNSSearch
    )

    if($server -is [object] -and $server.category -eq "os-deployment-servers"){
        $destServer = $server
    }
    else{
        try{
            $destServer = Get-I2ICSPServer -Server $Server.serialNumber
        }
        catch{
        
        }
    }

    if(!$destServer -or $destServer -is [array] -or $destServer.category -ne "os-deployment-servers"){
        throw "Operation failed. Unable to retrieve a single server object"
    }

    if($BuildPlan -is [object] -and $BuildPlan.category -eq "os-deployment-build-plans"){
        $destBuildPlan = $BuildPlan
    }
    else{
        try{
            $destBuildPlan = Get-I2ICSPBuildPlan -Name $BuildPlan
        }
        catch{
        
        }
    }

    if(!$destBuildPlan -or $destBuildPlan -is [array] -or $destBuildPlan.category -ne "os-deployment-build-plans"){
        throw "Operation failed. Unable to retrieve a single build plan object"
    }
    
    $Body = @{}

    $dnsSearch = @($DNSSearch)

    if(!$IPGateway){
        $ipSplit = $ip.split(".")
        $IPGateway = $ipSplit[0] + "." + $ipSplit[1] + "." + $ipSplit[2] + ".1"
    }

    $staticNetworks = @()
    if(!$SubnetPrefix){
        $staticNetworks += $IP + "/24"
    }
    else{
        $staticNetworks += $IP + "/" + $SubnetPrefix
    }
    
    $serverdata = @()
    $servers = @{}
    $osbpuris = @()
    $osbpuris += $destBuildPlan.uri
    
    $Personalitydata = @{}
    
    $Interfaces = New-Object System.Collections.Arraylist
    
    foreach($srvInt in $server.interfaces){
            
        $interface = New-Object PSCustomObject
        $interface | Add-Member -MemberType NoteProperty -Name macAddress -Value $srvInt.macAddr
        $interface | Add-Member -MemberType NoteProperty -Name dhcpv4 -Value $false
        
        $interface | Add-Member -MemberType NoteProperty -Name ipv6Autoconfig -Value $false
        $interface | Add-Member -MemberType NoteProperty -Name ipv6gateway -Value $null
        
        if($srvInt.slot -eq "eth0"){
            $interface | Add-Member -MemberType NoteProperty -Name enabled -Value $true
            $interface | Add-Member -MemberType NoteProperty -Name ipv4gateway -Value $IPGateway
            $interface | Add-Member -MemberType NoteProperty -Name vlanid -Value $VlanId
            $interface | Add-Member -MemberType NoteProperty -Name staticNetworks -Value $staticNetworks
            $interface | Add-Member -MemberType NoteProperty -Name dnsServers -Value $dnsServers
            $interface | Add-Member -MemberType NoteProperty -Name winsServers -Value $null
            $interface | Add-Member -MemberType NoteProperty -Name dnsSearch -Value $dnsSearch
        }
        else{

            
        }
        
        $interfaces += $Interface
    }

    $Personalitydata["interfaces"] = $interfaces
    $Personalitydata["virtualInterfaces"] = $null
    $Personalitydata["hostname"] = $hostname 
    $Personalitydata["domain"] = $null
    $Personalitydata["workgroup"] = $null
    
    $servers["serverUri"] = $destServer.uri
    $servers["skipReboot"] = $true
    $servers["personalityData"] = $Personalitydata
    $serverdata += $servers

    $Body["osbpUris"] = $osbpuris
    $Body["serverData"] = $serverdata
    $body["failMode"] = $null

    $body = ConvertTo-Json $body -Depth 6

    $resource = "os-deployment-jobs"
    Write-Verbose $body
    
    $response = Invoke-I2ICSPAPIRequest -Method POST -Resource $resource -Body $Body
    $response

}

