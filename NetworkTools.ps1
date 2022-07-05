using namespace System.Collections.Generic

<#

[NetToolv4]::new("192.168.1.100", "255.255.255.0")
[NetToolv4]::new("192.168.1.100/24")

#>

class NetToolv4
{
    [string]$IP
    [string]$GW
    [string]$SNM
    [string]$NetAddress
    [string]$Broadcast

    NetToolv4()
    {
        $this.IP         = $null
        $this.GW         = $null
        $this.SNM        = $null
        $this.NetAddress      = $null 
        $this.Broadcast  = $null
    }

    NetToolv4($IP)
    {
        Write-Verbose "[NetToolv4] - Begin"
        # is this in CIDR notation?
        if ($IP -match '/')
        {
            Write-Verbose "[NetToolv4] - Found CIDR notation: $IP"
            # assume this is in IP in CIDR notation
            $CIDR = $IP.Split('/')[1]
            Write-Verbose "[NetToolv4] - CIDR value: $CIDR"

            $strIP = $IP.Split('/')[0]
            Write-Verbose "[NetToolv4] - IP value: $strIP"

            $strSNM = $this.ConvertCIDR2SNM($CIDR)
            Write-Verbose "[NetToolv4] - Subnet Mask: $strSNM"
        }
        else
        {
            $strIP = $IP.ToString()
            Write-Verbose "[NetToolv4] - Just an IP: $strIP"
            $strSNM = $null
        }

        Write-Verbose "[NetToolv4] - Adding $strIP to object."
        $this.IP  = $this.ParseIP($strIP)

        Write-Verbose "[NetToolv4] - Null gateway."
        $this.GW  = $null

        if ([string]::IsNullOrEmpty($strSNM))
        {
            Write-Verbose "[NetToolv4] - Null subnet mask."
            $this.SNM = $null
        }
        else
        {
            Write-Verbose "[NetToolv4] - Adding derived subnet mask $strSNM."
            $this.SNM = $strSNM
        }
        
        if (-NOT [string]::IsNullOrEmpty($strSNM) -and -NOT [string]::IsNullOrEmpty($strIP))
        {
           $this.CalcThings($strIP, $strSNM)
        }
        else
        {
            $this.NetAddress     = $null
            $this.Broadcast = $null
        }
    }

    NetToolv4($IP, $SNM)
    {
        $this.IP         = $this.ParseIP($IP)
        $this.GW         = $null
        $this.SNM        = $this.ParseIP($SNM)

        if (-NOT [string]::IsNullOrEmpty($IP) -and -NOT [string]::IsNullOrEmpty($SNM))
        {
           $this.CalcThings($IP, $SNM)
        }
        else
        {
            $this.NetAddress     = $null
            $this.Broadcast = $null
        }
    }

    NetToolv4($IP, $SNM, $GW)
    {
        $this.IP         = $this.ParseIP($IP)
        $this.GW         = $this.ParseIP($GW)
        $this.SNM        = $this.ParseIP($SNM)
        $this.NetAddress      = $null 
        $this.Broadcast  = $null
    }


    CalcThings($strIP, $strSNM)
    {
        Write-Verbose "[NetToolv4]::CalcThings() - Calculating network address using $strIP and $strSNM."
        $strNetAddress = $this.GetNetworkAddress($strIP, $strSNM)

        Write-Verbose "[NetToolv4]::CalcThings() - Calculating broadcast address using $strIP and $strSNM."
        $strBcast = $this.GetBroadcastAddress($strIP, $strSNM)

        Write-Verbose "[NetToolv4] - Network address: $strNetAddress."
        $this.NetAddress = $strNetAddress
        
        Write-Verbose "[NetToolv4] - Broadcast address: $strBcast."
        $this.Broadcast = $strBcast

    }


    [string]
    ParseIP($IP)
    {
        try
        {
            [ipaddress]::TryParse($IP, [ref]'1.1.1.1')
        }
        catch
        {
            Write-Error "Failed to parse the IP address $IP."
            return $null
        }

        return $IP
    }


    [string]
    GetNetworkAddress()
    {
        if (-NOT [string]::IsNullOrEmpty($this.NetAddress))
        {
            return $this.NetAddress
        }
        else 
        {
            return ($this.GetNetworkAddress($this.IP, $this.SNM))
        }

    }

    [string]
    GetNetworkAddress([string]$IP, [string]$SNM)
    {
        Write-Verbose "[NetToolv4]::GetNetworkAddress() - Begin"
        if ([string]::IsNullOrEmpty($IP)) 
        {  
            Write-Warning "Cannot calculate the Network Address. Reason: There is no IP address (IP) defined in the object."
            return $null
        }
        
        if ([string]::IsNullOrEmpty($SNM))
        {  
            Write-Warning "Cannot calculate the Network Address. Reason: There is no Subnet Mask (SNM) defined in the object."
            return $null
        }

        # stores the IP address octets
        Write-Verbose "[NetToolv4]::GetNetworkAddress() - Blank byte list for NetAddress."
        $arrNetAddress = [System.Collections.Generic.List[Byte]]@(0,0,0,0)

        Write-Verbose "[NetToolv4]::GetNetworkAddress() - Split IP by octect."
        $arrIP = [System.Collections.Generic.List[Byte]]@(($IP.Split('.')))

        Write-Verbose "[NetToolv4]::GetNetworkAddress() - Split SNM by octet."
        $arrSNM = [System.Collections.Generic.List[Byte]]@(($SNM.Split('.')))

        # not worrying about performance optimizations at this point
        Write-Verbose "[NetToolv4]::GetNetworkAddress() - Building network address."
        0..3 | ForEach-Object {
            Write-Debug "[NetToolv4]::GetNetworkAddress() - Octect: $_"
            Write-Debug "[NetToolv4]::GetNetworkAddress() - $($arrSNM[$_]) -band $($arrIP[$_])"
            [byte]$tmpB = ($arrSNM[$_]) -band ($arrIP[$_])
            $arrNetAddress[$_] = $tmpB
            
            Write-Debug "[NetToolv4]::GetNetworkAddress() - Result: $($arrNetAddress[$_])"
            Remove-Variable tmpB -EA SilentlyContinue
        }

        return ($arrNetAddress -join '.')

    }

    SetNetworkAddress($IP)
    {
        $this.NetAddress = $this.ParseIP($IP)
    }



    [string]
    GetBroadcastAddress()
    {
        if (-NOT [string]::IsNullOrEmpty($this.Broadcast))
        {
            return $this.Broadcast
        }
        else 
        {
            return ($this.GetBroadcastAddress($this.IP, $this.SNM))
        }

    }

    [string]
    GetBroadcastAddress([string]$IP, [string]$SNM)
    {
        Write-Verbose "[NetToolv4]::GetBroadcastAddress() - Begin"
        if ([string]::IsNullOrEmpty($IP)) 
        {  
            Write-Warning "Cannot calculate the Network Address. Reason: There is no IP address (IP) defined in the object."
            return $null
        }
        
        if ([string]::IsNullOrEmpty($SNM))
        {  
            Write-Warning "Cannot calculate the Network Address. Reason: There is no Subnet Mask (SNM) defined in the object."
            return $null
        }

        # stores the IP address octets
        Write-Verbose "[NetToolv4]::GetBroadcastAddress() - Subnet mask: $SNM"
        [ipaddress]$ipSNM = $SNM

        if ([string]::IsNullOrEmpty($this.NetAddress))
        {
            Write-Verbose "[NetToolv4]::GetBroadcastAddress() - Calculating subnet mask."
            [ipaddress]$ipNetAddress = $this.GetNetworkAddress($IP, $SNM)
            $this.NetAddress = $ipNetAddress.IPAddressToString
            Write-Verbose "[NetToolv4]::GetBroadcastAddress() - Result: $($this.NetAddress)"
        }
        else 
        {
            Write-Verbose "[NetToolv4]::GetBroadcastAddress() - Network Address: $($this.NetAddress)"
            [ipaddress]$ipNetAddress = $this.NetAddress    
        }

        

        Write-Verbose "[NetToolv4]::GetBroadcastAddress() - Doing the broadcast math."
        [ipaddress]$ipBcast = [ipaddress](([ipaddress]::parse("255.255.255.255").address -bxor $ipSNM.address -bor $ipNetAddress.address))
        Write-Verbose "[NetToolv4]::GetBroadcastAddress() - Did the math: $($ipBcast.IPAddressToString)"

        return ($ipBcast.IPAddressToString)

    }

    SetBroadcastAddress($IP)
    {
        $this.Broadcast = $this.ParseIP($IP)
    }



    [string]
    GetAddressRange()
    {
        if (-NOT [string]::IsNullOrEmpty($this.Broadcast))
        {
            return $this.Broadcast
        }
        else 
        {
            return ($this.GetBroadcastAddress($this.IP, $this.SNM))
        }

    }

    [string]
    GetAddressRange([string]$IP, [string]$SNM)
    {
        Write-Verbose "[NetToolv4]::GetBroadcastAddress() - Begin"
        if ([string]::IsNullOrEmpty($IP)) 
        {  
            Write-Warning "Cannot calculate the Network Address. Reason: There is no IP address (IP) defined in the object."
            return $null
        }
        
        if ([string]::IsNullOrEmpty($SNM))
        {  
            Write-Warning "Cannot calculate the Network Address. Reason: There is no Subnet Mask (SNM) defined in the object."
            return $null
        }

        # stores the IP address octets
        Write-Verbose "[NetToolv4]::GetBroadcastAddress() - Subnet mask: $SNM"
        [ipaddress]$ipSNM = $SNM

        if ([string]::IsNullOrEmpty($this.NetAddress))
        {
            Write-Verbose "[NetToolv4]::GetBroadcastAddress() - Calculating subnet mask."
            [ipaddress]$ipNetAddress = $this.GetNetworkAddress($IP, $SNM)
            $this.NetAddress = $ipNetAddress.IPAddressToString
            Write-Verbose "[NetToolv4]::GetBroadcastAddress() - Result: $($this.NetAddress)"
        }
        else 
        {
            Write-Verbose "[NetToolv4]::GetBroadcastAddress() - Network Address: $($this.NetAddress)"
            [ipaddress]$ipNetAddress = $this.NetAddress    
        }

        

        Write-Verbose "[NetToolv4]::GetBroadcastAddress() - Doing the broadcast math."
        [ipaddress]$ipBcast = [ipaddress](([ipaddress]::parse("255.255.255.255").address -bxor $ipSNM.address -bor $ipNetAddress.address))
        Write-Verbose "[NetToolv4]::GetBroadcastAddress() - Did the math: $($ipBcast.IPAddressToString)"

        return ($ipBcast.IPAddressToString)

    }

    SetAddressRange($IP)
    {
        $this.Range = $this.ParseIP($IP)
    }



    [string]
    ConvertCIDR2SNM($CIDR)
    {
        # make sure the CIDR value is within range
        if ($CIDR -lt 0 -or $CIDR -gt 32)
        {
            Write-Error "The CIDR value is invalid. The valid CIDR range is 0-32. CIDR value passed: $CIDR"
        }

        # do the math thing
        $ipSNM = [ipaddress]([math]::pow(2, 32) -1 -bxor [math]::pow(2, (32 - $CIDR))-1)

        return ($ipSNM.IPAddressToString)
    }

}

[NetToolv4]::new("192.168.1.100/24")
[NetToolv4]::new("192.168.1.100", "255.255.255.0")