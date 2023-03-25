Function Remove-Null {
	[CmdletBinding()]
	Param(
		# Object from which to remove the null values.
		[Parameter(ValueFromPipeline,Mandatory)]
		$InputObject,
		# Instead of also removing values that are empty strings, include them in the output.
		[Switch]$LeaveEmptyStrings,
		# Additional entries to remove, which are either present in the properties list as an object or as a string representation of the object.
		# I.e. $item.ToString().
		[Object[]]$AlsoRemove=@()
	)
	Process {
		# Iterate InputObject in case input was passed as an array
		ForEach ($obj in $InputObject) {
			$obj | Select-Object -Property (
				$obj.PSObject.Properties.Name | Where-Object {
					-not (
						# If the property is null, remove it
						$null -eq $obj.$_ -or
                                                # If -LeaveEmptyStrings is not specified and the property is an empty string, remove it
                                                (-not $LeaveEmptyStrings.IsPresent -and [string]::IsNullOrEmpty($obj.$_)) -or
						# If AlsoRemove contains the property, remove it
						$AlsoRemove.Contains($obj.$_) -or
						# If AlsoRemove contains the string representation of the property, remove it
						$AlsoRemove.Contains($obj.$_.ToString())
					)
				}
			)
		}
	}
}
# TODO: expand to all tenants
$hashendpoints = @{}
# Enumerates public address for all subscriptions
foreach($s in Get-AzSubscription){
    $sub = (Set-AzContext $s).Subscription
    $sub | ft Name
    $hashendpoints.$($sub.Name) = @()
    # Gets IpAddress associated to a resource
    $ips = Get-AzPublicIpAddress| ? {$_.IpConfiguration -ne $null}
    foreach($ip in $ips){
        $associated = $ip.IpConfiguration.Id
        # We assume associated resource is network type
        $match = $associated -Match ".*/resourceGroups/([^/]+)/.*/Microsoft.Network/([^/]+)/([^/]+)"
        $resourceid = $matches[0]
        $resourcegroup = $matches[1]
        $resourcetype = $matches[2]
        $resourcename = $matches[3]

        $endpoint = [ordered]@{IpAddress = $ip.IpAddress; Fqdn = $ip.DnsSettings.Fqdn; Type = $resourcetype}

        If($resourcetype -eq "loadBalancers"){
            # TODO: check nic firewall configuration for backend ports and displays special one
            # Returns LB configurations with backend endpoints for InboundNatRules and LoadBalancingRules
            $loadbalancer = Get-AzLoadBalancer -ResourceGroupName $resourcegroup -Name $resourcename
            $portMappers = "InboundNatRules", "LoadBalancingRules"
            $LBproperties = "Protocol", "FrontendPort", "FrontendPortRangeStart", "FrontendPortRangeEnd", "BackendPort"
            $isEmpty = $true
            foreach($mapper in $portMappers){
                foreach($rule in $loadbalancer.$mapper){
                    # Below is code to take security rules into accounts but parsing rules is too complex compared to benefits
                   <#  if($rule.backendAddressPool){

                    }elseif($rule.backendIPConfiguration){
                        $match = $rule.backendIPConfiguration.Id -Match "/resourceGroups/([^/]+)/.*/Microsoft.Compute/([^/]+)/([^/]+)/.*/networkInterfaces/([^/]+)"
                        $group = $matches[1]
                        $type = $matches[2]
                        $name = $matches[3]
                        $nicName = $matches[4]
                        if($type -eq "virtualMachineScaleSets"){
                            $nsgId = (Get-AzVmss -ResourceGroupName $group -VMScaleSetName $name).VirtualMachineProfile.NetworkProfile.NetworkInterfaceConfigurations | ? {$_.Name -eq $nicName} | $_.NetworkSecurityGroup.Id
                            $nsg = $nsgId -Match "/resourceGroups/([^/]+)/.*/networkSecurityGroups/([^/])+" | Get-AzNetworkSecurityGroup -ResourceGroupName $matches[1] -Name $matches[2]
                            # Following return THE security rule applicable for the load balancer rule
                            $secrule = $nsg.SecurityRules + $nsg.DefaultSecurityRules | Sort-Object -Property Priority | ? {$_.Direction -eq "Inbound" -and $_.Protocol -match "$($rule.Protocol)|\*" -and ($rule.BackendPort -match "[$($_.DestinationPortRange)]" -or $rule.BackendPort -match "$($_.DestinationPortRange.Replace("*",".*"))") -and } | Select-Object -First 1
                            if($secrule.Access -eq "Allow"){
                                if($secrule.SourceAddressPrefix -ne "*"){
                                    $endpoint.("$($rule.Name).AuthorizedSources") = $secrule.SourceAddressPrefix
                                }
                                if($secrule.SourcePortRange -ne "*"){
                                    $endpoint.("$($rule.Name).AuthorizedSourcePorts") = $secrule.SourcePortRange
                                }
                            }else{
                                Write-Warning "Security rules forbid: $rule"
                                continue
                            }
                        }elseif($type -eq "virtualMachines"){

                        }else{
                            Write-Warning "Backend type not supported: $($rule.backendIPConfiguration.Id)"
                        }
                    }else{
                        Write-Warning "Uneffective rule: $rule`n"
                        continue
                    } #>
                    $rulename = $rule.Name
                    $endpoint.("$rulename.Type") = $mapper
                    $isEmpty = $false
                    foreach($property in $LBproperties){
                        if($rule.$property){
                            $endpoint.("$rulename.$property") = $rule.$property
                        }
                    }
                    # Backend can be a pool containing Ip configs or directly an Ip conf
                    $backendConf = @()
                    if($rule.BackendAddressPool){
                        $backendConf = @($loadbalancer.inboundNatPools + $loadbalancer.backendAddressPools | ? {$_.Name -eq ($rule.BackendAddressPool.Id -split '/')[-1]} | Select-Object BackendIpConfigurations)
                    }
                    $backendConf = $backendConf + @($rule.backendIPConfiguration)
                    if($backendConf){
                        $endpoint.("$rulename.BackendHost") = ($backendConf | select Id | %{$match = $_ -match "/resourceGroups/([^/]+)/providers/Microsoft\.[A-Za-z]+/[^/]+/([^/]+)"; "$($matches[1])/$($matches[2])"}) -join ','
                    }
                }
            }
            if($isEmpty){Write-Warning "Load balancer with no effective rules: $resourceid"; continue}
        }
        elseif($resourcetype -eq "azureFirewalls"){
            $fw = Get-AzFirewall -ResourceGroupName $resourcegroup -Name $resourcename
            # Takes only DNAT because it doesn't seem possible to reach endpoint behind fw through direct hostname call
            # TODO don't fetch rule erased by another with a priority lower
            $rulesCollections = $fw.NatRuleCollections | ? {$_.Action.Type -eq "DNAT"} | Sort-Object -Property Priority
            foreach($rulesCollection in $rulesCollections){
                foreach($rule in $rulesCollection.Rules){
                    # Returns addresses only if not private ip: 10.X or 172.16.X-172.31.X or 192.168.X- or 100.64.X-100.127.X  
                    $externalAddr = $rule.SourceAddresses | ? {-not($_ -match "10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|100\.(6[0-4]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.")}
                    # And addresses if rule applies to current IP
                    $currentIp = $rule.DestinationAddresses | ? {$_ -match $ip.IpAddress}
                    if(-not($externalAddr -and $currentIp)){
                        continue
                    }
                    $rulename=$rule.Name
                    # Attributes based on LoadBalancer names
                    # Not useful when printing only DNAT $endpoint.("$rulename.Type") = $rulesCollection.Action.Type
                    $endpoint.("$rulename.Protocol") = $rule.Protocols -join ','
                    $endpoint.("$rulename.FrontendPort") = $rule.DestinationPorts -join ','
                    $endpoint.("$rulename.BackendPort") = $rule.TranslatedPort -join ','
                    $endpoint.("$rulename.BackendHost") = $rule.TranslatedAddress
                    if(-not($externalAddr | ? {$_ -match "\*"})){$endpoint.("$rulename.AuthorizedSources") = $externalAddr -join ','}
                }
            }
        }elseif($resourcetype -eq "virtualNetworkGateways"){
            # Azure VPN seems to be based on VPN layer so no ports linked to it
            # Configuration can be weak (e.g weak Shared Access Key)
            $endpoint.Name = $resourcename
        }elseif($resourcetype -eq "bastionHosts"){
            # Configuration can be weak (IP based connection, Shareable Link, Kerberos Auth)
            $endpoint.Name = $resourcename
        }elseif($resourcetype){
            # Resources will be implementend when needed
            $endpoint.Name = $resourcename
        }else{
            Write-Warning "Resource type not supported for analysis: $associated"
            continue
        }
        $endpoint = [pscustomobject]$endpoint | Remove-Null
        # TODO: export to csv instead
        $endpoint | fl
        #$hashendpoints.$($sub.Name) += $endpoint | Add-
    }
}
#return $hashendpoints
