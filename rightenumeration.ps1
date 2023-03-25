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
# Enumerates privileges of interesting groups and groups which can delegate for all subscriptions
#$trusted = Import-Csv "trusted.csv" | select -ExpandProperty DisplayName
$hashassignments = @{}
foreach($s in Get-AzSubscription){
    (Set-AzContext $s).Subscription | ft Name
    # Gets All ressources in current subscription
    $resources = Get-AzResource
    foreach($r in $resources){
        $assignments = Get-AzRoleAssignment -scope $r.Id # | ? {($_.DisplayName -notin $trusted) -or $_.CanDelegate} | Select DisplayName, RoleDefinitionName, ObjectType, CanDelegate, Description, SignInName | Remove-Null
        foreach($a in $assignments){
            $keyname = $a.Scope + '#' + $a.DisplayName
            $hashassignments.$keyname = $a
        }
    }
}
$hashassignments.Values | Export-Csv .\assignments.csv -NoTypeInformation
return $hashassignments

