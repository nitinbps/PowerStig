# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\Common\Common.psm1
using module .\..\Rule\Rule.psm1
#header

<#
    .SYNOPSIS
        An Account Policy Rule object
    .DESCRIPTION
        The AccountPolicyRule class is used to maange the Account Policy Settings.
    .PARAMETER PolicyName
        The name of the account policy
    .PARAMETER PolicyValue
        The value the account policy should be set to.
#>
Class AccountPolicyRule : Rule
{
    [string] $PolicyName
    [string] $PolicyValue <#(ExceptionValue)#>

    <#
        .SYNOPSIS
            Default constructor to support the AsRule cast method
    #>
    AccountPolicyRule () {}

    <#
        .SYNOPSIS
            The Convert child class constructor
        .PARAMETER Rule
            The STIG rule to convert
        .PARAMETER Convert
            A simple bool flag to create a unique constructor signature
    #>
    AccountPolicyRule ([xml.xmlelement] $Rule, [bool] $Convert) : Base ($Rule, $Convert) {}

    <#
        .SYNOPSIS
            Used to load PowerSTIG data from the processed data directory
        .PARAMETER Rule
            The STIG rule to load
    #>
    AccountPolicyRule ([xml.xmlelement] $Rule) : Base ($Rule)
    {
        $this.PolicyName  = $Rule.PolicyName
        $this.PolicyValue = $Rule.PolicyValue
    }

    [PSObject] GetExceptionHelp()
    {
        $return = @{
            Value = "15"
            Notes = $null
        }
        return $return
    }
}
