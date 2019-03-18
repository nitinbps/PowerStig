# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\Common\Common.psm1
using module .\..\Rule\Rule.psm1
#header

<#
    .SYNOPSIS
        Convert the contents of an xccdf check-content element into a RegistryRule
    .DESCRIPTION
        The RegistryRule class is used to extract the registry settings
        from the check-content of the xccdf. Once a STIG rule is identified a
        registry rule, it is passed to the RegistryRule class for parsing
        and validation.
    .PARAMETER Key
        The registry key to be evaluated
    .PARAMETER ValueName
        The registry value name to be evaluated
    .PARAMETER ValueData
        The value data that should be appiled to the the ValueName
    .PARAMETER ValueType
        The type of registry value
    .PARAMETER Ensure
        A present or absent flag
#>
Class RegistryRule : Rule
{
    [string] $Key
    [string] $ValueName
    [string[]] $ValueData <#(ExceptionValue)#>
    [string] $ValueType
    [ensure] $Ensure
    [string] $FixText

    <#
        .SYNOPSIS
            Default constructor to support the AsRule cast method
    #>
    RegistryRule () {}

    <#
        .SYNOPSIS
            THe Convert child class constructor
        .PARAMETER Rule
            The STIG rule to convert
        .PARAMETER Convert
            A simple bool flag to create a unique constructor signature
    #>
    RegistryRule ([xml.xmlelement] $Rule, [bool] $Convert) : Base ($Rule, $Convert) {}

    <#
        .SYNOPSIS
            Used to load PowerSTIG data from the processed data directory
        .PARAMETER Rule
            The STIG rule to load
    #>
    RegistryRule ([xml.xmlelement] $Rule) : Base ($Rule)
    {
        $this.Key = $Rule.Key
        $this.ValueName = $Rule.ValueName
        $this.ValueData = $Rule.ValueData
        $this.ValueType = $Rule.ValueType
        $this.Ensure = $Rule.Ensure
        $this.FixText = $Rule.FixText
    }

    <#
        .SYNOPSIS
            Creates the class specifc help content and passes it to the base class
            method to create the help content
    #>
    [PSObject] GetExceptionHelp()
    {
        $return = @{
            Value = "1"
            Notes = "This registry value type is $($this.ValueType). Ensure the exception data matches the value type."
        }
        return $return
    }
}
