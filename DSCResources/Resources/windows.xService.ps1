# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type ServiceRule

foreach ( $rule in $rules )
{
    xService (Get-ResourceTitle -Rule $rule)
    {
        Name        = $rule.ServiceName
        State       = $rule.ServiceState
        StartupType = $rule.StartupType
    }
}
