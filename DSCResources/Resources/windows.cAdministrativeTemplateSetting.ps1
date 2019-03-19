# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type RegistryRule

foreach ($rule in $rules)
{
    if ($rule.FixText -match "Administrative Template" -or $rule.Key -match "^HKEY_CURRENT_USER")
    {
        $splitKeyPath = $rule.Key -split '\\', 2
        $policyType = $splitKeyPath[0].Split('_')[-1]

        if ($rule.ValueType -eq 'MultiString')
        {
            $valueData = $rule.ValueData.Split("{;}")
        }
        else
        {
            $valueData = $rule.ValueData
        }

        if ($valueData -eq 'ShouldBeAbsent')
        {
            $rule.Ensure = 'Absent'
        }

        cAdministrativeTemplateSetting (Get-ResourceTitle -Rule $rule)
        {
            PolicyType   = $policyType
            KeyValueName = $splitKeyPath[1] + '\' + $rule.ValueName
            Data         = $valueData
            Type         = $rule.ValueType
            Ensure       = $rule.Ensure
        }
    }
}
