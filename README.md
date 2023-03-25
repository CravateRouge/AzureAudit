# AzureAudit
## Network Discovery
[networkdiscovery.ps1](networkdiscovery.ps1) enumerates endpoints publicly exposed in all readable subscriptions of a given tenant. You must have Azure read access on those endpoints in order for the script to work.
For the moment, only load balancers and azure firewalls rules are interpreted by this script and smartly printed.

## Right User Enumeration
[rightuserenumeration.ps1](rightuserenumeration.ps1) enumerates all roles assigned to ressources in all readable subscriptions of a given tenant. You must have Azure read access on those ressources in order for the script to show roles associated to them. This script will export the results to `assignments.csv`.
Only Azure roles are enumerated. Permissions in ressources environment (Azure DevOps, ADX...) are not enumerated.
