#art becasue why not
Function Print-Art{
    Write-Host -ForegroundColor Magenta @"
  _________                    .__  __  .__                  _____                                  _________ __                                          _____                                   __          
 /   _____/ ____   ____   _____|__|/  |_|__|__  __ ____     /  _  \ __________ _________   ____    /   _____//  |_  ________________     ____   ____     /  _  \   ____  ____  ____  __ __  _____/  |_  ______
 \_____  \_/ __ \ /    \ /  ___/  \   __\  \  \/ // __ \   /  /_\  \\___   /  |  \_  __ \_/ __ \   \_____  \\   __\/  _ \_  __ \__  \   / ___\_/ __ \   /  /_\  \_/ ___\/ ___\/  _ \|  |  \/    \   __\/  ___/
 /        \  ___/|   |  \\___ \|  ||  | |  |\   /\  ___/  /    |    \/    /|  |  /|  | \/\  ___/   /        \|  | (  <_> )  | \// __ \_/ /_/  >  ___/  /    |    \  \__\  \__(  <_> )  |  /   |  \  |  \___ \ 
/_______  /\___  >___|  /____  >__||__| |__| \_/  \___  > \____|__  /_____ \____/ |__|    \___  > /_______  /|__|  \____/|__|  (____  /\___  / \___  > \____|__  /\___  >___  >____/|____/|___|  /__| /____  >
        \/     \/     \/     \/                       \/          \/      \/                  \/          \/                        \//_____/      \/          \/     \/    \/                 \/          \/ 
                                                                            
                                                                            By: Tamir Yehuda & Hai Vaknin
"@

}

   
   
   # Check for admin privleges on the local machine if installing az module is required
   Function Test-AdminPrivileges {
       <#
       .SYNOPSIS
       Checks if the script is being run with administrative privileges. If not, it issues a warning and stops execution.
       
       .DESCRIPTION
       This function is used to ensure that the script has administrative privileges before performing operations
       that require admin rights, such as installing modules.
   
       .EXAMPLE
       Test-AdminPrivileges
       # If the function does not stop the script, continue with admin-level operations.
       #>
   
       $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
       if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
           Write-Warning "[!] Please run the module installation as an Administrator!"
           Break
       }
   } 
   
   # check if Az PowerShell Module is Installed   
   Function Check-AzModuleInstall {
       <#
       .SYNOPSIS
       Checks for the presence of the Az PowerShell Module and prompts for installation if not found.
       
       .DESCRIPTION
       This function checks if the Azure PowerShell Module (Az) is installed. If it is not installed, it prompts
       the user whether they want to install it. If the user agrees, it then checks for admin privileges before
       proceeding with the installation.
   
       .EXAMPLE
       Check-AzModuleInstall
       # Prompts the user to install the Az module if it is not already installed.
       #>
       
       try
       {
           Get-InstalledModule -Name az -ErrorAction Stop | Out-Null
       }
       catch
       {
           Write-Host -ForegroundColor Yellow "[!] PowerShell az module is not installed. Do you want to installed it? (y/n)"
           $response = Read-Host
           if($response.ToLower() -eq "y")
           {
               Test-AdminPrivileges
               Install-Module az
           }
           else 
           {
               Write-Host -ForegroundColor Red "[-] Aborting..."
               break
           }
       }
   }
   
   # Function to find sensitive Azure Storage accounts that might be misconfigured or exposed
   function Find-SensitiveAzStorageAccounts {
       <#
       .SYNOPSIS
       Scans for and reports sensitive Azure Storage accounts, such as those used by Logic Apps, Function Apps, and Cloud Shell and can be susceptible to the attacke described in the article https://medium.com/@tamirye94/not-the-access-you-asked-for-how-azure-storage-account-read-write-permissions-can-be-abused-75311103430f.
   
       .DESCRIPTION
       This function checks for the installation of the Az module, ensures the user is logged into Azure, and then scans all
       accessible storage accounts to identify potentially sensitive or exposed configurations.
   
       .EXAMPLE
       Find-SensitiveAzStorageAccounts
       # Scans and reports on sensitive Azure Storage accounts.
       #>
       Print-Art
       Check-AzModuleInstall
       $token = (Get-AzAccessToken -Resource "https://management.azure.com" -ErrorAction SilentlyContinue).Token
       while ($null -eq $token)
       {
           Write-Host -ForegroundColor Yellow "[!] No active login. Prompting for login."
           Connect-AzAccount
           $token = (Get-AzAccessToken -Resource "https://management.azure.com" -ErrorAction SilentlyContinue).Token
       }
       $username = (Get-AzContext).Name
       $subscriptions = Get-AzSubscription
       $LogicAppStorageAccounts=@()
       $FunctionAppStorageAccounts=@()
       $CloudShellStorageAccounts=@()
   
       foreach ($subscription in $subscriptions)
       {
           Set-AzContext -Subscription $subscription.Id | Out-Null
           Write-Host -ForegroundColor Green "[+] Searching subscription: $($subscription.Name)"
           $storageAccounts = Get-AzStorageAccount 
           if($null -eq $storageAccounts) 
           {
               Write-Host -ForegroundColor Red "[-] $username doesn't have access to any Storage Account in the $($subscription.Name) subscription....."
               continue
           }
   
           foreach($SA in $storageAccounts)
           {
               $SAName = $SA.StorageAccountName
               $SARG = $SA.ResourceGroupName
               $SAContext = $SA.context
               $fileShares = Get-AzStorageShare -Context $SAContext
               if($null -ne $fileShares)
               {
                   Write-Host -ForegroundColor Yellow "[!] Checking $SAName storage account..."
                   foreach($fileShare in $fileShares)
                   {              
                       $shareName = $fileShare.Name
                       $directories = Get-AzStoragefile -ShareName $shareName -Context $SAContext -Path "site\wwwroot\" -ErrorAction SilentlyContinue | Get-AzStorageFile | where {$_.ListFileProperties.IsDirectory -eq $true}
   
                       if($null -ne $directories)
                       {
                           $logic = Get-AzStoragefile -ShareName $shareName -Context $SAContext -Path "site\wwwroot\$($directories[0].Name)" | Get-AzStorageFile | where {$_.Name -match "workflow.json"}
                           $function = Get-AzStoragefile -ShareName $shareName -Context $SAContext -Path "site\wwwroot\$($directories[0].Name)" | Get-AzStorageFile | where {$_.Name -match "run"}
                           if($null -ne $logic)
                           {
                               $LogicAppStorageAccounts += "[!] Storage Account Name: $SAName, Resource Group Name: $SARG, Subscription Name: $($subscription.Name)`n"
                           }
                           if($null -ne $function)
                           {
                               $FunctionAppStorageAccounts += "[!] Storage Account Name: $SAName, Resource Group Name: $SARG, Subscription Name: $($subscription.Name)`n"
                           }
   
                       } elseif($shareName -like "cs-*") {
                           $checkCloudShellUsername = $shareName -match '^cs-(.*?)-\d+'
                           $CloudShellStorageAccounts += "[!] Storage Account Name: $SAName, Resource Group Name: $SARG, Subscription Name: $($subscription.Name), Cloud Shell Username: $($matches[1])`n"
                       }
                   }
               }
           }
       }
       Write-Host -ForegroundColor Green "[+] Standard Logic App Storage Accounts:"
       Write-Host -ForegroundColor Yellow ($LogicAppStorageAccounts -join "")
       Write-Host -ForegroundColor Green "[+] Function App Storage Accounts:"
       Write-Host -ForegroundColor Yellow ($FunctionAppStorageAccounts -join "")
       Write-Host -ForegroundColor Green "[+] Cloud Shell Storage Accounts:"
       Write-Host -ForegroundColor Yellow ($CloudShellStorageAccounts -join "")
       Write-Host -ForegroundColor Green "[+] Done!"
   
   }