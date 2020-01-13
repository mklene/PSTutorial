#requires -version 2

<#
.SYNOPSIS
    
    Script automates deployment of multiple vms loaded from pre-defined .csv file 

.DESCRIPTION

    Script reads input from .csv file (that needs to be saved in script's working directory, under the name of "vms2deploy.csv")
    Script will return an error if the file is not found in working directory.
    After rudimentary input sanitization (removing lines with empty fields) a separate background job (process) is started for
    each unique host cluster found in input. 
    The scriptblock that defines background job takes care of asynchronous creation of requested VMs (clone from template). 
    To not overload the cluster number of VMs being deployed at any given moment is smaller than number of active vmhosts in cluster. 
    After VM is deployed scriptblock powers it on to start OS Customization process.
    Last part of deploy scriptblock is to search vCenter events for successful or failed customization completions.
    Background job exits when all powered on VMs completed OS Customization (no matter successfully or not) or when pre-defined 
    time-out elapses.

.PARAMETER vCenterServer

    Mandatory parameter indicating vCenter server to connect to (FQDN or IP address)
   
.EXAMPLE

    ultimate_deploy.ps1 -vCenterServer vcenter.seba.local
    
    vCenter Server indicated as FQDN
    
.EXAMPLE

    ultimate_deploy.ps1 -vcenter 10.0.0.1
    
    vCenter Server indicated as IP address   
    
.EXAMPLE

    ultimate_deploy.ps1
    
    Script will interactively ask for mandatory vCenterServer parameter
 
#>

[CmdletBinding()]
Param(
   [Parameter(Mandatory=$True,Position=1)]
   [ValidateNotNullOrEmpty()]
   [string]$vCenterServer
)


Function Write-And-Log {

[CmdletBinding()]
Param(
   [Parameter(Mandatory=$True,Position=1)]
   [ValidateNotNullOrEmpty()]
   [string]$LogFile,
	
   [Parameter(Mandatory=$True,Position=2)]
   [ValidateNotNullOrEmpty()]
   [string]$line,

   [Parameter(Mandatory=$False,Position=3)]
   [int]$Severity=0,

   [Parameter(Mandatory=$False,Position=4)]
   [string]$type="terse"

   
)

$timestamp = (Get-Date -Format ("[yyyy-MM-dd HH:mm:ss] "))
$ui = (Get-Host).UI.RawUI

switch ($Severity) {

        {$_ -gt 0} {$ui.ForegroundColor = "red"; $type ="full"; $LogEntry = $timestamp + ":Error: " + $line; break;}
        {$_ -eq 0} {$ui.ForegroundColor = "green"; $LogEntry = $timestamp + ":Info: " + $line; break;}
        {$_ -lt 0} {$ui.ForegroundColor = "yellow"; $LogEntry = $timestamp + ":Warning: " + $line; break;}

}
switch ($type) {
   
        "terse"   {Write-Output $LogEntry; break;}
        "full"    {Write-Output $LogEntry; $LogEntry | Out-file $LogFile -Append; break;}
        "logonly" {$LogEntry | Out-file $LogFile -Append; break;}
     
}

$ui.ForegroundColor = "white" 

}

#a scary scriptblock to feed background jobs
$deployscriptblock = {
				param($vCS, $cred, $vms, $log, $progress)
				
				#simple helper object to track job progress, we will dump it to $clustername-progres.csv for the parent process to read every minute
				$job_progress = New-Object PSObject
				
				$job_progress | Add-Member -Name "PWROK" -Value 0 -MemberType NoteProperty
				$job_progress | Add-Member -Name "PWRFAIL" -Value 0 -MemberType NoteProperty
                $job_progress | Add-Member -Name "DPLFAIL" -Value 0 -MemberType NoteProperty
				$job_progress | Add-Member -Name "CUSTSTART" -Value 0 -MemberType NoteProperty
				$job_progress | Add-Member -Name "CUSTOK" -Value 0 -MemberType NoteProperty
				$job_progress | Add-Member -Name "CUSTFAIL" -Value 0 -MemberType NoteProperty
				$job_progress | Export-Csv -Path $progress -NoTypeInformation
				
				#scriptblock is started as separate PS (not PowerCLI!), completely autonomous process, so we really need to load the snap-in
				$vmsnapin = Get-PSSnapin VMware.VimAutomation.Core -ErrorAction SilentlyContinue
				$Error.Clear()
				if ($vmsnapin -eq $null){
					Add-PSSnapin VMware.VimAutomation.Core 
					if ($error.Count -ne 0){
						(Get-Date -Format ("[yyyy-MM-dd HH:mm:ss] ")) + "Error: Loading PowerCLI" | out-file $log -Append
						exit
					}
				}
				
				#and connect vCenter
				connect-viserver -server $vCS -Credential $cred 2>&1 | out-null
				if ($error.Count -eq 0){
					(Get-Date -Format ("[yyyy-MM-dd HH:mm:ss] ")) + ":Info: vCenter $vCS successfully connected" | out-file $log -Append
					
					#array to store cloned OS customizations that we need to clean-up once script finishes
					$cloned_2b_cleaned = @()
					#hash table to store new-vm async tasks
					$newvm_tasks = @{}
					
					#this is needed as timestamp for searching the logs for customization events at the end of this scriptblock
					$start_events = get-date
					$started_vms = @()
                    
					#array of customization status values and a timeout for customization in seconds (it is exactly 2hrs, feel free to reduce it)
					$Customization_In_Progress = @("CustomizationNotStarted", "CustomizationStarted")
					[int]$timeout_sec = 7200
					
					#after we sanitized input, something must be there
					$total_vms = $vms.count
					
                    #so I'm not afraid to reach for element [0] of this array
					$vmhosts = get-vmhost -location $vms[0].cluster -state "connected"
					
					$total_hosts = $vmhosts.count
					$batch = 0
					
                    #split vms to batches for deployment, each batch has $total_hosts concurrent deployments (so a single host deploys only one vm at a time)
					while ($batch -lt $total_vms){ #scan array until we run out of vms to deploy
							$index =0 
							while ($index -lt $total_hosts){ #in batches equal to number of available hosts
								if ($vms[($batch + $index)].name) { #check if end of array
									if (!(get-vm $vms[($batch + $index)].name -erroraction 0)){ #check if vm name is already taken
										
										#if "none" detected as IP address, we do not set it via OSCustomizationSpec, whatever is in template will be inherited (hopefully DHCP)
                                        if ($vms[($batch + $index)].ip -match "none"){
											(Get-Date -Format ("[yyyy-MM-dd HH:mm:ss] ")) + ":Info: No IP config for $($vms[($batch + $index)].name) deploying with DHCP!" | out-file $log -Append
											(Get-Date -Format ("[yyyy-MM-dd HH:mm:ss] ")) + ":Info: Starting async deployment for $($vms[($batch + $index)].name)" | out-file $log -Append
											$newvm_tasks[(new-vm -name $($vms[($batch + $index)].name) -template $(get-template -name $($vms[($batch + $index)].template)) -vmhost $vmhosts[$index] -oscustomizationspec $(get-oscustomizationspec -name $($vms[($batch + $index)].oscust)) -datastore $(get-datastorecluster -name $($vms[($batch + $index)].datastorecluster)) -diskstorageformat thin -location $(get-folder -name $($vms[($batch + $index)].folder)) -RunAsync -ErrorAction SilentlyContinue).id] = $($vms[($batch + $index)].name)
                                            #catch new-vm errors - if any
                                            if ($error.count) {
                                                $error[0].exception | out-file $log -Append
                                                $job_progress.DPLFAIL++
                                                $error.clear()
                                            }
																							
										}
										else {
											#clone the "master" OS Customization Spec, then use it to apply vm specific IP configuration (for 1st vNIC ONLY!)
											(Get-Date -Format ("[yyyy-MM-dd HH:mm:ss] ")) + ":Info: Cloning OS customization for $($vms[($batch + $index)].name)" | out-file $log -Append
											$cloned_oscust = Get-OSCustomizationSpec $vms[($batch + $index)].oscust | New-OSCustomizationSpec -name "$($vms[($batch + $index)].oscust)_$($vms[($batch + $index)].name)"
											
											#for Linux systems you can not set DNS via OS Customization Spec, so set it to "none"
											if ($vms[($batch + $index)].dns1 -match "none") {
												Set-OSCustomizationNicMapping -OSCustomizationNicMapping ($cloned_oscust | Get-OscustomizationNicMapping) -Position 1 -IpMode UseStaticIp -IpAddress $vms[($batch + $index)].ip -SubnetMask $vms[($batch + $index)].mask -DefaultGateway $vms[($batch + $index)].gw | Out-Null
											}
											else {
												Set-OSCustomizationNicMapping -OSCustomizationNicMapping ($cloned_oscust | Get-OscustomizationNicMapping) -Position 1 -IpMode UseStaticIp -IpAddress $vms[($batch + $index)].ip -SubnetMask $vms[($batch + $index)].mask -DefaultGateway $vms[($batch + $index)].gw -Dns $vms[($batch + $index)].dns1,$vms[($batch + $index)].dns2 | Out-Null
											}
											
                                            #we need to keep track of these cloned OSCustomizationSpecs for the clean-up before we exit
											$cloned_2b_cleaned += $cloned_oscust
											(Get-Date -Format ("[yyyy-MM-dd HH:mm:ss] ")) + ":Info: Starting async deployment for $($vms[($batch + $index)].name)" | out-file $log -Append
											$newvm_tasks[(new-vm -name $($vms[($batch + $index)].name) -template $(get-template -name $($vms[($batch + $index)].template)) -vmhost $vmhosts[$index] -oscustomizationspec $cloned_oscust -datastore $(get-datastorecluster -name $($vms[($batch + $index)].datastorecluster)) -diskstorageformat thin -location $(get-folder -name $($vms[($batch + $index)].folder)) -RunAsync -ErrorAction SilentlyContinue).id] = $($vms[($batch + $index)].name)
                                            #catch new-vm errors - if any
                                            if ($error.count) {
                                                $error[0].exception | out-file $log -Append
                                                $job_progress.DPLFAIL++
                                                $error.clear()
                                            }
										}
									}
									else { 
										(Get-Date -Format ("[yyyy-MM-dd HH:mm:ss] ")) + ":Error: VM $($vms[($batch + $index)].name) already exists! Skipping" | out-file $log -Append
									}
									$index++
								}
								else {
									$index = $total_hosts #end of array, no point in looping.
								}
							}
							
                            #track the progress of async tasks
							$running_tasks = $newvm_tasks.count
							#exit #debug
							while($running_tasks -gt 0){
									$Error.clear()
									get-task | %{
										if ($newvm_tasks.ContainsKey($_.id)){ #check if deployment of this VM has been initiated above
										
											if($_.State -eq "Success"){ #if deployment successful - power on!
												(Get-Date -Format ("[yyyy-MM-dd HH:mm:ss] ")) + ":Info: $($newvm_tasks[$_.id]) deployed! Powering on" | out-file $log -Append
												$started_vms += (Get-VM -name $newvm_tasks[$_.id] | Start-VM -confirm:$false -ErrorAction SilentlyContinue)
												if ($error.count) { $job_progress.PWRFAIL++ }
												else {$job_progress.PWROK++}
												$newvm_tasks.Remove($_.id) #and remove task from hash table 
												$running_tasks--
											}
											elseif($_.State -eq "Error"){ #if deployment failed - only report it and remove task from hash table
												(Get-Date -Format ("[yyyy-MM-dd HH:mm:ss] ")) + ":Error: $($newvm_tasks[$_.id]) NOT deployed! Skipping" | out-file $log -Append
												$newvm_tasks.Remove($_.id)
												$job_progress.PWRFAIL++
												$running_tasks--
											}
										}
																			
									}
								#and write it down for parent process to display
                                $job_progress | Export-Csv -Path $progress -NoTypeInformation
								Start-Sleep -Seconds 10	
								}	
							$batch += $total_hosts #skip to next batch
					}
					
					Start-Sleep -Seconds 10
					
					#this is where real rock'n'roll starts, searching for customization events
					
					#there is a chance, not all vms power-on successfully
					$started_vms = $started_vms | where-object { $_.PowerState -eq "PoweredOn"}
					
					#but if they are
					if ($started_vms){
						#first - initialize helper objects to track customization, we assume customization has not started for any of successfully powered-on vms
						#exit #debug
						$vm_descriptors = New-Object System.Collections.ArrayList
						foreach ($vm in $started_vms){
								$obj = "" | select VM,CustomizationStatus,StartVMEvent 
								$obj.VM = $vm
								$obj.CustomizationStatus = "CustomizationNotStarted"
								$obj.StartVMEvent = Get-VIEvent -Entity $vm -Start $start_events | where { $_ -is "VMware.Vim.VmStartingEvent" } | Sort-object CreatedTime | Select -Last 1 
								[void]($vm_descriptors.Add($obj))
						}
					
						#timeout from here
						$start_timeout = get-date
						#now that's real mayhem - scriptblock inside scriptblock
						$continue = {
								#we check if there are any VMs left with customization in progress and if we didn't run out of time
								$vms_in_progress = $vm_descriptors | where-object { $Customization_In_Progress -contains $_.CustomizationStatus }
								$now = get-date
								$elapsed = $now - $start_timeout
								$no_timeout = ($elapsed.TotalSeconds -lt $timeout_sec)
								if (!($no_timeout) ){
									(Get-Date -Format ("[yyyy-MM-dd HH:mm:ss] ")) + ":Error: Timeout waiting for customization! Manual cleanup required! Exiting..." | out-file $log -Append
								}
								return ( ($vms_in_progress -ne $null) -and ($no_timeout)) #return $true or $false to control "while loop" below
						}
					
						#loop searching for events
						while (& $continue){
								foreach ($vmItem in $vm_descriptors){
									$vmName = $vmItem.VM.name
									switch ($vmItem.CustomizationStatus) {
								    
                                    #for every VM filter "Customization Started" events from the moment it was last powered-on
										"CustomizationNotStarted" {
											$vmEvents = Get-VIEvent -Entity $vmItem.VM -Start $vmItem.StartVMEvent.CreatedTime 
											$startEvent = $vmEvents | where { $_ -is "VMware.Vim.CustomizationStartedEvent"} 
											if ($startEvent) { 
												$vmItem.CustomizationStatus = "CustomizationStarted" 
												$job_progress.CUSTSTART++
												(Get-Date -Format ("[yyyy-MM-dd HH:mm:ss] ")) + ":Info: OS Customization for $vmName started at $($startEvent.CreatedTime)" | out-file $log -Append
											}
									
										break;} 
								
										#pretty much same here, just searching for customization success / failure)
										"CustomizationStarted" {
											$vmEvents = Get-VIEvent -Entity $vmItem.VM -Start $vmItem.StartVMEvent.CreatedTime 
											$succeedEvent = $vmEvents | where { $_ -is "VMware.Vim.CustomizationSucceeded" } 
											$failedEvent = $vmEvents | where { $_ -is "VMware.Vim.CustomizationFailed"} 
											if ($succeedEvent) { 
												$vmItem.CustomizationStatus = "CustomizationSucceeded"
												$job_progress.CUSTOK++
												(Get-Date -Format ("[yyyy-MM-dd HH:mm:ss] ")) + ":Info: OS Customization for $vmName completed at $($succeedEvent.CreatedTime)" | out-file $log -Append
											} 
											if ($failedEvent) { 
												$vmItem.CustomizationStatus = "CustomizationFailed" 
												$job_progress.CUSTFAIL++
												(Get-Date -Format ("[yyyy-MM-dd HH:mm:ss] ")) + ":Error: OS Customization for $vmName failed at $($failedEvent.CreatedTime)" | out-file $log -Append 
											} 
									
										break;} 
								
									}
								}
							$job_progress | Export-Csv -Path $progress -NoTypeInformation
							Start-Sleep -Seconds 10	
						}
					}
                    #we've got no loose ends at the moment (well, except for timeouts but... tough luck)
					(Get-Date -Format ("[yyyy-MM-dd HH:mm:ss] ")) + ":Info: Cleaning-up cloned OS customizations" | out-file $log -Append
					$cloned_2b_cleaned | Remove-OSCustomizationSpec -Confirm:$false
					
				}
				else{
					(Get-Date -Format ("[yyyy-MM-dd HH:mm:ss] ")) + ":Error: vCenter $vCS connection failure" | out-file $log -Append
				}
						
}

#constans

#variables
$ScriptRoot = Split-Path $MyInvocation.MyCommand.Path
$StartTime = Get-Date -Format "yyyyMMddHHmmss_"
$csvfile = $ScriptRoot + "\" + "vms2deploy.csv"
$logdir = $ScriptRoot + "\UltimateDeployLogs\"
$transcriptfilename = $logdir + $StartTime + "ultimate-deploy_Transcript.log"
$logfilename = $logdir + $StartTime + "ultimate-deploy.log"

#initializing maaaany counters
[int]$total_vms = 0 
[int]$processed_vms = 0
[int]$total_clusters = 0
[int]$total_errors = 0
[int]$total_dplfail = 0
[int]$total_pwrok = 0
[int]$total_pwrfail = 0
[int]$total_custstart = 0
[int]$total_custok = 0
[int]$total_custfail = 0

#test for log directory, create if needed
if ( -not (Test-Path $logdir)) {
			New-Item -type directory -path $logdir | out-null
}

#start PowerShell transcript
#Start-Transcript -Path $transcriptfilename

#load PowerCLI snap-in
$vmsnapin = Get-PSSnapin VMware.VimAutomation.Core -ErrorAction SilentlyContinue
$Error.Clear()
if ($vmsnapin -eq $null) {
	Add-PSSnapin VMware.VimAutomation.Core
	if ($error.Count -eq 0) {
		write-and-log $logfilename "PowerCLI VimAutomation.Core Snap-in was successfully enabled." 0 "terse"
	}
	else{
		write-and-log $logfilename "Could not enable PowerCLI VimAutomation.Core Snap-in, exiting script" 1 "terse"
		Exit
	}
}
else{
	write-and-log $logfilename "PowerCLI VimAutomation.Core Snap-in is already enabled" 0 "terse"
}

if ($true) {#if ($env:Processor_Architecture -eq "x86") { #32-bit is required for OS Customization Spec related cmdlets
	
	if (($vmsnapin.Version.Major -gt 5) -or (($vmsnapin.version.major -eq 5) -and ($vmsnapin.version.minor -ge 5))) { #check PowerCLI version
			
		#assume everything is OK at this point
		$Error.Clear()
	
		#sanitize input a little
		$vms2deploy = Import-Csv -Path $csvfile
		$vms2deploy = $vms2deploy | where-object {($_.name -ne "") -and ($_.template -ne "") -and ($_.oscust -ne "") -and ($_.cluster -ne "")} | sort-object name -unique
		$total_vms = $vms2deploy.count
	
		#anything still there - let's deploy!
		if ($vms2deploy) {
			
			#we will start one background job per unique cluster listed in .csv file
			$host_clusters = $vms2deploy | sort-object cluster -unique | select-object cluster
			$total_clusters = $host_clusters.count
		
			#connect vCenter from parameter, we need to save credentials, to pass them to background jobs later on
			$credentials = $Host.UI.PromptForCredential("vCenter authentication dialog","Please provide credentials for $vCenterServer", "", "")
			Connect-VIServer -Server $vCenterServer -Credential $credentials -ErrorAction SilentlyContinue | Out-Null

			#execute only if connection successful
			if ($error.Count -eq 0){
	    
				#use previously defined function to inform what is going on, anything else than "terse" will cause the message to be written both in logfile and to screen
				Write-And-Log $logfilename "vCenter $vCenterServer successfully connected" $error.count "terse"
						
				#measuring execution time is really hip these days
				$stop_watch = [Diagnostics.Stopwatch]::StartNew()
			
				#fire a background job for each unique cluster
                foreach ($cluster in $host_clusters) {
						$vms_in_cluster = $vms2deploy | where-object { $_.cluster -eq $cluster.cluster }
						$logfile = $logdir + $StartTime + $cluster.cluster + "-DeployJob.log"
						$progressfile = $logdir + $cluster.cluster + "-progress.csv"
						Write-And-Log $logfilename "Dispatching background deployment job for cluster $($cluster.cluster)" 0 "full"
						$jobs_tab += @{ $cluster.cluster = start-job -name $cluster.cluster -scriptblock $deployscriptblock -argumentlist $vCenterServer, $credentials, $vms_in_cluster, $logfile, $progressfile }
				}
				
                #track the job progress + "ornaments"
				do{
					#do not repeat too often
					Start-Sleep -Seconds 20
                    Write-And-Log $logfilename "Pooling background deployment jobs" -1
					$running_jobs = 0
                    $total_pwrok = 0
                    $total_dplfail = 0
					$total_pwrfail = 0
					$total_custstart = 0
					$total_custok = 0
					$total_custfail = 0

					foreach ($cluster in $host_clusters){
						if ($($jobs_tab.Get_Item($cluster.cluster)).state -eq "running") {
							$running_jobs++
						}
										
						$progressfile = $logdir +$cluster.cluster + "-progress.csv"
						$jobs_progress = Import-Csv -Path $progressfile
						$total_pwrok += $jobs_progress.PWROK
                        $total_dplfail += $jobs_progress.DPLFAIL
						$total_pwrfail += $jobs_progress.PWRFAIL
						$total_custstart += $jobs_progress.CUSTSTART
						$total_custok += $jobs_progress.CUSTOK
						$total_custfail += $jobs_progress.CUSTFAIL
					}
					
					#display different progress bar depending on stage we are at (if any customization started, show customization progress, in this way we always show "worst case" progress)
					if ($total_custstart){
						$processed_vms = $total_custok + $total_custfail
						write-progress -Activity "$running_jobs background deployment jobs in progress" -Status "Percent complete $("{0:N2}" -f (($processed_vms / $total_pwrok) * 100))%" -PercentComplete (($processed_vms / $total_vms) * 100) -CurrentOperation "VM OS customization in progress"
					}
					else {
						$processed_vms = $total_pwrok + $total_pwrfail + $total_dplfail
						write-progress -Activity "$running_jobs background deployment jobs in progress" -Status "Percent complete $("{0:N2}" -f (($processed_vms / $total_vms) * 100))%" -PercentComplete (($processed_vms / $total_vms) * 100) -CurrentOperation "VM deployment in progress"
					}
										
					Write-And-Log $logfilename "Out of total $total_vms VM deploy requests there are $total_pwrok VMs successfully powered on, $($total_pwrfail + $total_dplfail) failed." $($total_pwrfail + $total_dplfail) "full"
					Write-And-Log $logfilename "Out of total $total_pwrok successfully powered on VMs OS Customization has started for $total_custstart VMs, succeeded for $total_custok VMs, failed for $total_custfail." $total_custfail "full"
					
                    
				#until we are out of active jobs
                } until ($running_jobs -eq 0)
				
				#time!
				$stop_watch.Stop()
				$elapsed_seconds = ($stop_watch.elapsedmilliseconds)/1000
				$total_errors = $total_pwrfail + $total_custfail + $total_dplfail
				
                #farewell message before disconnect
				Write-And-Log $logfilename "Out of total $total_vms VM deploy requests $total_pwrok VMs were successfully powered on, $($total_pwrfail + $total_dplfail) failed, $($total_vms - $total_pwrok - $total_pwrfail - $total_dplfail) duplicate VM names were detected (not deployed)." $($total_pwrfail + $total_dplfail) "full"
				Write-And-Log $logfilename "Out of total $total_pwrok successfully powered on VMs OS Customization has been successful for $total_custok VMs, failed for $total_custfail." $total_custfail "full"
				Write-And-Log $logfilename "$($host_clusters.count) background deployment jobs completed in $("{0:N2}" -f $elapsed_seconds)s, $total_errors ERRORs reported, exiting." $total_errors "full"	

				#disconnect vCenter
				Disconnect-VIServer -Server $vCenterServer -Confirm:$false -Force:$true
			}
			else{
			Write-And-Log $logfilename "Error connecting vCenter server $vCenterServer, exiting" $error.count "full"
			}
		}
		else {
			Write-And-Log $logfilename "Invalid input in $csvfile file, exiting" 1 "full"
		}
	}	
	else {
		write-and-log $logfilename "This script requires PowerCLI 5.5 or greater to run properly" 1 "full"
	}
}
else {
	write-and-log $logfilename "This script should be run from 32-bit version of PowerCLI only, Open 32-bit PowerCLI window and start again" 1 "full"
}

#Stop-Transcript