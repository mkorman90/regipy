
# Regipy plugin validation results

## Plugins with validation

| plugin_name                   | plugin_description                                                                       | plugin_class_name               | test_case_name                                | success   |
|-------------------------------|------------------------------------------------------------------------------------------|---------------------------------|-----------------------------------------------|-----------|
| active_control_set            | Get information on SYSTEM hive control sets                                              | ActiveControlSetPlugin          | ActiveControlSetPluginValidationCase          | True      |
| amcache                       | Parse Amcache                                                                            | AmCachePlugin                   | AmCachePluginValidationCase                   | True      |
| app_paths                     | Parses application paths registry entries                                                | AppPathsPlugin                  | AppPathsPluginValidationCase                  | True      |
| background_activity_moderator | Get the computer name                                                                    | BAMPlugin                       | BamValidationCase                             | True      |
| backuprestore_plugin          | Gets the contents of the FilesNotToSnapshot, KeysNotToRestore, and FilesNotToBackup keys | BackupRestorePlugin             | BackupRestorePluginValidationCase             | True      |
| boot_entry_list               | List the Windows BCD boot entries                                                        | BootEntryListPlugin             | BootEntryListPluginValidationCase             | True      |
| bootkey                       | Get the Windows boot key                                                                 | BootKeyPlugin                   | BootKeyPluginValidationCase                   | True      |
| codepage                      | Get codepage value                                                                       | CodepagePlugin                  | CodepagePluginValidationCase                  | True      |
| computer_name                 | Get the computer name                                                                    | ComputerNamePlugin              | ComputerNamePluginValidationCase              | True      |
| crash_dump                    | Get crash control information                                                            | CrashDumpPlugin                 | CrashDumpPluginValidationCase                 | True      |
| diag_sr                       | Get Diag\SystemRestore values and data                                                   | DiagSRPlugin                    | DiagSRPluginValidationCase                    | True      |
| disable_last_access           | Get NTFSDisableLastAccessUpdate value                                                    | DisableLastAccessPlugin         | DisableLastAccessPluginValidationCase         | True      |
| disablesr_plugin              | Gets the value that turns System Restore either on or off                                | DisableSRPlugin                 | DisableSRPluginValidationCase                 | True      |
| domain_sid                    | Get the machine domain name and SID                                                      | DomainSidPlugin                 | DomainSidPluginValidationCase                 | True      |
| execution_policy              | Parses PowerShell and script execution policies                                          | ExecutionPolicyPlugin           | ExecutionPolicyPluginValidationCase           | True      |
| host_domain_name              | Get the computer host and domain names                                                   | HostDomainNamePlugin            | HostDomainNamePluginValidationCase            | True      |
| image_file_execution_options  | Retrieve image file execution options - a persistence method                             | ImageFileExecutionOptions       | ImageFileExecutionOptionsValidationCase       | True      |
| installed_programs_ntuser     | Retrieve list of installed programs and their install date from the NTUSER Hive          | InstalledProgramsNTUserPlugin   | InstalledProgramsNTUserPluginValidationCase   | True      |
| installed_programs_software   | Retrieve list of installed programs and their install date from the SOFTWARE Hive        | InstalledProgramsSoftwarePlugin | InstalledProgramsSoftwarePluginValidationCase | True      |
| last_logon_plugin             | Get the last logged on username                                                          | LastLogonPlugin                 | LastLogonPluginValidationCase                 | True      |
| local_sid                     | Get the machine local SID                                                                | LocalSidPlugin                  | LocalSidPluginValidationCase                  | True      |
| lsa_packages                  | Parses LSA security packages configuration                                               | LSAPackagesPlugin               | LSAPackagesPluginValidationCase               | True      |
| mounted_devices               | Parses mounted device information                                                        | MountedDevicesPlugin            | MountedDevicesPluginValidationCase            | True      |
| network_data                  | Get network data from many interfaces                                                    | NetworkDataPlugin               | NetworkDataPluginValidationCase               | True      |
| network_drives_plugin         | Parse the user's mapped network drives                                                   | NetworkDrivesPlugin             | NetworkDrivesPluginValidationCase             | True      |
| networklist                   | Parses network connection history                                                        | NetworkListPlugin               | NetworkListPluginValidationCase               | True      |
| ntuser_classes_installer      | List of installed software from NTUSER hive                                              | NtuserClassesInstallerPlugin    | NtuserClassesInstallerPluginValidationCase    | True      |
| ntuser_persistence            | Retrieve values from known persistence subkeys in NTUSER hive                            | NTUserPersistencePlugin         | NTUserPersistenceValidationCase               | True      |
| ntuser_shellbag_plugin        | Parse NTUSER Shellbag items                                                              | ShellBagNtuserPlugin            | ShellBagNtuserPluginValidationCase            | True      |
| pagefile                      | Parses pagefile configuration                                                            | PagefilePlugin                  | PagefilePluginValidationCase                  | True      |
| previous_winver_plugin        | Get previous relevant OS information                                                     | PreviousWinVersionPlugin        | PreviousWinVersionPluginValidationCase        | True      |
| print_demon_plugin            | Get list of installed printer ports, as could be taken advantage by cve-2020-1048        | PrintDemonPlugin                | PrintDemonPluginValidationCase                | True      |
| processor_architecture        | Get processor architecture info from the System's environment key                        | ProcessorArchitecturePlugin     | ProcessorArchitecturePluginValidationCase     | True      |
| profilelist_plugin            | Parses information about user profiles found in the ProfileList key                      | ProfileListPlugin               | ProfileListPluginValidationCase               | True      |
| ras_tracing                   | Retrieve list of executables using ras                                                   | RASTracingPlugin                | RASTracingPluginValidationCase                | True      |
| routes                        | Get list of routes                                                                       | RoutesPlugin                    | RoutesPluginValidationCase                    | True      |
| safeboot_configuration        | Get safeboot configuration                                                               | SafeBootConfigurationPlugin     | SafeBootConfigurationPluginValidationCase     | True      |
| samparse                      | Parses user accounts from SAM hive                                                       | SAMParsePlugin                  | SAMParsePluginValidationCase                  | True      |
| services                      | Enumerate the services in the SYSTEM hive                                                | ServicesPlugin                  | ServicesPluginValidationCase                  | True      |
| shimcache                     | Parse Shimcache artifact                                                                 | ShimCachePlugin                 | AmCacheValidationCase                         | True      |
| shutdown                      | Get shutdown data                                                                        | ShutdownPlugin                  | ShutdownPluginValidationCase                  | True      |
| software_classes_installer    | List of installed software from SOFTWARE hive                                            | SoftwareClassesInstallerPlugin  | SoftwareClassesInstallerPluginValidationCase  | True      |
| software_plugin               | Retrieve values from known persistence subkeys in Software hive                          | SoftwarePersistencePlugin       | SoftwarePersistenceValidationCase             | True      |
| spp_clients_plugin            | Determines volumes monitored by VSS                                                      | SppClientsPlugin                | SppClientsPluginValidationCase                | True      |
| susclient_plugin              | Extracts SusClient* info, including HDD SN                                               | SusclientPlugin                 | SusclientPluginValidationCase                 | True      |
| terminal_services_history     | Retrieve history of RDP connections                                                      | TSClientPlugin                  | TSClientPluginValidationCase                  | True      |
| timezone_data                 | Get timezone data                                                                        | TimezoneDataPlugin              | TimezoneDataPluginValidationCase              | True      |
| timezone_data2                | Get timezone data                                                                        | TimezoneDataPlugin2             | TimezoneDataPlugin2ValidationCase             | True      |
| typed_paths                   | Retrieve the typed Paths from the history                                                | TypedPathsPlugin                | TypedPathsPluginValidationCase                | True      |
| typed_urls                    | Retrieve the typed URLs from IE history                                                  | TypedUrlsPlugin                 | TypedUrlsPluginValidationCase                 | True      |
| uac_plugin                    | Get the status of User Access Control                                                    | UACStatusPlugin                 | UACStatusPluginValidationCase                 | True      |
| usb_devices                   | Parses USB device connection history                                                     | USBDevicesPlugin                | USBDevicesPluginValidationCase                | True      |
| usbstor_plugin                | Parse the connected USB devices history                                                  | USBSTORPlugin                   | USBSTORPluginValidationCase                   | True      |
| user_assist                   | Parse User Assist artifact                                                               | UserAssistPlugin                | NTUserUserAssistValidationCase                | True      |
| usrclass_shellbag_plugin      | Parse USRCLASS Shellbag items                                                            | ShellBagUsrclassPlugin          | ShellBagUsrclassPluginValidationCase          | True      |
| wdigest                       | Get WDIGEST configuration                                                                | WDIGESTPlugin                   | WDIGESTPluginValidationCase                   | True      |
| windows_defender              | Parses Windows Defender configuration and exclusions                                     | WindowsDefenderPlugin           | WindowsDefenderPluginValidationCase           | True      |
| winrar_plugin                 | Parse the WinRAR archive history                                                         | WinRARPlugin                    | WinRARPluginValidationCase                    | True      |
| winscp_saved_sessions         | Retrieve list of WinSCP saved sessions                                                   | WinSCPSavedSessionsPlugin       | WinSCPSavedSessionsPluginValidationCase       | True      |
| winver_plugin                 | Get relevant OS information                                                              | WinVersionPlugin                | WinVersionPluginValidationCase                | True      |
| word_wheel_query              | Parse the word wheel query artifact                                                      | WordWheelQueryPlugin            | WordWheelQueryPluginValidationCase            | True      |
| wsl                           | Get WSL information                                                                      | WSLPlugin                       | WSLPluginValidationCase                       | True      |

## Plugins without validation
**Starting regipy v6.1.0 - plugins without validation are excluded by default.** Use `--include-unvalidated` flag in CLI or `include_unvalidated=True` in `run_relevant_plugins()` to include them.

The validation state is stored in `regipy/plugins/validation_status.py` in the `VALIDATED_PLUGINS` set. Plugins not in this set are considered unvalidated and may return incomplete or inaccurate data.

| plugin_name         | plugin_description                                | plugin_class_name       | test_case_name   | success   |
|---------------------|---------------------------------------------------|-------------------------|------------------|-----------|
| appcert_dlls        | Parses AppCertDLLs persistence entries            | AppCertDLLsPlugin       |                  | False     |
| appcompat_flags     | Parses application compatibility flags and layers | AppCompatFlagsPlugin    |                  | False     |
| appinit_dlls        | Parses AppInit_DLLs persistence entries           | AppInitDLLsPlugin       |                  | False     |
| appkeys             | Parses application keyboard shortcuts             | AppKeysPlugin           |                  | False     |
| comdlg32            | Parses Open/Save dialog MRU lists                 | ComDlg32Plugin          |                  | False     |
| muicache            | Parses MUI Cache (application display names)      | MUICachePlugin          |                  | False     |
| pending_file_rename | Parses pending file rename operations             | PendingFileRenamePlugin |                  | False     |
| powershell_logging  | Parses PowerShell logging and execution policy    | PowerShellLoggingPlugin |                  | False     |
| putty               | Parses PuTTY sessions and SSH host keys           | PuTTYPlugin             |                  | False     |
| recentdocs          | Parses recently opened documents                  | RecentDocsPlugin        |                  | False     |
| runmru              | Parses Run dialog MRU list                        | RunMRUPlugin            |                  | False     |
| shares              | Parses network share configuration                | SharesPlugin            |                  | False     |
| sysinternals        | Parses Sysinternals tools EULA acceptance         | SysinternalsPlugin      |                  | False     |
    