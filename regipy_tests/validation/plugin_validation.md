
# Regipy plugin validation results

## Plugins with validation

| plugin_name                   | plugin_description                                                                | plugin_class_name               | test_case_name                                | success   |
|-------------------------------|-----------------------------------------------------------------------------------|---------------------------------|-----------------------------------------------|-----------|
| active_control_set            | Get information on SYSTEM hive control sets                                       | ActiveControlSetPlugin          | ActiveControlSetPluginValidationCase          | True      |
| amcache                       | Parse Amcache                                                                     | AmCachePlugin                   | AmCachePluginValidationCase                   | True      |
| background_activity_moderator | Get the computer name                                                             | BAMPlugin                       | BamValidationCase                             | True      |
| boot_entry_list               | List the Windows BCD boot entries                                                 | BootEntryListPlugin             | BootEntryListPluginValidationCase             | True      |
| bootkey                       | Get the Windows boot key                                                          | BootKeyPlugin                   | BootKeyPluginValidationCase                   | True      |
| computer_name                 | Get the computer name                                                             | ComputerNamePlugin              | ComputerNamePluginValidationCase              | True      |
| domain_sid                    | Get the machine domain name and SID                                               | DomainSidPlugin                 | DomainSidPluginValidationCase                 | True      |
| host_domain_name              | Get the computer host and domain names                                            | HostDomainNamePlugin            | HostDomainNamePluginValidationCase            | True      |
| installed_programs_software   | Retrieve list of installed programs and their install date from the SOFTWARE Hive | InstalledProgramsSoftwarePlugin | InstalledProgramsSoftwarePluginValidationCase | True      |
| last_logon_plugin             | Get the last logged on username                                                   | LastLogonPlugin                 | LastLogonPluginValidationCase                 | True      |
| local_sid                     | Get the machine local SID                                                         | LocalSidPlugin                  | LocalSidPluginValidationCase                  | True      |
| network_data                  | Get network data from many interfaces                                             | NetworkDataPlugin               | NetworkDataPluginValidationCase               | True      |
| network_drives_plugin         | Parse the user's mapped network drives                                            | NetworkDrivesPlugin             | NetworkDrivesPluginValidationCase             | True      |
| ntuser_classes_installer      | List of installed software from NTUSER hive                                       | NtuserClassesInstallerPlugin    | NtuserClassesInstallerPluginValidationCase    | True      |
| ntuser_persistence            | Retrieve values from known persistence subkeys in NTUSER hive                     | NTUserPersistencePlugin         | NTUserPersistenceValidationCase               | True      |
| ntuser_shellbag_plugin        | Parse NTUSER Shellbag items                                                       | ShellBagNtuserPlugin            | ShellBagNtuserPluginValidationCase            | True      |
| print_demon_plugin            | Get list of installed printer ports, as could be taken advantage by cve-2020-1048 | PrintDemonPlugin                | PrintDemonPluginValidationCase                | True      |
| profilelist_plugin            | Parses information about user profiles found in the ProfileList key               | ProfileListPlugin               | ProfileListPluginValidationCase               | True      |
| ras_tracing                   | Retrieve list of executables using ras                                            | RASTracingPlugin                | RASTracingPluginValidationCase                | True      |
| services                      | Enumerate the services in the SYSTEM hive                                         | ServicesPlugin                  | ServicesPluginValidationCase                  | True      |
| shimcache                     | Parse Shimcache artifact                                                          | ShimCachePlugin                 | AmCacheValidationCase                         | True      |
| software_classes_installer    | List of installed software from SOFTWARE hive                                     | SoftwareClassesInstallerPlugin  | SoftwareClassesInstallerPluginValidationCase  | True      |
| software_plugin               | Retrieve values from known persistence subkeys in Software hive                   | SoftwarePersistencePlugin       | SoftwarePersistenceValidationCase             | True      |
| typed_paths                   | Retrieve the typed Paths from the history                                         | TypedPathsPlugin                | TypedPathsPluginValidationCase                | True      |
| typed_urls                    | Retrieve the typed URLs from IE history                                           | TypedUrlsPlugin                 | TypedUrlsPluginValidationCase                 | True      |
| uac_plugin                    | Get the status of User Access Control                                             | UACStatusPlugin                 | UACStatusPluginValidationCase                 | True      |
| usbstor_plugin                | Parse the connected USB devices history                                           | USBSTORPlugin                   | USBSTORPluginValidationCase                   | True      |
| user_assist                   | Parse User Assist artifact                                                        | UserAssistPlugin                | NTUserUserAssistValidationCase                | True      |
| usrclass_shellbag_plugin      | Parse USRCLASS Shellbag items                                                     | ShellBagUsrclassPlugin          | ShellBagUsrclassPluginValidationCase          | True      |
| wdigest                       | Get WDIGEST configuration                                                         | WDIGESTPlugin                   | WDIGESTPluginValidationCase                   | True      |
| winrar_plugin                 | Parse the WinRAR archive history                                                  | WinRARPlugin                    | WinRARPluginValidationCase                    | True      |
| winscp_saved_sessions         | Retrieve list of WinSCP saved sessions                                            | WinSCPSavedSessionsPlugin       | WinSCPSavedSessionsPluginValidationCase       | True      |
| word_wheel_query              | Parse the word wheel query artifact                                               | WordWheelQueryPlugin            | WordWheelQueryPluginValidationCase            | True      |

## Plugins without validation
**Please note that in the future, this check will be enforced for all plugins**

| plugin_name                  | plugin_description                                                                       | plugin_class_name             | test_case_name   | success   |
|------------------------------|------------------------------------------------------------------------------------------|-------------------------------|------------------|-----------|
| backuprestore_plugin         | Gets the contents of the FilesNotToSnapshot, KeysNotToRestore, and FilesNotToBackup keys | BackupRestorePlugin           |                  | False     |
| codepage                     | Get codepage value                                                                       | CodepagePlugin                |                  | False     |
| crash_dump                   | Get crash control information                                                            | CrashDumpPlugin               |                  | False     |
| diag_sr                      | Get Diag\SystemRestore values and data                                                   | DiagSRPlugin                  |                  | False     |
| disable_last_access          | Get NTFSDisableLastAccessUpdate value                                                    | DisableLastAccessPlugin       |                  | False     |
| disablesr_plugin             | Gets the value that turns System Restore either on or off                                | DisableSRPlugin               |                  | False     |
| image_file_execution_options | Retrieve image file execution options - a persistence method                             | ImageFileExecutionOptions     |                  | False     |
| installed_programs_ntuser    | Retrieve list of installed programs and their install date from the NTUSER Hive          | InstalledProgramsNTUserPlugin |                  | False     |
| previous_winver_plugin       | Get previous relevant OS information                                                     | PreviousWinVersionPlugin      |                  | False     |
| processor_architecture       | Get processor architecture info from the System's environment key                        | ProcessorArchitecturePlugin   |                  | False     |
| routes                       | Get list of routes                                                                       | RoutesPlugin                  |                  | False     |
| safeboot_configuration       | Get safeboot configuration                                                               | SafeBootConfigurationPlugin   |                  | False     |
| shutdown                     | Get shutdown data                                                                        | ShutdownPlugin                |                  | False     |
| spp_clients_plugin           | Determines volumes monitored by VSS                                                      | SppClientsPlugin              |                  | False     |
| susclient_plugin             | Extracts SusClient* info, including HDD SN                                               | SusclientPlugin               |                  | False     |
| terminal_services_history    | Retrieve history of RDP connections                                                      | TSClientPlugin                |                  | False     |
| timezone_data                | Get timezone data                                                                        | TimezoneDataPlugin            |                  | False     |
| timezone_data2               | Get timezone data                                                                        | TimezoneDataPlugin2           |                  | False     |
| winver_plugin                | Get relevant OS information                                                              | WinVersionPlugin              |                  | False     |
    