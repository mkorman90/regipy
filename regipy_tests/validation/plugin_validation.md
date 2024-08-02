
# Regipy plugin validation results

## Plugins with validation

| plugin_name                   | plugin_class_name               | test_case_name                                | success   |
|-------------------------------|---------------------------------|-----------------------------------------------|-----------|
| domain_sid                    | DomainSidPlugin                 | DomainSidPluginValidationCase                 | True      |
| background_activity_moderator | BAMPlugin                       | BamValidationCase                             | True      |
| usbstor_plugin                | USBSTORPlugin                   | USBSTORPluginValidationCase                   | True      |
| typed_urls                    | TypedUrlsPlugin                 | TypedUrlsPluginValidationCase                 | True      |
| user_assist                   | UserAssistPlugin                | NTUserUserAssistValidationCase                | True      |
| winrar_plugin                 | WinRARPlugin                    | WinRARPluginValidationCase                    | True      |
| ntuser_persistence            | NTUserPersistencePlugin         | NTUserPersistenceValidationCase               | True      |
| word_wheel_query              | WordWheelQueryPlugin            | WordWheelQueryPluginValidationCase            | True      |
| network_drives_plugin         | NetworkDrivesPlugin             | NetworkDrivesPluginValidationCase             | True      |
| software_classes_installer    | SoftwareClassesInstallerPlugin  | SoftwareClassesInstallerPluginValidationCase  | True      |
| print_demon_plugin            | PrintDemonPlugin                | PrintDemonPluginValidationCase                | True      |
| installed_programs_software   | InstalledProgramsSoftwarePlugin | InstalledProgramsSoftwarePluginValidationCase | True      |
| ras_tracing                   | RASTracingPlugin                | RASTracingPluginValidationCase                | True      |
| software_plugin               | SoftwarePersistencePlugin       | SoftwarePersistenceValidationCase             | True      |
| last_logon_plugin             | LastLogonPlugin                 | LastLogonPluginValidationCase                 | True      |
| uac_plugin                    | UACStatusPlugin                 | UACStatusPluginValidationCase                 | True      |
| profilelist_plugin            | ProfileListPlugin               | ProfileListPluginValidationCase               | True      |
| computer_name                 | ComputerNamePlugin              | ComputerNamePluginValidationCase              | True      |
| bootkey                       | BootKeyPlugin                   | BootKeyPluginValidationCase                   | True      |
| host_domain_name              | HostDomainNamePlugin            | HostDomainNamePluginValidationCase            | True      |
| wdigest                       | WDIGESTPlugin                   | WDIGESTPluginValidationCase                   | True      |
| shimcache                     | ShimCachePlugin                 | AmCacheValidationCase                         | True      |
| network_data                  | NetworkDataPlugin               | NetworkDataPluginValidationCase               | True      |
| ntuser_shellbag_plugin        | ShellBagNtuserPlugin            | ShellBagNtuserPluginValidationCase            | True      |
| typed_paths                   | TypedPathsPlugin                | TypedPathsPluginValidationCase                | True      |
| ntuser_classes_installer      | NtuserClassesInstallerPlugin    | NtuserClassesInstallerPluginValidationCase    | True      |
| winscp_saved_sessions         | WinSCPSavedSessionsPlugin       | WinSCPSavedSessionsPluginValidationCase       | True      |
| amcache                       | AmCachePlugin                   | AmCachePluginValidationCase                   | True      |
| local_sid                     | LocalSidPlugin                  | LocalSidPluginValidationCase                  | True      |
| usrclass_shellbag_plugin      | ShellBagUsrclassPlugin          | ShellBagUsrclassPluginValidationCase          | True      |
| boot_entry_list               | BootEntryListPlugin             | BootEntryListPluginValidationCase             | True      |
| services                      | ServicesPlugin                  | ServicesPluginValidationCase                  | True      |

## Plugins without validation
**Please note that in the future, this check will be enforced for all plugins**

| plugin_name                  | plugin_class_name             | test_case_name   | success   |
|------------------------------|-------------------------------|------------------|-----------|
| installed_programs_ntuser    | InstalledProgramsNTUserPlugin |                  | False     |
| timezone_data                | TimezoneDataPlugin            |                  | False     |
| active_control_set           | ActiveControlSetPlugin        |                  | False     |
| safeboot_configuration       | SafeBootConfigurationPlugin   |                  | False     |
| terminal_services_history    | TSClientPlugin                |                  | False     |
| routes                       | RoutesPlugin                  |                  | False     |
| image_file_execution_options | ImageFileExecutionOptions     |                  | False     |
    