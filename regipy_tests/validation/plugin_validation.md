
# Regipy plugin validation results

## Plugins with validation

| plugin_name                   | plugin_class_name               | test_case_name                                | success   |
|-------------------------------|---------------------------------|-----------------------------------------------|-----------|
| network_data                  | NetworkDataPlugin               | NetworkDataPluginValidationCase               | True      |
| bootkey                       | BootKeyPlugin                   | BootKeyPluginValidationCase                   | True      |
| wdigest                       | WDIGESTPlugin                   | WDIGESTPluginValidationCase                   | True      |
| host_domain_name              | HostDomainNamePlugin            | HostDomainNamePluginValidationCase            | True      |
| computer_name                 | ComputerNamePlugin              | ComputerNamePluginValidationCase              | True      |
| shimcache                     | ShimCachePlugin                 | AmCacheValidationCase                         | True      |
| services                      | ServicesPlugin                  | ServicesPluginValidationCase                  | True      |
| software_classes_installer    | SoftwareClassesInstallerPlugin  | SoftwareClassesInstallerPluginValidationCase  | True      |
| ras_tracing                   | RASTracingPlugin                | RASTracingPluginValidationCase                | True      |
| software_plugin               | SoftwarePersistencePlugin       | SoftwarePersistenceValidationCase             | True      |
| last_logon_plugin             | LastLogonPlugin                 | LastLogonPluginValidationCase                 | True      |
| uac_plugin                    | UACStatusPlugin                 | UACStatusPluginValidationCase                 | True      |
| profilelist_plugin            | ProfileListPlugin               | ProfileListPluginValidationCase               | True      |
| print_demon_plugin            | PrintDemonPlugin                | PrintDemonPluginValidationCase                | True      |
| installed_programs_software   | InstalledProgramsSoftwarePlugin | InstalledProgramsSoftwarePluginValidationCase | True      |
| winscp_saved_sessions         | WinSCPSavedSessionsPlugin       | WinSCPSavedSessionsPluginValidationCase       | True      |
| ntuser_classes_installer      | NtuserClassesInstallerPlugin    | NtuserClassesInstallerPluginValidationCase    | True      |
| ntuser_shellbag_plugin        | ShellBagNtuserPlugin            | ShellBagNtuserPluginValidationCase            | True      |
| typed_paths                   | TypedPathsPlugin                | TypedPathsPluginValidationCase                | True      |
| user_assist                   | UserAssistPlugin                | NTUserUserAssistValidationCase                | True      |
| ntuser_persistence            | NTUserPersistencePlugin         | NTUserPersistenceValidationCase               | True      |
| typed_urls                    | TypedUrlsPlugin                 | TypedUrlsPluginValidationCase                 | True      |
| winrar_plugin                 | WinRARPlugin                    | WinRARPluginValidationCase                    | True      |
| word_wheel_query              | WordWheelQueryPlugin            | WordWheelQueryPluginValidationCase            | True      |
| network_drives_plugin         | NetworkDrivesPlugin             | NetworkDrivesPluginValidationCase             | True      |
| domain_sid                    | DomainSidPlugin                 | DomainSidPluginValidationCase                 | True      |
| amcache                       | AmCachePlugin                   | AmCachePluginValidationCase                   | True      |
| background_activity_moderator | BAMPlugin                       | BamValidationCase                             | True      |
| usbstor_plugin                | USBSTORPlugin                   | USBSTORPluginValidationCase                   | True      |
| local_sid                     | LocalSidPlugin                  | LocalSidPluginValidationCase                  | True      |
| boot_entry_list               | BootEntryListPlugin             | BootEntryListPluginValidationCase             | True      |
| usrclass_shellbag_plugin      | ShellBagUsrclassPlugin          | ShellBagUsrclassPluginValidationCase          | True      |

## Plugins without validation
**Please note that in the future, this check will be enforced for all plugins**

| plugin_name                  | plugin_class_name             | test_case_name   | success   |
|------------------------------|-------------------------------|------------------|-----------|
| routes                       | RoutesPlugin                  |                  | False     |
| installed_programs_ntuser    | InstalledProgramsNTUserPlugin |                  | False     |
| active_control_set           | ActiveControlSetPlugin        |                  | False     |
| timezone_data                | TimezoneDataPlugin            |                  | False     |
| terminal_services_history    | TSClientPlugin                |                  | False     |
| safeboot_configuration       | SafeBootConfigurationPlugin   |                  | False     |
| image_file_execution_options | ImageFileExecutionOptions     |                  | False     |
    