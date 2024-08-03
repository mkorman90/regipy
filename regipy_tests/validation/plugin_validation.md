
# Regipy plugin validation results

## Plugins with validation

| plugin_name                   | plugin_class_name               | test_case_name                                | success   |
|-------------------------------|---------------------------------|-----------------------------------------------|-----------|
| amcache                       | AmCachePlugin                   | AmCachePluginValidationCase                   | True      |
| background_activity_moderator | BAMPlugin                       | BamValidationCase                             | True      |
| boot_entry_list               | BootEntryListPlugin             | BootEntryListPluginValidationCase             | True      |
| bootkey                       | BootKeyPlugin                   | BootKeyPluginValidationCase                   | True      |
| computer_name                 | ComputerNamePlugin              | ComputerNamePluginValidationCase              | True      |
| domain_sid                    | DomainSidPlugin                 | DomainSidPluginValidationCase                 | True      |
| host_domain_name              | HostDomainNamePlugin            | HostDomainNamePluginValidationCase            | True      |
| installed_programs_software   | InstalledProgramsSoftwarePlugin | InstalledProgramsSoftwarePluginValidationCase | True      |
| last_logon_plugin             | LastLogonPlugin                 | LastLogonPluginValidationCase                 | True      |
| local_sid                     | LocalSidPlugin                  | LocalSidPluginValidationCase                  | True      |
| network_data                  | NetworkDataPlugin               | NetworkDataPluginValidationCase               | True      |
| network_drives_plugin         | NetworkDrivesPlugin             | NetworkDrivesPluginValidationCase             | True      |
| ntuser_classes_installer      | NtuserClassesInstallerPlugin    | NtuserClassesInstallerPluginValidationCase    | True      |
| ntuser_persistence            | NTUserPersistencePlugin         | NTUserPersistenceValidationCase               | True      |
| ntuser_shellbag_plugin        | ShellBagNtuserPlugin            | ShellBagNtuserPluginValidationCase            | True      |
| print_demon_plugin            | PrintDemonPlugin                | PrintDemonPluginValidationCase                | True      |
| profilelist_plugin            | ProfileListPlugin               | ProfileListPluginValidationCase               | True      |
| ras_tracing                   | RASTracingPlugin                | RASTracingPluginValidationCase                | True      |
| services                      | ServicesPlugin                  | ServicesPluginValidationCase                  | True      |
| shimcache                     | ShimCachePlugin                 | AmCacheValidationCase                         | True      |
| software_classes_installer    | SoftwareClassesInstallerPlugin  | SoftwareClassesInstallerPluginValidationCase  | True      |
| software_plugin               | SoftwarePersistencePlugin       | SoftwarePersistenceValidationCase             | True      |
| typed_paths                   | TypedPathsPlugin                | TypedPathsPluginValidationCase                | True      |
| typed_urls                    | TypedUrlsPlugin                 | TypedUrlsPluginValidationCase                 | True      |
| uac_plugin                    | UACStatusPlugin                 | UACStatusPluginValidationCase                 | True      |
| usbstor_plugin                | USBSTORPlugin                   | USBSTORPluginValidationCase                   | True      |
| user_assist                   | UserAssistPlugin                | NTUserUserAssistValidationCase                | True      |
| usrclass_shellbag_plugin      | ShellBagUsrclassPlugin          | ShellBagUsrclassPluginValidationCase          | True      |
| wdigest                       | WDIGESTPlugin                   | WDIGESTPluginValidationCase                   | True      |
| winrar_plugin                 | WinRARPlugin                    | WinRARPluginValidationCase                    | True      |
| winscp_saved_sessions         | WinSCPSavedSessionsPlugin       | WinSCPSavedSessionsPluginValidationCase       | True      |
| word_wheel_query              | WordWheelQueryPlugin            | WordWheelQueryPluginValidationCase            | True      |

## Plugins without validation
**Please note that in the future, this check will be enforced for all plugins**

| plugin_name                  | plugin_class_name             | test_case_name   | success   |
|------------------------------|-------------------------------|------------------|-----------|
| active_control_set           | ActiveControlSetPlugin        |                  | False     |
| image_file_execution_options | ImageFileExecutionOptions     |                  | False     |
| installed_programs_ntuser    | InstalledProgramsNTUserPlugin |                  | False     |
| routes                       | RoutesPlugin                  |                  | False     |
| safeboot_configuration       | SafeBootConfigurationPlugin   |                  | False     |
| terminal_services_history    | TSClientPlugin                |                  | False     |
| timezone_data                | TimezoneDataPlugin            |                  | False     |
    