
# Regipy plugin validation results

## Plugins with validation

{| class="wikitable" style="text-align: left;"
|+ <!-- caption -->
|-
! plugin_name                   !! plugin_class_name         !! test_case_name                    !! success
|-
| software_plugin               || SoftwarePersistencePlugin || SoftwarePersistenceValidationCase || True
|-
| amcache                       || AmCachePlugin             || AmCachePluginValidationCase       || True
|-
| user_assist                   || UserAssistPlugin          || NTUserUserAssistValidationCase    || True
|-
| ntuser_persistence            || NTUserPersistencePlugin   || NTUserPersistenceValidationCase   || True
|-
| word_wheel_query              || WordWheelQueryPlugin      || NTUserUserAssistValidationCase    || True
|-
| background_activity_moderator || BAMPlugin                 || NTUserUserAssistValidationCase    || True
|-
| shimcache                     || ShimCachePlugin           || AmCacheValidationCase             || True
|}

## Plugins without validation
**Please note that in the future, this check will be enforced for all plugins**

{| class="wikitable" style="text-align: left;"
|+ <!-- caption -->
|-
! plugin_name                  !! plugin_class_name               !! test_case_name   !! success
|-
| usrclass_shellbag_plugin     || ShellBagUsrclassPlugin          ||                  || False
|-
| domain_sid                   || DomainSidPlugin                 ||                  || False
|-
| routes                       || RoutesPlugin                    ||                  || False
|-
| last_logon_plugin            || LastLogonPlugin                 ||                  || False
|-
| services                     || ServicesPlugin                  ||                  || False
|-
| host_domain_name             || HostDomainNamePlugin            ||                  || False
|-
| profilelist_plugin           || ProfileListPlugin               ||                  || False
|-
| ntuser_shellbag_plugin       || ShellBagNtuserPlugin            ||                  || False
|-
| computer_name                || ComputerNamePlugin              ||                  || False
|-
| installed_programs_ntuser    || InstalledProgramsNTUserPlugin   ||                  || False
|-
| winscp_saved_sessions        || WinSCPSavedSessionsPlugin       ||                  || False
|-
| local_sid                    || LocalSidPlugin                  ||                  || False
|-
| print_demon_plugin           || PrintDemonPlugin                ||                  || False
|-
| active_control_set           || ActiveControlSetPlugin          ||                  || False
|-
| timezone_data                || TimezoneDataPlugin              ||                  || False
|-
| uac_plugin                   || UACStatusPlugin                 ||                  || False
|-
| typed_paths                  || TypedPathsPlugin                ||                  || False
|-
| network_data                 || NetworkDataPlugin               ||                  || False
|-
| typed_urls                   || TypedUrlsPlugin                 ||                  || False
|-
| terminal_services_history    || TSClientPlugin                  ||                  || False
|-
| ras_tracing                  || RASTracingPlugin                ||                  || False
|-
| installed_programs_software  || InstalledProgramsSoftwarePlugin ||                  || False
|-
| software_classes_installer   || SoftwareClassesInstallerPlugin  ||                  || False
|-
| safeboot_configuration       || SafeBootConfigurationPlugin     ||                  || False
|-
| usbstor_plugin               || USBSTORPlugin                   ||                  || False
|-
| wdigest                      || WDIGESTPlugin                   ||                  || False
|-
| ntuser_classes_installer     || NtuserClassesInstallerPlugin    ||                  || False
|-
| image_file_execution_options || ImageFileExecutionOptions       ||                  || False
|-
| network_drives_plugin        || NetworkDrivesPlugin             ||                  || False
|-
| bootkey                      || BootKeyPlugin                   ||                  || False
|-
| boot_entry_list              || BootEntryListPlugin             ||                  || False
|-
| winrar_plugin                || WinRARPlugin                    ||                  || False
|}
    