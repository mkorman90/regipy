regipy
==========
Regipy is a python library for parsing offline registry hives!

**Requires Python 3.9 or higher.**

Features:

* Use as a library
* Recurse over the registry hive, from root or a given path and get all subkeys and values
* Read specific subkeys and values
* Apply transaction logs on a registry hive
* Command Line Tools:
    * Dump an entire registry hive to json
    * Apply transaction logs on a registry hive
    * Compare registry hives
    * Execute plugins from a robust plugin system (i.e: amcache, shimcache, extract computer name...)

:Project page: https://github.com/mkorman90/regipy

Using as a library:
--------------------
.. code:: python

    from regipy.registry import RegistryHive
    reg = RegistryHive('/Users/martinkorman/Documents/TestEvidence/Registry/Vibranium-NTUSER.DAT')

    # Iterate over a registry hive recursively:
    for entry in reg.recurse_subkeys(as_json=True):
        print(entry)

    # Iterate over a key and get all subkeys and their modification time:
    for sk in reg.get_key('Software').get_subkeys():
        print(sk.name, convert_wintime(sk.header.last_modified).isoformat())

    # Get values from a specific registry key:
    reg.get_key('Software\Microsoft\Internet Explorer\BrowserEmulation').get_values(as_json=True)

    # Use plugins:
    from regipy.plugins.ntuser.ntuser_persistence import NTUserPersistencePlugin
    NTUserPersistencePlugin(reg, as_json=True).run()

    # Run all validated plugins on a registry hive:
    run_relevant_plugins(reg, as_json=True)

    # Include unvalidated plugins (may return incomplete/inaccurate data):
    run_relevant_plugins(reg, as_json=True, include_unvalidated=True)

Install
^^^^^^^
Install regipy and the command line tools dependencies:

``pip install regipy[cli]``


NOTE: using pip with ``regipy[cli]`` instead of the plain ``regipy`` is a
significant change from version 1.9.x

For using regipy as a library, install only ``regipy`` which comes with fewer
dependencies:

``pip install regipy``

Plugin Validation
^^^^^^^^^^^^^^^^^
Regipy plugins are validated using test cases to ensure they return accurate data.
By default, only validated plugins are executed when using ``run_relevant_plugins()``
or the CLI tools.

To include unvalidated plugins (which may return incomplete or inaccurate data):

.. code:: python

    # As a library:
    run_relevant_plugins(reg, as_json=True, include_unvalidated=True)

.. code:: bash

    # CLI:
    regipy-plugins-run /path/to/hive -o output.json --include-unvalidated

Unvalidated plugins will log a warning when executed. Use them at your own discretion.

Available Plugins
^^^^^^^^^^^^^^^^^

**NTUSER Plugins:**

* ``user_assist`` - Parses User Assist execution history
* ``typed_urls`` - Retrieves typed URLs from IE history
* ``typed_paths`` - Retrieves typed file paths
* ``ntuser_persistence`` - Retrieves persistence entries (Run, RunOnce, etc.)
* ``shellbag_plugin`` - Parses Shellbag items
* ``network_drives_plugin`` - Retrieves mapped network drives
* ``terminal_services_history`` - Parses RDP/Terminal Server client data
* ``winrar_plugin`` - Parses WinRAR archive history
* ``winscp_saved_sessions`` - Retrieves WinSCP saved sessions
* ``word_wheel_query`` - Parses Windows Search word wheel query
* ``wsl`` - Gets WSL distribution information
* ``installed_programs_ntuser`` - Retrieves installed programs
* ``ntuser_classes_installer`` - Parses class installer information
* ``recentdocs`` - Parses recently opened documents
* ``comdlg32`` - Parses Open/Save dialog MRU lists
* ``runmru`` - Parses Run dialog MRU list
* ``muicache`` - Parses MUI Cache (application display names)
* ``appkeys`` - Parses application keyboard shortcuts
* ``sysinternals`` - Parses Sysinternals tools EULA acceptance
* ``putty`` - Parses PuTTY sessions and SSH host keys

**SOFTWARE Plugins:**

* ``installed_programs_software`` - Retrieves installed programs
* ``profilelist_plugin`` - Parses user profile information
* ``uac_plugin`` - Gets User Access Control settings
* ``winver_plugin`` - Gets OS version information
* ``last_logon_plugin`` - Gets last logon information
* ``image_file_execution_options`` - Retrieves IFEO entries
* ``print_demon_plugin`` - Gets installed printer ports
* ``ras_tracing`` - Gets tracing/debugging configuration
* ``disablesr_plugin`` - Gets system restore disable status
* ``spp_clients_plugin`` - Determines volumes monitored by VSS
* ``susclient_plugin`` - Extracts Windows Update client info
* ``software_classes_installer`` - Parses class installer information
* ``software_plugin`` - Retrieves persistence entries
* ``app_paths`` - Parses application paths registry entries
* ``appinit_dlls`` - Parses AppInit_DLLs persistence entries
* ``appcert_dlls`` - Parses AppCertDLLs persistence entries
* ``appcompat_flags`` - Parses application compatibility flags
* ``windows_defender`` - Parses Windows Defender configuration
* ``powershell_logging`` - Parses PowerShell logging configuration
* ``execution_policy`` - Parses PowerShell execution policies
* ``networklist`` - Parses network connection history

**SYSTEM Plugins:**

* ``shimcache`` - Parses Shimcache/AppCompatCache
* ``services`` - Enumerates services and parameters
* ``usbstor_plugin`` - Parses connected USB storage devices
* ``background_activity_moderator`` - Gets BAM execution data
* ``network_data`` - Gets network interface configuration
* ``routes`` - Gets network routes
* ``computer_name`` - Gets the computer name
* ``timezone_data`` / ``timezone_data2`` - Gets timezone configuration
* ``safeboot_configuration`` - Gets safeboot configuration
* ``active_control_set`` - Gets the active control set
* ``backuprestore_plugin`` - Gets backup/restore exclusion entries
* ``processor_architecture`` - Gets processor architecture info
* ``previous_winver_plugin`` - Gets previous Windows version info
* ``codepage`` - Gets system codepage information
* ``host_domain_name`` - Gets host and domain name
* ``crash_dump`` - Gets crash control information
* ``diag_sr`` - Gets diagnostic system restore information
* ``disable_last_access`` - Gets LastAccessTime disable status
* ``wdigest`` - Gets WDIGEST authentication configuration
* ``bootkey`` - Extracts the Windows boot key
* ``shutdown`` - Gets shutdown time data
* ``usb_devices`` - Parses USB device connection history
* ``mounted_devices`` - Parses mounted device information
* ``shares`` - Parses network share configuration
* ``pagefile`` - Parses pagefile configuration
* ``lsa_packages`` - Parses LSA security packages
* ``pending_file_rename`` - Parses pending file rename operations

**SAM Plugins:**

* ``local_sid`` - Extracts the machine local SID
* ``samparse`` - Parses user accounts from SAM hive

**SECURITY Plugins:**

* ``domain_sid`` - Extracts domain name and SID

**AMCACHE Plugins:**

* ``amcache`` - Parses Amcache application execution history

**BCD Plugins:**

* ``boot_entry_list`` - Lists Windows BCD boot entries

**USRCLASS Plugins:**

* ``usrclass_shellbag_plugin`` - Parses USRCLASS Shellbag items
