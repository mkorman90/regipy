from regipy.registry import RegistryHive
from regipy.plugins.utils import run_relevant_plugins
from regipy.plugins.ntuser.shellbags_ntuser import ShellBagPlugin

reg = RegistryHive("C:\\offline\\shellbags\\NTUSER_BAGMRU.DAT")
plugin = ShellBagPlugin(reg,as_json=True)
plugin.run()

for entery in plugin.entries:
    print (len(plugin.entries))
    print(entery)
    print('-------------')