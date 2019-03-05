from .amcache.amcache import AmCachePlugin
from .ntuser.persistence import NTUserPersistencePlugin
from .ntuser.user_assist import UserAssistPlugin
from .system.routes import RoutesPlugin
# Services plugin is currently disabled because it is relatively slow
# from .system.services import ServicesPlugin
from .system.computer_name import ComputerNamePlugin
from .system.shimcache import ShimCachePlugin
from .software.installed_programs import InstalledSoftwarePlugin
from .software.image_file_execution_options import ImageFileExecutionOptions
from .software.persistence import SoftwarePersistencePlugin
from .system.timezone_data import TimezoneDataPlugin
from .system.active_controlset import ActiveControlSetPlugin
