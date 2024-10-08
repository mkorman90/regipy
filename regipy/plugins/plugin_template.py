import logging

from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin

logger = logging.getLogger(__name__)


class TemplatePlugin(Plugin):
    NAME = "template_plugin"
    DESCRIPTION = "template_description"

    def can_run(self):
        # TODO: Choose the relevant condition - to determine if the plugin is relevant for the given hive
        return self.registry_hive.hive_type == NTUSER_HIVE_TYPE

    def run(self):
        # TODO: Return the relevant values
        raise NotImplementedError
