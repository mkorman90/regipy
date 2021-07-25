import logging

from typing import Any, Dict, List, Optional

from regipy.registry import RegistryHive

PLUGINS = set()

logger = logging.getLogger(__name__)


class Plugin(object):

    NAME: Optional[str] = None
    DESCRIPTION: Optional[str] = None
    COMPATIBLE_HIVE: Optional[str] = None

    def __init_subclass__(cls):
        PLUGINS.add(cls)

    def __init__(self, registry_hive: RegistryHive, as_json=False):
        self.registry_hive = registry_hive
        self.as_json = as_json

        self.partial_hive_path = registry_hive.partial_hive_path

        # This variable should always hold the final result - in order to use it in anomaly detection and timeline gen.
        self.entries: List[Dict[str, Any]] = list()

    def can_run(self):
        """
        Wether the plugin can run or not, according to specific checks
        :return:
        """
        return self.registry_hive.hive_type == self.COMPATIBLE_HIVE

    def run(self):
        """
        Execute the plugin
        :return:
        """

    def generate_timeline_artifacts(self):
        """
        Run on the output of a plugin and generate timeline entries
        :return:
        """
        pass

    def detect_anomalies(self):
        """
        Run on the output of a plugin and detect possible anomalies
        :return:
        """
        pass
