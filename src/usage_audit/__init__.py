
import importlib.metadata 
import logging
usage_audit_logger = logging.getLogger(__name__)

__version__ =  importlib.metadata.version('usage_audit')

DEFAULT_CONFIG = "/etc/nmrbox.d/nmrbox_audit.yaml"
