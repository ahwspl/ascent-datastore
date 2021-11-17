import os
import yaml
import configparser
import logging

module_code = 0
# TODO: change to use AscentLogger when it's available
# logger = AscentLogger(module_code=module_code)    # 3 digit module_code, 2 digit err_code
logger = logging.getLogger(__name__)


def load_config_file(config_path):
    """Read YAML or JSON config file and return config objects.

    Args:
        config_path (Union[str, dict]): Absolute path to the config file or dict contains configs.

    Returns:
        configs ([dict])
    """    
    configs = None
    if isinstance(config_path, str):
        if os.path.isfile(config_path):
            with open(config_path) as f:
                logging.info("Loading configurations from file...")
                configs = yaml.safe_load(f)
                if not isinstance(configs, dict):
                    raise Exception("Invalid configuration format. Configuration should be in dictionary format.")
                return configs
        else:
            raise Exception('Invalid path for configurations.')
    else:
        raise Exception("Invalid configuration. Only JSON or YAML should be provided")


def get_config_dir():
    """ returns the absolute path of the config folder """
    return os.path.dirname(
        os.path.dirname(
            os.path.dirname(
                os.path.dirname(
                    os.path.abspath(__file__))))) + '/config'


def get_root_dir():
    """ returns the absolute path of the root folder"""
    return os.path.dirname(
            os.path.dirname(
                os.path.dirname(
                    os.path.dirname((os.path.abspath(__file__))))))


def read_config_file(cfg_file_path):
    """ reads cfg format files and returns parsed config"""
    config = configparser.ConfigParser()
    file_read = config.read(cfg_file_path)
    if not file_read:
        logger.error('Failed to read cfg file {}'.format(cfg_file_path))
        raise FileNotFoundError
    return config


# def get_config_file_section(cfg_file_path, section_name):
#     """ reads a specific section in the cfg file and returns the parsed section"""
#     config = read_cfg_file(cfg_file_path)
#     try:
#         return config[section_name]
#     except KeyError:
#         logger.error('Failed to read cfg file {} section {}'.format(cfg_file_path, section_name))
#         raise

