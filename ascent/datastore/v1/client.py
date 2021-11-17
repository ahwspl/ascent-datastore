import logging
from ascent.datastore.v1.libraries.adaptors.ascent_es_adaptor import AscentESAdaptor
from ascent.datastore.v1.libraries.adaptors.ascent_mysql_adaptor import AscentMySQLAdaptor
from ascent.datastore.v1.libraries.helpers import common_util as utils


class Client(object):
    """ A library module for Ascent Elasticsearch library

        Producer module wrapped around the Ascent Datastore Adaptor. Creates an instance of the
        Database Client object.

    Args:
        object (obj): Object of `AscentDSAdaptor`
    """

    def __init__(self, ds_config):

        self.logger = logging.getLogger(__name__)
        if isinstance(ds_config, dict) or isinstance(ds_config, str):
            configs = ds_config if isinstance(ds_config, dict) else utils.load_config_file(ds_config)
            if 'elasticsearch' in configs:
                self.ds_adaptor = AscentESAdaptor(ds_config)
            elif 'mysql' in configs:
                self.ds_adaptor = AscentMySQLAdaptor(ds_config)
        else:
            self.ds_adaptor = ds_config

    def search(self, table, body=None, scroll=None, request_timeout=60, size=10000, **kwargs):
        """ Function wrapped around Ascent Databases search function

        Args:
            table (str): Database table name
            body (dict, optional): Defaults to None.
            scroll (str, optional): Scan and scroll option. Scroll parameter telling Database how long it should keep the scroll open e.g 1m (1 minute)
            request_timeout (int, optional): Request timeout set value. Default: 60
            size (int, optional): Size of records to return. Default: 10000

        Returns:
            dict: Returns a dictionary with Databases responses
        """
        pass
        # return self.ds_adaptor.search()

    def get(self, table, doc_id, **kwargs):
        """ Function wrapped around Ascent Databases get function

            function to get a typed JSON document from the index based on its id.

        Args:
            table (str): Database index name
            doc_id (str): Argument for Database document id

        Returns:
            dict: Returns a dictionary with Database responses
        """
        return self.ds_adaptor.get(table, doc_id=doc_id, **kwargs)
