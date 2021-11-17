import logging
from ascent.datastore.v1.libraries.adaptors.ascent_es_adaptor import AscentESAdaptor
from ascent.datastore.v1.libraries.adaptors.ascent_mssql_adaptor import AscentMSSQLAdaptor
from ascent.datastore.v1.libraries.adaptors.ascent_mysql_adaptor import AscentMySQLAdaptor
from ascent.datastore.v1.libraries.adaptors.ascent_pgsql_adaptor import AscentPGSQLAdaptor
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
            elif 'mssql' in configs:
                self.ds_adaptor = AscentMSSQLAdaptor(ds_config)
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

    def msearch(self, table, body=None, request_timeout=60, **kwargs):
        """ Function wrapped around Ascent Databases multisearch search function

        Args
            table (str): Database table name
            body (dict, optional): [description]. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Default: 60

        Returns:
            dict: Returns a dictionary with Databases responses
        """
        pass

    def get_remaining_data(self, scroll_id, context_duration='10m', request_timeout=30, **kwargs):
        """ Get remaining data function.

        Args:
            scroll_id (str): Scroll ID value.
            context_duration (str, optional): Defaults to '10m'.
            request_timeout (int, optional): Request timeout set value. Default: 30

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def table_exists(self, table, **kwargs):
        """ Function wrapped around Databases library table exists function

            Return a boolean indicating whether given table exists.

        Args:
            table (str): Database table name

        Returns:
            bool: Return a boolean indicating whether given table exists.
        """
        pass

    def table_create(self, table, body=None, **kwargs):
        """ Function wrapped around Ascent Databases library create table function

            Adds or updates a typed JSON document in a specific table, making it searchable.


        Args:
            table (str): Database table name
            body (dict, optional): The document. Default: None
            ignore (tuple, optional): Ignore error codes. Defaults to ().

        Returns:
            dict: Returns a dictionary with Elasticsearch responses
        """
        pass

    def table_exists_alias(self, table, alias, **kwargs):
        """ Check if alias exists

        Args:
            table (str): Database table name
            alias (str): Alias name

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def table_put_alias(self, table, alias, **kwargs):
        """ Put alias

        Args:
            table (str): Database table name
            alias (str): Alias name

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def table_update_aliases(self, query, **kwargs):
        """ Update the alias

        Args:
            query (dict): The document.

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def table_delete(self, table, **kwargs):
        """ Function wrapped around Ascent Databases library table delete function

            Delete an index in Database.

        Args:
            table (str): Database table name
            ignore (int, optional): Ignore error codes. Defaults to None.

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def create(self, table, data=None, bulk=False, doc_id=None, **kwargs):
        """ Function to create document

            Documents can be created in bulk or individually.

        Args:
            table (str): Database index name
            data (dict, optional): The document. Default: None
            bulk (bool, optional): Specify if bulk indexing. Default: False
            doc_id (str, optional): Optional argument for Database document id. Defaults to None.
            ignore (int, optional): Ignore error codes. Defaults to None.

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def create_document(self, table, data=None, doc_id=None, **kwargs):
        """ Function wrapped around Databases library create document function

            Adds or updates a typed JSON document in a specific index, making it searchable.


        Args:
            table (str): Database index name
            data (dict, optional): The document. Default: None
            doc_id (str, optional): Optional argument for Database document id. Defaults to None.
            ignore (int, optional): Ignore error codes. Defaults to None.

        Returns:
            dict: Returns a dictionary with Database responses
        """
        pass

    def update(self, table, data=None, doc_id=None, params=None, bulk=False, **kwargs):
        """ Function wrapped around Ascent Databases update function

            Update a document based on a script or partial data provided.

        Args:

            table (str): Database index name
            data (dict, optional): The document. Default: None
            doc_id (str, optional): Optional argument for Database document id. Defaults to None.
            params (dict, optional): Extra parameters. Defaults to None.
            bulk (bool, optional): Specify if bulk indexing. Default: False

        Returns:
            dict: Returns a dictionary with Database responses
        """
        pass

    def put_template(self, template_name, template, **kwargs):
        """ Put template into the database

        Args:
            template_name (str): Name of the template
            template (dict): Template/Schema

        Returns:
            dict: Returns a dictionary with Database responses
        """
        pass

    def exists_template(self, template_name, **kwargs):
        """ Function wrapped around Ascent Databases  put template function

            Indexes a template/schema for a table. Only

        Args:
            template_name (str): Name of the template

        Returns:
            dict: Returns a dictionary with Database responses
        """
        pass

    def table_update_settings(self, table, body, **kwargs):
        """ Function wrapped around Ascent Databases  update table settings function

            Updates the index/table settings. Only

        Args:
            table (str): Name of the table/index
            body (dict): Settings to be updated

        Returns:
            dict: Returns a dictionary with Database responses
        """
        pass

    def table_force_merge(self, table, **kwargs):
        """ Function wrapped around TINAA Databases table force merge function

            Force merges read-only indices. Only

        Args:
            table (str): Name of the table/index

        Returns:
            dict: Returns a dictionary with Database responses
        """
        pass

    def get(self, table, doc_id=None, **kwargs):
        """ Function wrapped around Ascent Databases get function

            function to get a typed JSON document from the index based on its id.

        Args:
            table (str): Database index name
            doc_id (str): Argument for Database document id

        Returns:
            dict: Returns a dictionary with Database responses
        """
        return self.ds_adaptor.get(table, doc_id=doc_id, **kwargs)

    def exists_document(self, table, doc_id, **kwargs):
        """ Function wrapped around Ascent Databases exists function

            Returns a boolean indicating whether or not given document exists in Database.

        Args:
            table (str): Database index name
            doc_id (str): [Database document id

        Returns:
            bool: Returns a boolean indicating whether or not given document exists in Database.
        """
        pass

    def document_delete(self, table, doc_id, bulk=False, **kwargs):
        """ Function wrapped around Ascent Databases document_delete function

            Deletes a given document from Database.

        Args:
            table (str): Database index name
            doc_id (str): Database document id/ list of document ids if bulk delete
            bulk (bool, optional): Optional argument to use bulk delete operation. Defaults to False.

        Returns:
            bool: Returns a boolean indicating whether or not the given document is deleted in database.
        """
        pass

    def percolate(self, table, data, **kwargs):
        """ Function wrapped around Ascent python client refresh function

            The percolator allows to register queries against an index, and then
            send percolate requests which include a doc, and getting back the
            queries that match on that doc out of the set of registered queries.

        Args:
            table (str): Database index name
            data (json): The document

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def create_watch(self, watch_id, body=None):
        """Create a Watch

        Args:
            watch_id (str): Watch ID
            body (dict): The watch. Defaults to None.

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def delete_watch(self, watch_id):
        """Delete a watch

        Args:
            watch_id (str): Watch ID

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def deactivate_watch(self, watch_id):
        """Deactivate a watch

        Args:
            watch_id (str): Watch ID

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def activate_watch(self, watch_id):
        """Activate a watch

        Args:
            watch_id (str): Watch ID

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def execute_watch(self, watch_id, body=None):
        """Execute a watch

        Args:
            watch_id (str): Watch ID
            body (dict): The watch. Defaults to None.

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def get_watch(self, watch_id):
        """Get a watch

        Args:
            watch_id (str): Watch ID

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def get_all_watches(self, **kwargs):
        """Get all watches available in the database

        Args:
            watch_id (str): Watch ID

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def start_watcher(self):
        """Start the watcher

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def stop_watcher(self):
        """Stop the watcher

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def get_stats_watcher(self, metric=None):
        """Get stats of the watcher

        Args:
            metric (list, optional): Controls what additional stat metrics should be
            include in the response  Valid choices: _all, queued_watches,
            current_watches, pending_watches. Defaults to None.

        Returns:
            dict: Returns a dictionary with responses
        """
        pass
