import os
import json
import logging
import requests
import functools
from .helpers import common_util as utils
from .helpers.DBOperationError import DBOperationError
import mysql.connector
from mysql.connector import errorcode


class AscentMySQLAdaptor(object):
    """An adaptor to create and manage MySQL database client.

    Args:
        ds_config (str): An abosolute path to the config file.
    """

    def __init__(self, ds_config=None):
        self.logger = logging.getLogger(__name__)

        configs = ds_config if isinstance(ds_config, dict) else utils.load_config_file(ds_config)
        self.db = None

        if 'mysql' not in configs:
            raise KeyError('mysql')

        self.mysql_configs = dict()
        self.mysql_configs['hostname'] = configs['mysql']['hostname']
        self.mysql_configs['port'] = configs['mysql'].get('port', 3306)
        self.mysql_configs['database'] = configs['mysql']['database']

        self.auth_type, mysql_username, mysql_password = None, configs['mysql'].get('username', None), None
        if mysql_username is not None:
            self.auth_type = "Basic"
            if configs['mysql'].get('password', None) is not None:
                mysql_password = configs['mysql']['password']
            elif os.environ.get("MYSQL_PASS") is not None:
                mysql_password = os.environ.get("MYSQL_PASS")
            else:
                self.logger.warn("Database password is not defined!")
        else:
            self.logger.warn("Database username is not defined!")

        kwargs = dict()
        for item, value in self.mysql_configs.items():
            if value is not None:
                kwargs[item] = value
        self.logger.info("Connecting to {} database...".format('mysql'))
        try:
            self.db = mysql.connector.connect(
                host=self.mysql_configs['hostname'],
                port=self.mysql_configs['port'],
                user=mysql_username,
                password=mysql_password,
                database=self.mysql_configs['database']
            )
            self.cursor = self.db.cursor()
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                self.logger.error("Something went wrong with the username and password provided in the request")
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                self.logger.error("Database {} does not exist!".format(self.mysql_configs['database']))
            else:
                self.logger.error("Encountered error when connecting to the {} database".format('mysql'))
        else:
            self.db.close()

    def build_search_query(self, fields=None, search_all=False, method='term', criteria='must', range=None, custom=None):
        """ Query builder function for ES

            This function will create Elasticsearch queries based on the options.

        Args:
            fields (list of `dict` or `dict`, optional): List of fields that needs to keep in the body, None if all fields are needed. Defaults to None.
            search_all (bool, optional): Get all documents in the index or not. Defaults to False.
            method (str, optional): term or match. Defaults to 'term'.
            criteria (str, optional): must/must_not/should. Defaults to 'must'.
            range (dict, optional): Range for matching. Defaults to None.
            custom (dict, optional): Custom query bodies, will use this body for query instead build by parameters. Defaults to None.

        Returns:
            `dict`: A query body built on the input parameters
        """
        pass

    def get_watcher_with_id(self, watcher_id, **kwargs):
        """Get a watcher with ID

        Args:
            watcher_id (int): Watcher ID

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def search_watcher(self, body=None, **kwargs):
        """Search a watcher

        Args:
            body (str):

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def create_watcher(self, watcher_id, body, params=None, **kwargs):
        """Create a watcher

        Args:
            watcher_id (int): Watcher ID
            body (str):
            params (dict(str)):

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def execute_watcher(self, watcher_id, **kwargs):
        """Execute a Watcher

        Args:
            watcher_id (int): Watcher ID

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def activate_watcher(self, watcher_id, **kwargs):
        """Activate a watcher

        Args:
            watcher_id (int): Watcher ID

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def deactivate_watcher(self, watcher_id, **kwargs):
        """Deactivate a watcher

        Args:
            watcher_id (int): Watcher ID

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def delete_watcher(self, watcher_id, **kwargs):
        """Delete a watcher

        Args:
            watcher_id (int): Watcher ID

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def check_watcher_exists(self, watcher_id, **kwargs):
        """Check if watcher exists

        Args:
            watcher_id (int): Watcher ID

        Returns:
            bool: True if watcher exists
        """
        pass

    def search(self, index, body=None, scroll=None, request_timeout=60, size=10000, **kwargs):
        """ Function wrapped around MySQL python client search function
            Search function to query MySQL

        Args:
            index (str): Index name
            body (dict, optional): MySQL search query. Defaults to None.
            scroll (str, optional): Scan and scroll option. Scroll parameter telling MySQL how long it should keep
                    the scroll open e.g 1m (1 minute). Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.
            size (int, optional): Size of records to return. Defaults to 10000.

        Raises:
            DBOperationError: Index not found
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with MySQL responses
        """
        try:
            pass
        except Exception as e:
            self.logger.error(f"Exception occurred when retrieving data: {str(e)}")

    def msearch(self, index, body=None, request_timeout=60, **kwargs):
        """ Function wrapped around MySQL python client multisearch search function
            MultiSearch function to query MySQL\

        Args:
            index (str): Index name
            body (dict, optional): MySQL search query. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Index not found
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with MySQL responses
        """
        pass

    def mget(self, index, body=None, request_timeout=60, **kwargs):
        """ Function wrapped around MySQL python client multi get function

        Args:
            index (str): Index name
            body (dict, optional): MySQL search query. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Index not found
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with MySQL responses
        """
        pass

    def get(self, index, doc_id, request_timeout=60, **kwargs):
        """ Function wrapped around MySQL python client get function

            function to get a typed JSON document from the index based on its id

        Args:
            index (str): Index name
            doc_id (str): Optional argument for MySQL document id. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Index not found
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with MySQL responses
        """
        try:
            query = ("SELECT * FROM %s WHERE id=%s" % (index, doc_id))
            self.cursor.execute(query)
            if self.cursor.rowcount > 0:
                response = self.cursor.fetchone()
            else:
                raise Exception
            return response
        except mysql.connector.errors as err:
            self.logger.error(f"Failed to retrieve data with id {str(doc_id)} from table {str(index)}: {str(err)}")
            # f"Error Code: {str(err.errno)}\n"
            # f"SQLState Value: {str(err.sqlstate)}\n"
            # f"Error Message: {str(err.msg)}"
