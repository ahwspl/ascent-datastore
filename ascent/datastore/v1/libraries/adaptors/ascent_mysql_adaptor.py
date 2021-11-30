import os
import json
import logging
import functools
from ..helpers import common_util as utils
from ..helpers.DBOperationError import DBOperationError
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
            self.cursor = self.db.cursor(dictionary=True)
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                self.logger.error("Something went wrong with the username and password provided in the request")
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                self.logger.error("Database {} does not exist!".format(self.mysql_configs['database']))
            else:
                self.logger.error("Encountered error when connecting to the {} database".format('mysql'))
        else:
            pass
            # self.db.close()

    def build_search_query(self, fields=None, search_all=False, method='term', criteria='must', range=None, custom=None):
        """ Query builder function for MySQL

            This function will create MySQL queries based on the options.

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

    def get(self, index, doc_id=None, request_timeout=60, **kwargs):
        """ Function wrapped around MySQL python client get function

            function to get a typed JSON document from the index based on its id

        Args:
            index (str): Index name
            doc_id (str, optional): Optional argument for MySQL document id. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Index not found
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with MySQL responses
        """
        response = {
            "_index": index,
            "_type": "_doc",
            "_seq_no": 0,
            "primary_term": 1,
            "found": False,
            "_source": {}
        }
        try:
            if self.exists_index(index=index) is False:
                raise DBOperationError(f'MySQL get failed. Index {index} not found')
            query = ("SELECT * FROM %s WHERE " % index)
            if doc_id is None:
                query += (list(kwargs.keys())[0] + "=" + str(list(kwargs.values())[0]))
                response.update(
                    {
                        "_id": str(list(kwargs.values())[0])
                    }
                )
            else:
                query += ("id=%s" % doc_id)
                response.update(
                    {
                        "_id": doc_id
                    }
                )
            self.cursor.execute(query)
            query_output = self.cursor.fetchall()
            if query_output:
                response.update(
                    {
                        "found": True,
                        "_source": query_output[0]
                    }
                )
            return response
        except mysql.connector.errors as err:
            self.logger.error(f"Failed to retrieve data with id {str(doc_id)} from table {str(index)}: {str(err)}")
            raise DBOperationError(f"MySQL get failed. Reason - {str(err)}")

    def update_by_query(self, index, doc_id=None, request_timeout=60, **kwargs):
        """ Function wrapped around MySQL python client get function

            function to get a typed JSON document from the index based on its id

        Args:
            index (str): Index name
            doc_id (str, optional): Optional argument for Elasticsearch document id. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Index not found
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with MySQL responses
        """
        pass

    def create_document(self, index, body, doc_id=None, request_timeout=60, **kwargs):
        """ Function wrapped around MySQL python client index function

            Adds or updates a typed JSON document in a specific index, making it searchable.

        Args:
            index (str): Index name
            body (dict): Document
            doc_id (str, optional): Optional argument for MySQL document id. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with MySQL responses
        """
        pass

    def create_index(self, index, body=None, request_timeout=60, **kwargs):
        """ Function wrapped around MySQL python client indices function

            Adds or updates a typed JSON document in a specific index, making it searchable.

        Args:
            index (str): Index name
            body (dict): The document. Defaults to None.
            ignore (int, optional): Ignore error codes. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with MySQL responses
        """
        response = {
            "acknowledged": False,
            "index": index
        }
        try:
            query = body
            # parsing the body param based on the type -> dict => parsing fields and constraints to generate the query
            if type(body) is dict:
                query = "CREATE TABLE %s (%s %s) "
                field_add = ""
                fields = body["mappings"]["properties"]["fields"]
                for key, value in fields.items():
                    field_add += f" `{key}` {value['type']} "
                    if "constraints" in value.keys():
                        for ikey, ivalue in value["constraints"].items():
                            field_add += f" {ikey} "
                            if type(ivalue) is not bool:
                                field_add += f"{ivalue} "
                    field_add += ","
                constraints = body["mappings"]["properties"]["constraints"]

                constraint_add = ""
                for key, value in constraints.items():
                    if key == "PRIMARY KEY":
                        constraint_add += f" PRIMARY KEY (`{value}`),"
                    elif key == "FOREIGN KEY":
                        for item in value:
                            constraint_add += f" CONSTRAINT {item['name']} FOREIGN KEY (`{item['field']}`) REFERENCES `{item['reference']['table']}` (`{item['reference']['field']}`),"

                query = query % (field_add, constraint_add)
                query = ''.join(query.rsplit(',', 1))

            self.cursor.execute(query)
            query_output = self.cursor.fetchall()
            if query_output:
                response.update(
                    {
                        "acknowledged": True
                    }
                )
            return response

        except mysql.connector.errors as err:
            self.logger.error(f"Failed to create table {str(index)}: {str(err)}")
            raise DBOperationError(f"MySQL create_index failed. Reason - {str(err)}")

    def delete_documents_by_query(self, index, body, request_timeout=60, **kwargs):
        """Delete a document

        Args:
            index (str): Index name
            body (dict): The document. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with MySQL responses
        """
        pass

    def delete_document(self, index, doc_id, request_timeout=60, **kwargs):
        """ Function wrapped around MySQL python client delete function

            Delete a typed JSON document from a specific index based on its id.

        Args:
            index (str): Index name
            doc_id (str): MySQL Document ID
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with MySQL responses
        """
        pass

    def delete_index(self, index, request_timeout=60, **kwargs):
        """ Function wrapped around MySQL python client indices.delete function

            Delete an index in MySQL

        Args:
            index (str): Index name
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with MySQL responses
        """
        pass

    def exists_document(self, index, doc_id, request_timeout=60, **kwargs):
        """ Function wrapped around MySQL python client exists function

            Returns a boolean indicating whether or not given document exists in MySQL.

        Args:
            index (str): Index name
            doc_id (str): MySQL Document ID
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            bool: Returns a boolean indicating whether or not given document exists in MySQL.
        """
        try:
            response = self.get(index=index, doc_id=doc_id, **kwargs)
            return response.get("found")
        except mysql.connector.errors as err:
            self.logger.error(f"Failed to retrieve data with id {str(doc_id)} from table {str(index)}: {str(err)}")
            raise DBOperationError(f'MySQL exists document failed. Reason - {str(err)}')

    def exists_index(self, index, request_timeout=60, **kwargs):
        """ Function wrapped around MySQL python client indices.exists function

            Return a boolean indicating whether given index exists.

        Args:
            index (str): Index name
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            bool: Return a boolean indicating whether given index exists.
        """
        try:
            query = (
                    "SELECT * FROM information_schema.tables WHERE table_schema='%s' AND table_name='%s'" %
                    (self.mysql_configs['database'], index)
            )
            self.cursor.execute(query)
            if bool(self.cursor.fetchone()):
                return True
            return False
        except Exception as err:
            self.logger.error(f"Failed to check if MySQL table exists. Reason - {str(err)}")
            raise DBOperationError(f'MySQL exists index failed. Reason - {str(err)}')

    def exists_alias(self, name, request_timeout=60, **kwargs):
        """Check if alias exists

        Args:
            name (str): Name
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def put_alias(self, index, name, request_timeout=60, **kwargs):
        """Put alias

        Args:
            index (str): Index name
            name (str): Name
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def update_aliases(self, body, request_timeout=60, **kwargs):
        """ Update aliases

        Args:
            body (dict): The document. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def indices_delete(self, index, request_timeout=60, **kwargs):
        """  Function wrapped around MySQL python client indices.delete function

            Delete an index in MySQL

        Args:
            index (str): Index name
            ignore (int, optional): Ignore error codes. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with responses

        """
        try:
            if self.exists_index(index=index) is False:
                raise DBOperationError(f'MySQL delete index failed. Index {index} not found')
            query = ("DROP TABLE %s.%s" % (self.mysql_configs['database'], index))
            self.cursor.execute(query)
            return {
                "acknowledged": True
            }
        except Exception as err:
            self.logger.error(f"Failed to check if MySQL table exists. Reason - {str(err)}")
            raise DBOperationError(f'MySQL delete index failed. Reason - {str(err)}')

    def refresh(self, index, request_timeout=60, **kwargs):
        """ Function wrapped around MySQL python client refresh function

            Explicitly refresh one or more index, making all operations performed
            since the last refresh available for search.

        Args:
            index (str): Index name
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def reindex(self, data, **kwargs):
        """ Function wrapped around post method of request python client
            Sends a post request

        Args:
            data (dict): Post data for MySQL reindex

        Raises:
            DBOperationError: Internal Error
            DBOperationError: Connection error

        Returns:
            obj: Returns a `Response` object
        """
        pass

    def percolate(self, index, body, request_timeout=60, **kwargs):
        """ Function wrapped around MySQL python client refresh function

            The percolator allows to register queries against an index, and then
            send percolate requests which include a doc, and getting back the
            queries that match on that doc out of the set of registered queries.

        Args:
            index (str): Index Name
            body (json): Body
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def update(self, index, body, doc_id=None, bulk=False, request_timeout=60, **kwargs):
        """  Function wrapped around MySQL python client refresh function

            Update a document based on a script or partial data provided.

        Args:
            index (str): Index Name
            body (json): Body
            doc_id (str, optional): Optional argument for MySQL document id. Defaults to None.
            bulk (bool, optional): Update in bulk. Defaults to False.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def scroll(self, scroll_id, scroll='10m', request_timeout=60, **kwargs):
        """

        Args:
            scroll_id (int): Scroll ID
            scroll (str, optional): Defaults to '10m'.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error
            DBOperationError: Scroll failure

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def create(self, index, data, bulk=False, doc_id=None, request_timeout=60, **kwargs):
        """ Function to create document

            Documents can be created in bulk or individually. Calls either bulk index or create document.

        Args:
            index (str): Index Name
            data (json): Index Name
            bulk (bool, optional): Specify if bulk indexing. Defaults to False.
            doc_id (str, optional): Optional argument for MySQL document id. Defaults to None.
            ignore (int, optional): Ignore error codes. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Returns:
            dict: Returns a dictionary with responses

        """
        pass

    def bulk_index(self, index, data, doc_id=None, **kwargs):
        """ Bulk index function for ES

            This function will index documents in bulk fashion with a single request to ES

        Args:
            index (str): Index Name
            data (json): Index Name
            doc_id (str, optional): Optional argument for MySQL document id. Defaults to None.

        Raises:
            DBOperationError: Connection Error
            DBOperationError: Index Failure

        Returns:
            dict: Summary of status of all index operations
        """
        pass

    def put_template(self, template_name, template, request_timeout=60, **kwargs):
        """ Function wrapped around MySQL python client put_template function

            Create an index template that will automatically be applied to new indices created.

        Args:
            template_name (str): Template Name
            template (dict): Template/Schema
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Failed Template

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def force_merge(self, index, request_timeout=60, **kwargs):
        """ Function wrapped around MySQL python client forcemerge function

            Force merge one or more indices.

        Args:
            index (str): Index Name
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Failed Merge

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def update_settings(self, index, body, request_timeout=60, **kwargs):
        """ Function wrapped around MySQL python client put_settings function

            Change specific index level settings in real time.

        Args:
            index (str): Index Name
            body (dict): Index settings
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Failed Update

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def exists_template(self, template_name, request_timeout=60, **kwargs):
        """ Function wrapped around MySQL python client exists_template function

            Return a boolean indicating whether given template exists.

        Args:
            template_name (str): Template name
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Failed Search

        Returns:
            dict: Returns a dictionary with responses
        """
        pass

    def bulk_update(self, index, data, **kwargs):
        """ Bulk update function for ES

            This function will update documents in bulk fashion with a single request to ES

        Args:
            index (str): Index name
            data (list): List of MySQL update document bodies. Must include document Id as `doc_id` in
                each update document body

        Raises:
            KeyError: Invalid Key
            DBOperationError: Connection Error
            DBOperationError: Failed Update

        Returns:
            dict: Summary of status of all update operations
        """
        pass

    def bulk_delete(self, index, doc_id_list, **kwargs):
        """ Bulk delete function for ES

            This function will delete documents in bulk fashion with a single request to ES

        Args:
            index (str): Index name
            doc_id_list (list): List of MySQL document IDs to be deleted

        Raises:
            DBOperationError: Connection Error
            DBOperationError: Failed Update

        Returns:
            dict: Summary of status of all delete operation.

        """
        pass

    @staticmethod
    def parse_search_result(data):
        """ Parse search result from MySQL to remove metadata fields

        Args:
            data (dict): [description]

        Raises:
            Exception: Failed Parse

        Returns:
            list: list of hits

        """
        pass
