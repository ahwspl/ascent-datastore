import os
import json
import logging
import requests
import elasticsearch
import functools
from ..helpers import common_util as utils
from ..helpers.DBOperationError import DBOperationError


class AscentESAdaptor(object):
    """An adaptor to create and manage ElasticSearch, Neo4j, etc. database client. Currently only Elasticsearch is supported.

    Args:
        ds_config (str): An abosolute path to the config file.
    """

    def __init__(self, ds_config=None):
        self.logger = logging.getLogger(__name__)

        configs = ds_config if isinstance(ds_config, dict) else utils.load_config_file(ds_config)
        self.db = None

        if 'elasticsearch' not in configs:
            raise KeyError('elasticsearch')

        self.es_configs = dict()
        self.es_configs['uri'] = configs['elasticsearch']['uri']
        self.es_configs['idx_uri'] = configs['elasticsearch']['idx_uri']
        self.es_configs['verify_certs'] = configs['elasticsearch']['ssl_verify']

        self.auth_type, es_username, es_password = None, configs['elasticsearch'].get('username', None), None
        if es_username is not None:
            self.auth_type = "Basic"
            if configs['elasticsearch'].get('password', None) is not None:
                es_password = configs['elasticsearch']['password']
            elif os.environ.get("ES_PASS") is not None:
                es_password = os.environ.get("ES_PASS")
            else:
                self.logger.warn("Database password is not defined!")
            self.es_configs['http_auth'] = (es_username, es_password)
        else:
            self.auth_type = "Bearer"
            self.es_configs['http_auth'] = ()

        self.es_configs['timeout'] = configs['elasticsearch']['timeout']

        self.internal_conf = utils.read_config_file(
            utils.get_config_dir() + "/handler_config.cfg"
        )

        kwargs = dict()
        for item, value in self.es_configs.items():
            if value is not None:
                kwargs[item] = value
        self.logger.info("Connecting to {} database...".format('elasticsearch'))
        self.db = elasticsearch.Elasticsearch([self.es_configs['uri']], **kwargs)

    def _oauth2_decorator():
        def decorator(func):
            @functools.wraps(func)
            def wrapper(self, *args, **kwargs):
                if self.auth_type == 'Bearer':
                    if 'access_token' in kwargs:
                        self.db.transport.connection_pool.connection.headers.update(
                            {'authorization': "Bearer {}".format(kwargs['access_token'])})
                        del kwargs['access_token']
                    else:
                        raise DBOperationError('Access Token not provided')
                result = func(self, *args, **kwargs)
                return result

            return wrapper

        return decorator

    # elasticsearch generic crud operations -> get, post
    def _requests_get(self, uri, data=None, timeout=60, **kwargs):
        """Wrapper method around request.post to support multiple authorization types

        Args:
            uri ([type]): [description]
            data ([type], optional): [description]. Defaults to None.
            timeout (int, optional): [description]. Defaults to 60.

        Returns:
            [type]: [description]
        """
        if self.auth_type == "Basic":
            return requests.get(
                uri,
                data=json.dumps(data),
                timeout=timeout,
                headers={
                    "Content-Type": "application/json"
                },
                verify=self.es_configs['verify_certs'],
                auth=requests.auth.HTTPBasicAuth(
                    self.es_configs['http_auth'][0], self.es_configs['http_auth'][1]
                )
            )
        else:
            if 'access_token' not in kwargs:
                raise DBOperationError('Access Token not provided!')
            return requests.get(
                uri,
                data=json.dumps(data),
                timeout=timeout,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer {}".format(kwargs['access_token'])
                },
                verify=self.es_configs['verify_certs']
            )

    def _requests_post(self, uri, data=None, json=None, params=None, timeout=60, **kwargs):
        """Wrapper method around request.post to support multiple authorization types

        Args:
            uri ([type]): [description]
            data ([type], optional): [description]. Defaults to None.
            json ([type], optional): [description]. Defaults to None.
            params ([type], optional): [description]. Defaults to None.
            timeout (int, optional): [description]. Defaults to 60.
            access_token ([type], optional): [description]. Defaults to None.

        Returns:
            [type]: [description]
        """
        if self.auth_type == 'Basic':
            return requests.post(
                url=uri,
                data=data,
                json=json,
                timeout=timeout,
                params=params,
                headers={
                    "Content-Type": "application/json"
                },
                verify=self.es_configs['verify_certs'],
                auth=requests.auth.HTTPBasicAuth(
                    self.es_configs['http_auth'][0], self.es_configs['http_auth'][1]
                )
            )
        else:
            if 'access_token' not in kwargs:
                raise DBOperationError('Access Token not provided')
            return requests.post(
                url=uri,
                data=data,
                json=json,
                timeout=timeout,
                params=params,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer {}".format(kwargs['access_token'])
                },
                verify=self.es_configs['verify_certs']
            )

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
        if search_all:
            query = {
                'query': {
                    'match_all': {}
                }
            }
        elif isinstance(custom, dict) or type(fields) in [list, dict, type(None)]:
            if fields is None:
                filter_items = {'must': []}
            elif criteria == 'must':
                filter_items = {criteria: [{method: fields}] if isinstance(fields, dict) else [
                    {method: field} for field in fields
                ]}
            else:
                filter_items = {'must': [{'bool': {criteria: [{method: fields}] if isinstance(fields, dict) else [
                    {method: field} for field in fields
                ]}}]}

            query = {
                'query': {
                    'constant_score': {
                        'filter': {
                            'bool': custom or filter_items
                        }
                    }
                }
            }
        else:
            err = 'Term {} is not valid.'.format(fields)
            self.logger.error(err)
            return {'error': err}

        if isinstance(range, dict) and not search_all:
            must_filter = query['query']['constant_score']['filter']['bool']
            if not isinstance(must_filter.get('must'), list):
                must_filter['must'] = []
            must_filter['must'].append({'range': range})

        self.logger.debug(json.dumps(query, indent=4))

        return query

    def get_watcher_with_id(self, watcher_id, **kwargs):
        """Get a watcher with ID

        Args:
            watcher_id (int): Watcher ID

        Returns:
            dict: Returns a dictionary with responses
        """
        body = {
            "query": {
                "match": {
                    "_id": watcher_id
                }
            }
        }
        path = self.internal_conf['elasticsearch']['WATCHER_API_SEARCH_PATH']
        response = self._requests_get(
            uri=self.es_configs['uri'] + path,
            data=json.dumps(body),
            timeout=self.es_configs['timeout'],
            **kwargs
        )
        return json.loads(response.text)

    def search_watcher(self, body=None, **kwargs):
        """Search a watcher

        Args:
            body (str):

        Returns:
            dict: Returns a dictionary with responses
        """
        path = self.internal_conf['elasticsearch']['WATCHER_API_SEARCH_PATH']
        response = self._requests_get(
            uri=self.es_configs['uri'] + path,
            data=body,
            timeout=self.es_configs['timeout'],
            **kwargs
        )
        return json.loads(response.text)

    def create_watcher(self, watcher_id, body, params=None, **kwargs):
        """Create a watcher

        Args:
            watcher_id (int): Watcher ID
            body (str):
            params (dict(str)):

        Returns:
            dict: Returns a dictionary with responses
        """
        watcher_api_prefix = self.internal_conf['elasticsearch']['WATCHER_API_PREFIX']
        url = self.es_configs['uri'] + watcher_api_prefix + watcher_id
        response = self._requests_post(
            uri=url,
            data=body,
            params=params,
            **kwargs
        )
        return response

    def execute_watcher(self, watcher_id, **kwargs):
        """Execute a Watcher

        Args:
            watcher_id (int): Watcher ID

        Returns:
            dict: Returns a dictionary with responses
        """
        self.logger.info("Executing watcher {}".format(watcher_id))
        if not self.check_watcher_exists(watcher_id, **kwargs):
            self.logger.info(f"{watcher_id} does not exists")
            return
        suffix = self.internal_conf['elasticsearch']['WATCHER_API_EXECUTE_SUFFIX']
        watcher_api_prefix = self.internal_conf['elasticsearch']['WATCHER_API_PREFIX']
        self.logger.debug(self.es_configs['uri'] + watcher_api_prefix + watcher_id + suffix)
        response_execute = self._requests_post(
            uri=self.es_configs['uri'] + watcher_api_prefix + watcher_id + suffix,
            timeout=self.es_configs['timeout'],
            **kwargs
        )
        self.logger.debug(response_execute)
        return response_execute

    def activate_watcher(self, watcher_id, **kwargs):
        """Activate a watcher

        Args:
            watcher_id (int): Watcher ID

        Returns:
            dict: Returns a dictionary with responses
        """
        self.logger.info("Activating watcher {}".format(watcher_id))
        if not self.check_watcher_exists(watcher_id, **kwargs):
            self.logger.info(f"{watcher_id} does not exists")
            return
        suffix = self.internal_conf['elasticsearch']['WATCHER_API_ACTIVATE_SUFFIX']
        watcher_api_prefix = self.internal_conf['elasticsearch']['WATCHER_API_PREFIX']
        self.logger.info(self.es_configs['uri'] + watcher_api_prefix + watcher_id + suffix)
        response_activate = self._requests_post(
            uri=self.es_configs['uri'] + watcher_api_prefix + watcher_id + suffix,
            timeout=self.es_configs['timeout'],
            **kwargs
        )
        self.logger.debug(response_activate)
        return response_activate

    def deactivate_watcher(self, watcher_id, **kwargs):
        """Deactivate a watcher

        Args:
            watcher_id (int): Watcher ID

        Returns:
            dict: Returns a dictionary with responses
        """
        self.logger.info("Deactivating watcher {}".format(watcher_id))
        if not self.check_watcher_exists(watcher_id, **kwargs):
            self.logger.info(f"{watcher_id} does not exists")
            return
        suffix = self.internal_conf['elasticsearch']['WATCHER_API_DEACTIVATE_SUFFIX']
        watcher_api_prefix = self.internal_conf['elasticsearch']['WATCHER_API_PREFIX']
        self.logger.info(self.es_configs['uri'] + watcher_api_prefix + watcher_id + suffix)
        response_activate = self._requests_post(
            uri=self.es_configs['uri'] + watcher_api_prefix + watcher_id + suffix,
            timeout=self.es_configs['timeout'],
            **kwargs
        )
        self.logger.debug(response_activate)
        return response_activate

    def delete_watcher(self, watcher_id, **kwargs):
        """Delete a watcher

        Args:
            watcher_id (int): Watcher ID

        Returns:
            dict: Returns a dictionary with responses
        """
        self.logger.info("Deleting watcher {}".format(watcher_id))
        watcher_api_prefix = self.internal_conf['elasticsearch']['WATCHER_API_PREFIX']
        response_delete = requests.delete(
            uri=self.es_configs['uri'] + watcher_api_prefix + watcher_id,
            timeout=self.es_configs['timeout'],
            headers={
                "Content-Type": "application/json"
            }
        )
        if json.loads(response_delete.text)['found']:
            self.logger.info('watcher deleted')
        else:
            self.logger.info('watcher does not exist or already deleted')
        return response_delete

    def check_watcher_exists(self, watcher_id, **kwargs):
        """Check if watcher exists

        Args:
            watcher_id (int): Watcher ID

        Returns:
            bool: True if watcher exists
        """
        body = {
            "stored_fields": [],
            "query": {
                "match": {
                    "_id": watcher_id
                }
            }
        }
        path = self.internal_conf['elasticsearch']['WATCHER_API_SEARCH_PATH']
        response_exists = self._requests_get(
            uri=self.es_configs['uri'] + path,
            data=json.dumps(body),
            timeout=self.es_configs['timeout'],
            **kwargs
        )
        num_watcher = json.loads(response_exists.text)['hits']['total']
        if num_watcher == 1:
            return True
        elif num_watcher == 0:
            return False
        else:
            self.logger.warning('Warning: incorrect number of watches for ' + str(watcher_id))
            return True

    @_oauth2_decorator()
    def search(self, index, body=None, scroll=None, request_timeout=60, size=10000, **kwargs):
        """ Function wrapped around Elasticsearch python client search function
            Search function to query Elasticsearch
            `<http://www.elastic.co/guide/en/elasticsearch/reference/current/search-search.html>`

        Args:
            index (str): Index name
            body (dict, optional): Elasticsearch search query. Defaults to None.
            scroll (str, optional): Scan and scroll option. Scroll parameter telling Elasticsearch how long it should keep
                    the scroll open e.g 1m (1 minute). Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.
            size (int, optional): Size of records to return. Defaults to 10000.

        Raises:
            DBOperationError: Index not found
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with Elasticsearch responses
        """
        try:
            if scroll:
                return self.db.search(index=index, body=body, scroll=scroll, request_timeout=self.es_configs['timeout'], size=size, **kwargs)
            else:
                return self.db.search(index=index, body=body, request_timeout=self.es_configs['timeout'], size=size, **kwargs)
        except elasticsearch.exceptions.NotFoundError:
            raise DBOperationError('ES search failed. Index {} not found'.format(index))
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES search failed. Connection Error')

    @_oauth2_decorator()
    def msearch(self, index, body=None, request_timeout=60, **kwargs):
        """ Function wrapped around Elasticsearch python client multisearch search function
            MultiSearch function to query Elasticsearch
            `<http://www.elastic.co/guide/en/elasticsearch/reference/current/search-multi-search.html>`_

        Args:
            index (str): Index name
            body (dict, optional): Elasticsearch search query. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Index not found
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with Elasticsearch responses
        """
        try:
            return self.db.msearch(index=index, body=body, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.exceptions.NotFoundError:
            raise DBOperationError('ES search failed. Index {} not found'.format(index))
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES search failed. Connection Error')

    @_oauth2_decorator()
    def mget(self, index, body=None, request_timeout=60, **kwargs):
        """ Function wrapped around Elasticsearch python client multi get function

        Args:
            index (str): Index name
            body (dict, optional): Elasticsearch search query. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Index not found
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with Elasticsearch responses
        """
        try:
            return self.db.mget(index=index, body=body, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.exceptions.NotFoundError:
            raise DBOperationError('ES search failed. Index {} not found'.format(index))
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES search failed. Connection Error')

    @_oauth2_decorator()
    def get(self, index, doc_id=None, request_timeout=60, **kwargs):
        """ Function wrapped around Elasticsearch python client get function

            function to get a typed JSON document from the index based on its id
            `<http://www.elastic.co/guide/en/elasticsearch/reference/current/docs-get.html>`_

        Args:
            index (str): Index name
            doc_id (str, optional): Optional argument for Elasticsearch document id. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Index not found
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with Elasticsearch responses
        """
        try:
            return self.db.get(index=index, id=doc_id, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.exceptions.NotFoundError:
            raise DBOperationError('ES get failed. Index {} not found'.format(index))
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES get failed. Connection Error')

    @_oauth2_decorator()
    def update_by_query(self, index, doc_id=None, request_timeout=60, **kwargs):
        """ Function wrapped around Elasticsearch python client get function

            function to get a typed JSON document from the index based on its id
            <http://www.elastic.co/guide/en/elasticsearch/reference/current/docs-get.html>

        Args:
            index (str): Index name
            doc_id (str, optional): Optional argument for Elasticsearch document id. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Index not found
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with Elasticsearch responses
        """
        try:
            return self.db.update_by_query(index=index, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.exceptions.NotFoundError:
            raise DBOperationError('ES get failed. Index {} not found'.format(index))
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES get failed. Connection Error')

    @_oauth2_decorator()
    def create_document(self, index, body, doc_id=None, request_timeout=60, **kwargs):
        """ Function wrapped around Elasticsearch python client index function

            Adds or updates a typed JSON document in a specific index, making it searchable.
            `<http://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html>`_

        Args:
            index (str): Index name
            body (dict): Document
            doc_id (str, optional): Optional argument for Elasticsearch document id. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with Elasticsearch responses
        """
        try:
            return self.db.index(index=index, id=doc_id, body=body, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES create failed. Connection Error')

    @_oauth2_decorator()
    def create_index(self, index, body=None, request_timeout=60, **kwargs):
        """ Function wrapped around Elasticsearch python client indices function

            Adds or updates a typed JSON document in a specific index, making it searchable.
            `<http://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html>`_

        Args:
            index (str): Index name
            body (dict): The document. Defaults to None.
            ignore (int, optional): Ignore error codes. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with Elasticsearch responses
        """
        try:
            return self.db.indices.create(index=index, body=body, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES create failed. Connection Error')

    @_oauth2_decorator()
    def delete_documents_by_query(self, index, body, request_timeout=120, **kwargs):
        """Delete a document

        Args:
            index (str): Index name
            body (dict): The document. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with Elasticsearch responses
        """
        try:
            return self.db.delete_by_query(index=index, body=body, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES delete failed. Connection Error')

    @_oauth2_decorator()
    def delete_document(self, index, doc_id, request_timeout=60, **kwargs):
        """ Function wrapped around Elasticsearch python client delete function

            Delete a typed JSON document from a specific index based on its id.
            `<http://www.elastic.co/guide/en/elasticsearch/reference/current/docs-delete.html>`_

        Args:
            index (str): Index name
            doc_id (str): Elasticsearch Document ID
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with Elasticsearch responses
        """
        try:
            return self.db.delete(index=index, id=doc_id, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES delete failed. Connection Error')

    @_oauth2_decorator()
    def delete_index(self, index, request_timeout=60, **kwargs):
        """ Function wrapped around Elasticsearch python client indices.delete function

            Delete an index in Elasticsearch
            `<http://www.elastic.co/guide/en/elasticsearch/reference/current/indices-delete-index.html>`_

        Args:
            index (str): Index name
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with Elasticsearch responses
        """
        try:
            return self.db.indices.delete(index=index, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES delete failed. Connection Error')

    @_oauth2_decorator()
    def exists_document(self, index, doc_id, request_timeout=60, **kwargs):
        """ Function wrapped around Elasticsearch python client exists function

            Returns a boolean indicating whether or not given document exists in Elasticsearch.
            `<http://www.elastic.co/guide/en/elasticsearch/reference/current/docs-get.html>`_

        Args:
            index (str): Index name
            doc_id (str): Elasticsearch Document ID
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            bool: Returns a boolean indicating whether or not given document exists in Elasticsearch.
        """
        try:
            return self.db.exists(index=index, id=doc_id, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES exists failed. Connection Error')

    @_oauth2_decorator()
    def exists_index(self, index, request_timeout=60, **kwargs):
        """ Function wrapped around Elasticsearch python client indices.exists function

            Return a boolean indicating whether given index exists.
            `<http://www.elastic.co/guide/en/elasticsearch/reference/current/indices-exists.html>`_

        Args:
            index (str): Index name
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            bool: Return a boolean indicating whether given index exists.
        """
        try:
            return self.db.indices.exists(index=index, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES exists failed. Connection Error')

    @_oauth2_decorator()
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
        try:
            return self.db.indices.exists_alias(name=name, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES exists failed. Connection Error')

    @_oauth2_decorator()
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
        try:
            return self.db.indices.put_alias(index=index, name=name, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES exists failed. Connection Error')

    @_oauth2_decorator()
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
        try:
            return self.db.indices.update_aliases(body=body, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES exists failed. Connection Error')

    @_oauth2_decorator()
    def indices_delete(self, index, request_timeout=60, **kwargs):
        """  Function wrapped around Elasticsearch python client indices.delete function

            Delete an index in Elasticsearch
            `<http://www.elastic.co/guide/en/elasticsearch/reference/current/indices-delete-index.html>`_

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
            return self.db.indices.delete(index=index, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES exists failed. Connection Error')

    @_oauth2_decorator()
    def refresh(self, index, request_timeout=60, **kwargs):
        """ Function wrapped around Elasticsearch python client refresh function

            Explicitly refresh one or more index, making all operations performed
            since the last refresh available for search.
            `<http://www.elastic.co/guide/en/elasticsearch/reference/current/indices-refresh.html>`_

        Args:
            index (str): Index name
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with responses
        """
        try:
            return self.db.indices.refresh(index=index, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES refresh failed. Connection Error')

    def reindex(self, data, **kwargs):
        """ Function wrapped around post method of request python client
            Sends a post request

        Args:
            data (dict): Post data for Elasticsearch reindex

        Raises:
            DBOperationError: Internal Error
            DBOperationError: Connection error

        Returns:
            obj: Returns a `Response` object
        """
        try:
            response = self._requests_post(
                uri=self.es_configs['uri'] + "/_reindex",
                json=data,
                **kwargs
            )
            if response.status_code >= 400:
                raise DBOperationError('ES reindex failed. Internal Error')
            return json.loads(response.text)
        except elasticsearch.exceptions.ConnectionError or json.decoder.JSONDecodeError or DBOperationError:
            raise DBOperationError('ES reindex failed. Connection Error')

    @_oauth2_decorator()
    def percolate(self, index, body, request_timeout=60, **kwargs):
        """ Function wrapped around Elasticsearch python client refresh function

            The percolator allows to register queries against an index, and then
            send percolate requests which include a doc, and getting back the
            queries that match on that doc out of the set of registered queries.
            `<http://www.elastic.co/guide/en/elasticsearch/reference/current/search-percolate.html>`_

        Args:
            index (str): Index Name
            body (json): Body
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with responses
        """
        try:
            return self.db.percolate(index=index, body=body, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES percolate failed. Connection Error')

    @_oauth2_decorator()
    def update(self, index, body, doc_id=None, bulk=False, request_timeout=60, **kwargs):
        """  Function wrapped around Elasticsearch python client refresh function

            Update a document based on a script or partial data provided.
            `<http://www.elastic.co/guide/en/elasticsearch/reference/current/docs-update.html>`_

        Args:
            index (str): Index Name
            body (json): Body
            doc_id (str, optional): Optional argument for Elasticsearch document id. Defaults to None.
            bulk (bool, optional): Update in bulk. Defaults to False.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Connection error

        Returns:
            dict: Returns a dictionary with responses
        """
        try:
            if bulk:
                return self.bulk_update(index, body)
            else:
                self.logger.info(type(body))
                return self.db.update(index=index, id=doc_id, body=body, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES update failed. Connection Error')

    @_oauth2_decorator()
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
        try:
            return self.db.scroll(scroll_id=scroll_id, scroll=scroll, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES Scroll failed. Connection Error')
        except elasticsearch.ElasticsearchException as e:
            # elasticsearch.exceptions.RequestError would be caught here in the case scroll id was invalid
            self.logger.error(e)
            raise DBOperationError('ES Scroll failed.')

    def create(self, index, data, bulk=False, doc_id=None, request_timeout=60, **kwargs):
        """ Function to create document

            Documents can be created in bulk or individually. Calls either bulk index or create document.

        Args:
            index (str): Index Name
            data (json): Index Name
            bulk (bool, optional): Specify if bulk indexing. Defaults to False.
            doc_id (str, optional): Optional argument for Elasticsearch document id. Defaults to None.
            ignore (int, optional): Ignore error codes. Defaults to None.
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Returns:
            dict: Returns a dictionary with responses

        """
        if bulk:
            return self.bulk_index(index, data, doc_id=doc_id, **kwargs)
        else:
            return self.create_document(index, data, doc_id=doc_id, request_timeout=self.es_configs['timeout'], **kwargs)

    def bulk_index(self, index, data, doc_id=None, **kwargs):
        """ Bulk index function for ES

            This function will index documents in bulk fashion with a single request to ES

        Args:
            index (str): Index Name
            data (json): Index Name
            doc_id (str, optional): Optional argument for Elasticsearch document id. Defaults to None.

        Raises:
            DBOperationError: Connection Error
            DBOperationError: Index Failure

        Returns:
            dict: Summary of status of all index operations
        """
        op_descriptor = {
            'index': {
                '_index': index
            }
        }
        all_json_data = ""
        for doc in data:
            if doc_id is not None:
                op_descriptor['index']['_id'] = doc.pop('doc_id')
            indexible_json_doc = json.dumps(op_descriptor) + '\n' + json.dumps(doc)
            all_json_data = all_json_data + '\n' + indexible_json_doc
        all_json_data = all_json_data + '\n'
        try:
            pub_response = self._requests_post(
                uri=self.es_configs['idx_uri'] + "/_bulk/",
                data=all_json_data,
                **kwargs
            )
            if 'errors' in (json.loads(pub_response.text)).keys():
                if json.loads(pub_response.text)['errors'] is False:
                    response = {
                        "All_published": True
                    }
                else:
                    response = {
                        "All_published": False
                    }
            else:
                response = json.loads(pub_response.text)
            return response
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES reindex failed. Connection Error')
        except elasticsearch.ElasticsearchException as e:
            self.logger.error(e)
            raise DBOperationError('ES bulk index failed')

    @_oauth2_decorator()
    def put_template(self, template_name, template, request_timeout=60, **kwargs):
        """ Function wrapped around Elasticsearch python client put_template function

            Create an index template that will automatically be applied to new indices created.
            `<http://www.elastic.co/guide/en/elasticsearch/reference/current/indices-templates.html>`_

        Args:
            template_name (str): Template Name
            template (dict): Template/Schema
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Failed Template

        Returns:
            dict: Returns a dictionary with responses
        """
        try:
            return self.db.indices.put_template(name=template_name, body=template, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.ElasticsearchException as e:
            self.logger.error(e)
            raise DBOperationError('ES put template failed')

    @_oauth2_decorator()
    def force_merge(self, index, request_timeout=60, **kwargs):
        """ Function wrapped around Elasticsearch python client forcemerge function

            Force merge one or more indices.
            `<https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-forcemerge.html>`_

        Args:
            index (str): Index Name
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Failed Merge

        Returns:
            dict: Returns a dictionary with responses
        """
        try:
            return self.db.indices.forcemerge(index=index, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.ElasticsearchException as e:
            self.logger.error(e)
            raise DBOperationError('ES force merge failed')

    @_oauth2_decorator()
    def update_settings(self, index, body, request_timeout=60, **kwargs):
        """ Function wrapped around Elasticsearch python client put_settings function

            Change specific index level settings in real time.
            `<https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-update-settings.html>`

        Args:
            index (str): Index Name
            body (dict): Index settings
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Failed Update

        Returns:
            dict: Returns a dictionary with responses
        """
        try:
            return self.db.indices.put_settings(index=index, body=body, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.ElasticsearchException as e:
            self.logger.error(e)
            raise DBOperationError('ES update settings failed')

    @_oauth2_decorator()
    def exists_template(self, template_name, request_timeout=60, **kwargs):
        """ Function wrapped around Elasticsearch python client exists_template function

            Return a boolean indicating whether given template exists.
            `<http://www.elastic.co/guide/en/elasticsearch/reference/current/indices-templates.html>`

        Args:
            template_name (str): Template name
            request_timeout (int, optional): Request timeout set value. Defaults to 60.

        Raises:
            DBOperationError: Failed Search

        Returns:
            dict: Returns a dictionary with responses
        """
        try:
            return self.db.indices.exists_template(template_name, request_timeout=self.es_configs['timeout'], **kwargs)
        except elasticsearch.ElasticsearchException as e:
            self.logger.error(e)
            raise DBOperationError('ES template search failed')

    def bulk_update(self, index, data, **kwargs):
        """ Bulk update function for ES

            This function will update documents in bulk fashion with a single request to ES

        Args:
            index (str): Index name
            data (list): List of Elasticsearch update document bodies. Must include document Id as `doc_id` in
                each update document body

        Raises:
            KeyError: Invalid Key
            DBOperationError: Connection Error
            DBOperationError: Failed Update

        Returns:
            dict: Summary of status of all update operations
        """
        op_descriptor = {
            'update': {
                '_index': index
            }
        }
        all_json_data = ""
        for doc in data:
            if 'doc_id' in doc:
                op_descriptor['update']['_id'] = doc.pop('doc_id')
                update_json_doc = '{0}\n{1}'.format(json.dumps(op_descriptor), json.dumps({"doc": doc}))
                all_json_data = '{0}\n{1}'.format(all_json_data, update_json_doc)
            else:
                raise KeyError('doc_id key missing or invalid')
        all_json_data = all_json_data + '\n'
        try:
            pub_response = self._requests_post(
                uri=self.es_configs['idx_uri'] + "/_bulk/",
                data=all_json_data,
                **kwargs
            )
            if 'errors' in (json.loads(pub_response.text)).keys():
                if json.loads(pub_response.text)['errors'] is False:
                    response = {
                        "All_updated": True
                    }
                else:
                    response = {
                        "All_updated": False
                    }
            else:
                response = json.loads(pub_response.text)
            return response
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES bulk update failed. Connection Error')
        except elasticsearch.ElasticsearchException as e:
            self.logger.error(e)
            raise DBOperationError('ES bulk update failed')

    def bulk_delete(self, index, doc_id_list, **kwargs):
        """ Bulk delete function for ES

            This function will delete documents in bulk fashion with a single request to ES

        Args:
            index (str): Index name
            doc_id_list (list): List of Elasticsearch document IDs to be deleted

        Raises:
            DBOperationError: Connection Error
            DBOperationError: Failed Update

        Returns:
            dict: Summary of status of all delete operation.

        """
        all_json_data = ""
        for id in doc_id_list:
            op_descriptor = {
                'delete': {
                    '_index': index,
                    '_id': id
                }
            }
            all_json_data = '{0}\n{1}'.format(all_json_data, json.dumps(op_descriptor))
        all_json_data = all_json_data + '\n'
        try:
            pub_response = self._requests_post(
                self.es_configs['idx_uri'] + "/_bulk/",
                data=all_json_data,
                **kwargs)
            if 'errors' in (json.loads(pub_response.text)).keys():
                if json.loads(pub_response.text)['errors'] is False:
                    response = {
                        "All_deleted": True
                    }
                else:
                    response = {
                        "All_deleted": False
                    }
            else:
                response = json.loads(pub_response.text)
            return response
        except elasticsearch.exceptions.ConnectionError:
            raise DBOperationError('ES bulk update failed. Connection Error')
        except elasticsearch.ElasticsearchException as e:
            self.logger.error(e)
            raise DBOperationError('ES bulk update failed')

    @staticmethod
    def parse_search_result(data):
        """ Parse search result from ES to remove metadata fields

        Args:
            data (dict): [description]

        Raises:
            Exception: Failed Parse

        Returns:
            list: list of hits

        """
        try:
            result = []
            hits = data['hits']['hits']
            for hit in hits:
                result.append(hit.get('_source'))
            return result
        except Exception as e:
            raise Exception('Could not parse search result. {}'.format(e))
