import os
import json
import logging
import requests
import elasticsearch
import functools
from .helpers import common_util as utils
from .helpers.DBOperationError import DBOperationError


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
        pass
