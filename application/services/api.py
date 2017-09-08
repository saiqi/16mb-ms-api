import json
import datetime

from nameko.web.handlers import HttpRequestHandler
from nameko.standalone.rpc import ClusterRpcProxy
from nameko.dependency_providers import Config
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden
from werkzeug import Response

import jwt
import bson.json_util


class HttpAuthenticatedRequestHandler(HttpRequestHandler):
    def __init__(self, method, url, allowed_roles, expected_exceptions=()):
        self.allowed_roles = allowed_roles
        super().__init__(method, url, expected_exceptions=expected_exceptions)

    def handle_request(self, request):

        if not request.headers.get('Authorization'):
            raise Unauthorized()

        token = request.headers.get('Authorization')

        try:
            payload = jwt.decode(token, self.container.config['SECRET_KEY'], algorithms='HS256')
        except jwt.DecodeError:
            raise Unauthorized()
        except jwt.ExpiredSignatureError:
            raise Unauthorized()

        if payload['role'] not in self.allowed_roles:
            raise Forbidden()

        return super(HttpAuthenticatedRequestHandler, self).handle_request(request)


http = HttpAuthenticatedRequestHandler.decorator


class ApiService(object):
    name = 'api_service'

    config = Config()

    @http('POST', '/api/v1/command/opta/add_f1', ('admin', 'write',), expected_exceptions=BadRequest)
    def opta_add_f1(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.opta_collector.add_f1.call_async(**data)
            except:
                raise BadRequest()

            return Response(json.dumps(data), mimetype='application/json', status=201)

    @http('POST', '/api/v1/command/metadata/add_transformation', ('admin',), expected_exceptions=BadRequest)
    def metadata_add_transformation(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.metadata.add_transformation.call_async(**data)
            except:
                raise BadRequest()

            return Response(json.dumps({'id': data['_id']}), mimetype='application/json', status=201)

    @http('POST', '/api/v1/command/metadata/delete_transformation/<string:transformation_id>', ('admin',),
          expected_exceptions=BadRequest)
    def metadata_delete_transformation(self, request, transformation_id):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.metadata.delete_transformation.call_async(transformation_id)
            except:
                raise BadRequest()

            return Response(json.dumps({'id': transformation_id}), mimetype='application/json', status=204)

    @http('GET', '/api/v1/query/metadata/transformations', ('admin',), expected_exceptions=BadRequest)
    def metatdata_get_all_transformations(self, request):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = rpc.metadata.get_all_transformations()
            except:
                raise BadRequest()

            return Response(result, mimetype='application/json')

    @http('GET', '/api/v1/query/metadata/transformation/<string:transformation_id>', ('admin',),
          expected_exceptions=BadRequest)
    def metadata_get_transformation(self, request, transformation_id):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = rpc.metadata.get_transformation(transformation_id)
            except:
                raise BadRequest()

            return Response(result, mimetype='application/json')

    @http('POST', '/api/v1/command/crontask/update_opta_soccer', ('admin',), expected_exceptions=BadRequest)
    def crontask_update_opta_soccer(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.crontask.update_opta_soccer.call_async(**data)
            except:
                raise BadRequest()

            return Response(json.dumps(data), mimetype='application/json', status=201)

    @http('GET', '/api/v1/query/datareader/select', ('admin', 'write', 'read',), expected_exceptions=BadRequest)
    def datareader_select(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = rpc.datareader.select(**data)
            except:
                raise BadRequest()

            return Response(result, mimetype='application/json')
