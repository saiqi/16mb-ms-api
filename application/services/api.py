import json
import datetime
from functools import partial

from nameko.web.handlers import HttpRequestHandler
from nameko.standalone.rpc import ClusterRpcProxy
from nameko.dependency_providers import Config
from nameko.extensions import register_entrypoint
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden
from werkzeug import Response

import jwt
import bson.json_util


class CorsHttpRequestHandler(HttpRequestHandler):
    def __init__(self, method, url, expected_exceptions=(), **kwargs):
        super().__init__(method, url, expected_exceptions=expected_exceptions)
        self.allowed_origin = kwargs.get('origin', ['*'])
        self.allowed_methods = kwargs.get('method', ['*'])
        self.allow_credentials = kwargs.get('credentials', True)

    def handle_request(self, request):
        self.request = request
        if request.method == 'OPTIONS':
            return self.response_from_result(result='')
        return super().handle_request(request)

    def response_from_result(self, *args, **kwargs):
        response = super(CorsHttpRequestHandler, self).response_from_result(*args, **kwargs)
        response.headers.add("Access-Control-Allow-Headers",
                             self.request.headers.get("Access-Control-Request-Headers"))
        response.headers.add("Access-Control-Allow-Credentials", str(self.allow_credentials).lower())
        response.headers.add("Access-Control-Allow-Methods", ",".join(self.allowed_methods))
        response.headers.add("Access-Control-Allow-Origin", ",".join(self.allowed_origin))
        return response

    @classmethod
    def decorator(cls, *args, **kwargs):

        def registering_decorator(fn, args, kwargs):
            instance = cls(*args, **kwargs)
            register_entrypoint(fn, instance)
            if instance.method in ('GET', 'POST', 'DELETE', 'PUT') and \
                    ('*' in instance.allowed_methods or instance.method in instance.allowed_methods):
                options_args = ['OPTIONS'] + list(args[1:])
                options_instance = cls(*options_args, **kwargs)
                register_entrypoint(fn, options_instance)
            return fn

        if len(args) == 1 and isinstance(args[0], types.FunctionType):
            return registering_decorator(args[0], args=(), kwargs={})
        else:
            return partial(registering_decorator, args=args, kwargs=kwargs)


class HttpAuthenticatedRequestHandler(CorsHttpRequestHandler):
    def __init__(self, method, url, expected_exceptions=(), allowed_roles=()):
        self.allowed_roles = allowed_roles
        super().__init__(method, url, expected_exceptions=expected_exceptions)

    def handle_request(self, request):

        if request.method != 'OPTIONS':
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


cors_http = HttpAuthenticatedRequestHandler.decorator


class DateEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, (datetime.datetime, datetime.date)):
            return o.isoformat()
        return json.JSONEncoder.default(self, o)


class ApiService(object):
    name = 'api_service'

    config = Config()

    @cors_http('POST', '/api/v1/command/opta/add_f1', allowed_roles=('admin', 'write',), expected_exceptions=BadRequest)
    def opta_add_f1(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.opta_collector.add_f1.call_async(**data)
            except:
                raise BadRequest()

            return Response(json.dumps(data), mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/command/metadata/add_transformation', allowed_roles=('admin',),
               expected_exceptions=BadRequest)
    def metadata_add_transformation(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.metadata.add_transformation.call_async(**data)
            except:
                raise BadRequest()

            return Response(json.dumps({'id': data['_id']}), mimetype='application/json', status=201)

    @cors_http('DELETE', '/api/v1/command/metadata/delete_transformation/<string:transformation_id>',
               allowed_roles=('admin',), expected_exceptions=BadRequest)
    def metadata_delete_transformation(self, request, transformation_id):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.metadata.delete_transformation.call_async(transformation_id)
            except:
                raise BadRequest()

            return Response(json.dumps({'id': transformation_id}), mimetype='application/json', status=204)

    @cors_http('POST', '/api/v1/command/metadata/deploy_function/<string:transformation_id>', allowed_roles=('admin',),
               expected_exceptions=BadRequest)
    def metadata_deploy_function(self, request, transformation_id):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = rpc.metadata.get_transformation(transformation_id)
            except:
                raise BadRequest()

            if not result:
                raise BadRequest()

            transformation = bson.json_util.loads(result)

            try:
                rpc.datastore.create_or_replace_python_function(transformation['function_name'],
                                                                transformation['function'])
            except:
                raise BadRequest()

            return Response(json.dumps({'id': transformation_id}), mimetype='application/json', status=201)

    @cors_http('GET', '/api/v1/query/metadata/transformations', allowed_roles=('admin',),
               expected_exceptions=BadRequest)
    def metatdata_get_all_transformations(self, request):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = bson.json_util.loads(rpc.metadata.get_all_transformations())
            except:
                raise BadRequest()

            return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/metadata/transformation/<string:transformation_id>', allowed_roles=('admin',),
               expected_exceptions=BadRequest)
    def metadata_get_transformation(self, request, transformation_id):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = bson.json_util.loads(rpc.metadata.get_transformation(transformation_id))
            except:
                raise BadRequest()

            return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('POST', '/api/v1/command/metadata/add_query', allowed_roles=('admin', 'write',),
               expected_exceptions=BadRequest)
    def metadata_add_query(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.metadata.add_query.call_async(**data)
            except:
                raise BadRequest()

            return Response(json.dumps({'id': data['_id']}), mimetype='application/json', status=201)

    @cors_http('DELETE', '/api/v1/command/metadata/delete_query/<string:query_id>',
               allowed_roles=('admin', 'write',), expected_exceptions=BadRequest)
    def metadata_delete_query(self, request, query_id):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.metadata.delete_query.call_async(query_id)
            except:
                raise BadRequest()

            return Response(json.dumps({'id': query_id}), mimetype='application/json', status=204)

    @cors_http('GET', '/api/v1/query/metadata/queries', allowed_roles=('admin', 'write'),
               expected_exceptions=BadRequest)
    def metatdata_get_all_queries(self, request):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = bson.json_util.loads(rpc.metadata.get_all_queries())
            except:
                raise BadRequest()

            return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/metadata/query/<string:query_id>', allowed_roles=('admin', 'write',),
               expected_exceptions=BadRequest)
    def metadata_get_transformation(self, request, query_id):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = bson.json_util.loads(rpc.metadata.get_query(query_id))
            except:
                raise BadRequest()

            return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('POST', '/api/v1/command/crontask/update_opta_soccer', allowed_roles=('admin',),
               expected_exceptions=BadRequest)
    def crontask_update_opta_soccer(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.crontask.update_opta_soccer.call_async(**data)
            except:
                raise BadRequest()

            return Response(json.dumps(data), mimetype='application/json', status=201)

    @cors_http('GET', '/api/v1/query/crontask/logs', allowed_roles=('admin',), expected_exceptions=BadRequest)
    def crontask_get_logs(self, request):
        method_name = None
        if 'method_name' in request.args:
            method_name = request.args['method_name']
        tail = 10
        if 'tail' in request.args:
            tail = request.args['tail']
        with ClusterRpcProxy(self.config) as rpc:
            try:
                raw_logs = bson.json_util.loads(rpc.crontask.get_logs(tail=tail, method_name=method_name))
            except:
                raise BadRequest()

            return Response(json.dumps(raw_logs, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/datareader/select', allowed_roles=('admin', 'write', 'read',),
               expected_exceptions=BadRequest)
    def datareader_select(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = bson.json_util.loads(rpc.datareader.select(**data))
            except:
                raise BadRequest()

            return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')
