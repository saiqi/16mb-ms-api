import json
import datetime
from functools import partial
from logging import getLogger
import types

from nameko.exceptions import serialize
from nameko.web.handlers import HttpRequestHandler
from nameko.rpc import RpcProxy
from nameko.extensions import register_entrypoint
from nameko.dependency_providers import DependencyProvider
from nameko.events import EventDispatcher
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden, NotFound
from werkzeug import Response

import jwt
import bson.json_util

_log = getLogger(__name__)

class ErrorHandler(DependencyProvider):

    def worker_result(self, worker_ctx, res, exc_info):
        if exc_info is None:
            return

        exc_type, exc, tb = exc_info
        _log.error(str(exc))

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

    def response_from_exception(self, exc):
        if isinstance(exc, self.expected_exceptions) or\
        isinstance(exc, (Unauthorized, Forbidden, NotFound, BadRequest)):
            if isinstance(exc, NotFound):
                status_code = 404
            elif isinstance(exc, Unauthorized):
                status_code = 401
            elif isinstance(exc, Forbidden):
                status_code = 403
            else:
                status_code = 400
        else:
            status_code = 500

        error_dict = serialize(exc)
        payload = {'Error': error_dict['value']}

        response = Response(json.dumps(payload), mimetype='application/json', status=status_code)
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
        try:
            if request.method != 'OPTIONS':
                if not request.headers.get('Authorization'):
                    raise Unauthorized('Unauthorized')

                token = request.headers.get('Authorization')

                try:
                    payload = jwt.decode(token, self.container.config['SECRET_KEY'], algorithms='HS256')
                except jwt.DecodeError:
                    raise Unauthorized('Unauthorized')
                except jwt.ExpiredSignatureError:
                    raise Unauthorized('Unauthorized')

                if payload['role'] not in self.allowed_roles:
                    raise Forbidden('Forbidden')
        except Exception as exc:
            return self.response_from_exception(exc)

        return super(HttpAuthenticatedRequestHandler, self).handle_request(request)


cors_http = HttpAuthenticatedRequestHandler.decorator


class DateEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, (datetime.datetime, datetime.date)):
            return o.isoformat()
        return json.JSONEncoder.default(self, o)


class ApiService(object):
    name = 'api_service'
    error = ErrorHandler()

    metadata = RpcProxy('metadata')
    datareader = RpcProxy('datareader')
    datastore = RpcProxy('datastore')
    referential = RpcProxy('referential')
    svg_builder = RpcProxy('svg_builder')
    subscription = RpcProxy('subscription_manager')
    exporter = RpcProxy('exporter')
    tmpl = RpcProxy('template')
    loader = RpcProxy('loader')
    dispatch = EventDispatcher()

    def _handle_request_data(self, request):
        if not request.get_data():
            raise BadRequest('No data in request')

        try:
            json_data = json.loads(request.get_data(as_text=True))
        except:
            raise BadRequest('An error occured while loading request data')

        return json_data

    def _get_user_from_request(self, request):
        user = jwt.decode(request.headers.get('Authorization'), verify=False)
        return user['sub']

    @cors_http('POST', '/api/v1/command/input/add', allowed_roles=('admin'), expected_exceptions=BadRequest)
    def input_add(self, request):
        data = self._handle_request_data(request)
        self.dispatch('input_config', bson.json_util.dumps(data))
        return Response(json.dumps(data), mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/command/subscription/add', allowed_roles=('admin'), expected_exceptions=BadRequest)
    def subscription_add(self, request):
        data = self._handle_request_data(request)
        try:
            self.subscription.add_subscription(**data)
        except:
            raise BadRequest('An error occurred while adding subscription')
        return Response(json.dumps({'user': data['user']}), mimetype='application/json', status=201)

    @cors_http('GET', '/api/v1/query/subscription/<string:user>', allowed_roles=('admin'), 
        expected_exceptions=(NotFound, BadRequest))
    def subscription_get(self, request, user):
        sub = bson.json_util.loads(self.subscription.get_subscription_by_user(user))

        if not sub:
            raise NotFound('Subscription not found for user {}'.format(user))

        return Response(json.dumps(sub, cls=DateEncoder), mimetype='application/json')

    @cors_http('POST', '/api/v1/command/metadata/add_transformation', allowed_roles=('admin',),
               expected_exceptions=BadRequest)
    def metadata_add_transformation(self, request):
        data = self._handle_request_data(request)
        try:
            self.metadata.add_transformation(**data)
        except:
            raise BadRequest('An error occurred while adding transformation')

        return Response(json.dumps({'id': data['_id']}), mimetype='application/json', status=201)

    @cors_http('DELETE', '/api/v1/command/metadata/delete_transformation/<string:transformation_id>',
               allowed_roles=('admin',), expected_exceptions=BadRequest)
    def metadata_delete_transformation(self, request, transformation_id):
        try:
            self.metadata.delete_transformation(transformation_id)
        except:
            raise BadRequest('An error occurred while deleting transformation: {}'.format(transformation_id))

        return Response(json.dumps({'id': transformation_id}), mimetype='application/json', status=204)

    @cors_http('POST', '/api/v1/command/metadata/deploy_function/<string:transformation_id>', allowed_roles=('admin',),
               expected_exceptions=(BadRequest, NotFound))
    def metadata_deploy_function(self, request, transformation_id):
        try:
            result = self.metadata.get_transformation(transformation_id)
        except:
            raise NotFound('An error occurred while retrieving transformation: {}'.format(transformation_id))

        if not result:
            raise NotFound('No transformation {} in metadata'.format(transformation_id))

        transformation = bson.json_util.loads(result)

        try:
            self.datastore.create_or_replace_python_function(transformation['function_name'],
                                                            transformation['function'])
        except:
            raise BadRequest('An error occurred while creating python function')

        return Response(json.dumps({'id': transformation_id}), mimetype='application/json', status=201)

    @cors_http('GET', '/api/v1/query/metadata/transformations', allowed_roles=('admin',),
               expected_exceptions=BadRequest)
    def metatdata_get_all_transformations(self, request):
        try:
            result = bson.json_util.loads(self.metadata.get_all_transformations())
        except:
            raise BadRequest('An error occurred while retrieving all transformations')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/metadata/transformation/<string:transformation_id>', allowed_roles=('admin',),
               expected_exceptions=(BadRequest, NotFound))
    def metadata_get_transformation(self, request, transformation_id):
        try:
            result = bson.json_util.loads(self.metadata.get_transformation(transformation_id))
        except:
            raise BadRequest('An error occurred while retrieving transformation: {}'.format(transformation_id))

        if result is None:
            raise NotFound('Transformation not found')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('POST', '/api/v1/command/metadata/add_query', allowed_roles=('admin',),
               expected_exceptions=BadRequest)
    def metadata_add_query(self, request):
        data = self._handle_request_data(request)
        try:
            self.metadata.add_query(**data)
        except:
            raise BadRequest('An error occurred while adding query')

        return Response(json.dumps({'id': data['_id']}), mimetype='application/json', status=201)

    @cors_http('DELETE', '/api/v1/command/metadata/delete_query/<string:query_id>',
               allowed_roles=('admin',), expected_exceptions=BadRequest)
    def metadata_delete_query(self, request, query_id):
        try:
            self.metadata.delete_query(query_id)
        except:
            raise BadRequest('An error occurred while deleting query: {}'.format(query_id))

        return Response(json.dumps({'id': query_id}), mimetype='application/json', status=204)

    @cors_http('GET', '/api/v1/query/metadata/queries', allowed_roles=('admin', 'write',),
               expected_exceptions=BadRequest)
    def metatdata_get_all_queries(self, request):
        try:
            result = bson.json_util.loads(self.metadata.get_all_queries())
        except:
            raise BadRequest('An error occurred while retrieving all queries')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/metadata/query/<string:query_id>', allowed_roles=('admin', 'write',),
               expected_exceptions=(BadRequest, NotFound))
    def metadata_get_query(self, request, query_id):
        try:
            result = bson.json_util.loads(self.metadata.get_query(query_id))
        except:
            raise BadRequest('An error occurred while retrieving query: {}'.format(query_id))

        if result is None:
            raise NotFound('Query not found')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('POST', '/api/v1/command/metadata/add_trigger', allowed_roles=('admin',),
               expected_exceptions=BadRequest)
    def metadata_add_trigger(self, request):
        data = self._handle_request_data(request)
        try:
            self.metadata.add_trigger(**data)
        except:
            raise BadRequest('An error occurred while adding trigger')

        return Response(json.dumps({'id': data['_id']}), mimetype='application/json', status=201)

    @cors_http('DELETE', '/api/v1/command/metadata/delete_trigger/<string:trigger_id>',
               allowed_roles=('admin',), expected_exceptions=BadRequest)
    def metadata_delete_trigger(self, request, trigger_id):
        try:
            self.metadata.delete_trigger(trigger_id)
        except:
            raise BadRequest('An error occurred while deleting trigger: {}'.format(trigger_id))

        return Response(json.dumps({'id': trigger_id}), mimetype='application/json', status=204)

    @cors_http('GET', '/api/v1/query/metadata/triggers', allowed_roles=('admin',),
               expected_exceptions=BadRequest)
    def metatdata_get_all_triggers(self, request):
        try:
            result = bson.json_util.loads(self.metadata.get_all_triggers())
        except:
            raise BadRequest('An error occurred while retrieving all triggers')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/metadata/trigger/<string:trigger_id>', allowed_roles=('admin',),
               expected_exceptions=(BadRequest, NotFound))
    def metadata_get_trigger(self, request, trigger_id):
        try:
            result = bson.json_util.loads(self.metadata.get_trigger(trigger_id))
        except:
            raise BadRequest('An error occurred while retrieving trigger: {}'.format(trigger_id))

        if result is None:
            raise NotFound('Trigger not found')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('POST', '/api/v1/command/metadata/add_template', allowed_roles=('admin', 'write',),
               expected_exceptions=BadRequest)
    def metadata_add_template(self, request):
        data = self._handle_request_data(request)
        try:
            self.metadata.add_template(**data)
        except:
            raise BadRequest('An error occurred while adding template')

        return Response(json.dumps({'id': data['_id']}), mimetype='application/json', status=201)

    @cors_http('DELETE', '/api/v1/command/metadata/delete_template/<string:template_id>',
               allowed_roles=('admin', 'write',), expected_exceptions=BadRequest)
    def metadata_delete_template(self, request, template_id):
        try:
            self.metadata.delete_template(template_id)
        except:
            raise BadRequest('An error occurred while deleting template: {}'.format(template_id))

        return Response(json.dumps({'id': template_id}), mimetype='application/json', status=204)

    @cors_http('GET', '/api/v1/query/metadata/templates', allowed_roles=('admin', 'write', 'read',),
               expected_exceptions=BadRequest)
    def metatdata_get_all_templates(self, request):
        user = self._get_user_from_request(request)
        try:
            if 'bundle' in request.args:
                bundle = request.args['bundle']
                result = bson.json_util.loads(self.metadata.get_templates_by_bundle(bundle, user))
            else:
                result = bson.json_util.loads(self.metadata.get_all_templates(user))
        except:
            raise BadRequest('An error occurred while retrieving all templates')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/metadata/template/<string:template_id>', allowed_roles=('admin', 'write', 'read',),
               expected_exceptions=(BadRequest, NotFound))
    def metadata_get_template(self, request, template_id):
        user = self._get_user_from_request(request)
        try:
            result = bson.json_util.loads(self.metadata.get_template(template_id, user))
        except:
            raise BadRequest('An error occurred while retrieving template: {}'.format(template_id))

        if result is None:
            raise NotFound('Template not found')

        if 'svg' in result and result['svg']:
            responsive = self.svg_builder.make_responsive(result['svg'])
            result['preview'] = self.exporter.text_to_path(responsive)

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('POST', '/api/v1/command/metadata/template/add_query/<string:template_id>',
               allowed_roles=('admin', 'write',), expected_exceptions=BadRequest)
    def metadata_add_query_to_template(self, request, template_id):
        data = self._handle_request_data(request)
        try:
            self.metadata.add_query_to_template(template_id, **data)
        except:
            raise BadRequest('An error occurred while adding query to template {}'.format(template_id))

        return Response(json.dumps({'id': template_id}), mimetype='application/json', status=201)

    @cors_http('DELETE', '/api/v1/command/metadata/template/delete_query/<string:template_id>/<string:query_id>',
               allowed_roles=('admin', 'write',), expected_exceptions=BadRequest)
    def metadata_delete_query_from_template(self, request, template_id, query_id):
        try:
            self.metadata.delete_query_from_template(template_id, query_id)
        except:
            raise BadRequest('An error occurred while deleting query from template {}'.format(template_id))

        return Response(json.dumps({'id': template_id}), mimetype='application/json', status=204)

    @cors_http('POST', '/api/v1/command/metadata/template/update_svg/<string:template_id>',
               allowed_roles=('admin', 'write',), expected_exceptions=BadRequest)
    def metadata_update_svg_in_template(self, request, template_id):
        data = self._handle_request_data(request)
        try:
            self.metadata.update_svg_in_template(template_id, **data)
        except:
            raise BadRequest('An error occurred while updating svg in template {}'.format(template_id))

        return Response(json.dumps({'id': template_id}), mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/command/metadata/template/update_html/<string:template_id>',
               allowed_roles=('admin', 'write',), expected_exceptions=BadRequest)
    def metadata_update_html_in_template(self, request, template_id):
        data = self._handle_request_data(request)
        try:
            self.metadata.update_html_in_template(template_id, **data)
        except:
            raise BadRequest('An error occurred while updating html in template {}'.format(template_id))

        return Response(json.dumps({'id': template_id}), mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/query/metadata/query/resolve/<string:query_id>',
               allowed_roles=('admin', 'write','read',), expected_exceptions=(BadRequest, NotFound))
    def metadata_resolve_query(self, request, query_id):
        data = self._handle_request_data(request)
        query = bson.json_util.loads(self.metadata.get_query(query_id))

        if query is None:
            raise NotFound('Query not found')

        params = None
        if query['parameters'] is not None:
            if sorted(query['parameters']) != sorted(data.keys()):
                raise BadRequest('Request arguments are mismatching expected query parameters')
            params = [data[p] for p in query['parameters']]

        try:
            if params is not None:
                result = bson.json_util.loads(self.datareader.select(query['sql'], params, limit=-1))
            else:
                result = bson.json_util.loads(self.datareader.select(query['sql'], limit=-1))
        except:
            raise BadRequest('An error occurred while executing query')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')


    @cors_http('POST', '/api/v1/query/metadata/template/resolve_with_ids/<string:template_id>',
               allowed_roles=('admin', 'read', 'write'), expected_exceptions=(BadRequest, NotFound))
    def metadata_resolve_template_with_ids(self, request, template_id):
        user = self._get_user_from_request(request)
        data = self._handle_request_data(request)

        picture_context = None
        if 'picture' in data and 'context' in data['picture']:
            picture_context = data['picture']['context']

        language = None
        if 'language' in data:
            language = data['language']

        json_only = False
        if 'json_only' in data:
            json_only = data['json_only']

        referential = None
        if 'referential' in data:
            referential = data['referential']

        user_parameters = None
        if 'user_parameters' in data:
            user_parameters = data['user_parameters']

        text_to_path = False
        if 'text_to_path' in data and data['text_to_path']:
            text_to_path = True

        result = self.tmpl.resolve(template_id, picture_context, language, json_only, 
        referential, user_parameters, user, text_to_path)

        return Response(result['content'], mimetype=result['mimetype'])


    @cors_http('POST', '/api/v1/command/datastore/create_table', allowed_roles=('admin', 'write',),
               expected_exceptions=BadRequest)
    def datastore_create_table(self, request):
        data = self._handle_request_data(request)
        try:
            self.datastore.truncate(data['target_table'])
            self.datastore.insert(**data)
        except:
            raise BadRequest('An error occured while creating table')

        return Response(json.dumps({'target_table': data['target_table']}), mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/command/datastore/create_view', allowed_roles=('admin', 'write',),
               expected_exceptions=BadRequest)
    def datastore_create_view(self, request):
        data = self._handle_request_data(request)
        try:
            self.datastore.create_or_replace_view(**data)
        except:
            raise BadRequest('An error occured while creating view')

        return Response(json.dumps({'view_name': data['view_name']}), mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/command/datastore/write', allowed_roles=('admin'),
               expected_exceptions=BadRequest)
    def datastore_write(self, request):
        data = self._handle_request_data(request)

        self.loader.write(
            data['write_policy'], data['meta'], data['target_table'], data['records'], 
            data.get('upsert_key', None), data.get('delete_keys', None), data.get('chunk_size', None))

        return Response(json.dumps({'target_table': data['target_table'], 'count': len(data['records'])}),
                        mimetype='application/json', status=201)

    @cors_http('GET', '/api/v1/query/datareader/table/<string:table_name>', allowed_roles=('admin', 'write', 'read'), 
               expected_exceptions=BadRequest)
    def datareader_get_table(self, request, table_name):
        try:
            result = bson.json_util.loads(self.datareader.select('SELECT * FROM {}'.format(table_name)))
        except:
            raise BadRequest('An error occured while retrieving data from {}'.format(table_name))

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json', status=200)

    @cors_http('GET', '/api/v1/query/datareader/select', allowed_roles=('admin'), expected_exceptions=BadRequest)
    def datareader_select(self, request):
        args = request.args

        if 'query' not in args:
            raise BadRequest('Missing query argument')
        query = args['query']

        limit = 50 if 'limit' not in args else int(args['limit'])

        try:
            result = bson.json_util.loads(self.datareader.select(query, limit=limit))
        except:
            raise BadRequest('An error occured while performing query {}'.format(query))

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json', status=200)


    @cors_http('POST', '/api/v1/command/referential/add_label', allowed_roles=('admin', 'write'),
               expected_exceptions=BadRequest)
    def referential_add_label(self, request):
        data = self._handle_request_data(request)
        try:
            self.referential.add_label(**data)
        except:
            raise BadRequest('An error occured while adding label')

        return Response(json.dumps(data), mimetype='application/json', status=201)

    @cors_http('DELETE', '/api/v1/command/referential/delete_label/<string:label_id>/<string:language>/<string:context>',
               allowed_roles=('admin', 'write'), expected_exceptions=BadRequest)
    def referential_delete_label(self, request, label_id, language, context):
        try:
            self.referential.delete_label(label_id, language, context)
        except:
            raise BadRequest('An error occured while deleting label')

        return Response(json.dumps({'id': label_id}), mimetype='application/json', status=204)

    @cors_http('GET', '/api/v1/query/referential/get_label/<string:label_id>/<string:language>/<string:context>',
               allowed_roles=('admin', 'write',), expected_exceptions=(BadRequest, NotFound))
    def referential_get_label(self, request, label_id, language, context):
        try:
            label = self.referential.get_labels_by_id_and_language_and_context(label_id, language, context)
        except:
            raise BadRequest('An error occured while getting label')

        if label is None:
            raise NotFound('Label not found')

        return Response(json.dumps(label), mimetype='application/json')

    @cors_http('POST', '/api/v1/command/referential/add_entity', allowed_roles=('admin'),
               expected_exceptions=BadRequest)
    def referential_add_entity(self, request):
        data = self._handle_request_data(request)
        try:
            self.referential.add_entity(**data)
        except:
            raise BadRequest('An error occured while adding entity')
        return Response(json.dumps({'id': data['id']}), mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/command/referential/add_translation_to_entity/<string:entity_id>', allowed_roles=('admin', 'write',),
               expected_exceptions=BadRequest)
    def referential_add_translation_to_entity(self, request, entity_id):
        data = self._handle_request_data(request)
        try:
            self.referential.add_translation_to_entity(entity_id, data['language'], data['translation'])
        except:
            raise BadRequest('An error occured while adding translation to entity')
        return Response(json.dumps({'id': entity_id}), mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/command/referential/add_multiline_to_entity/<string:entity_id>', allowed_roles=('admin', 'write',),
               expected_exceptions=BadRequest)
    def referential_add_multiline_to_entity(self, request, entity_id):
        data = self._handle_request_data(request)
        try:
            self.referential.add_multiline_to_entity(entity_id, data['multiline'])
        except:
            raise BadRequest('An error occured while adding translation to entity')
        return Response(json.dumps({'id': entity_id}), mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/command/referential/add_picture_to_entity/<string:entity_id>', allowed_roles=('admin', 'write'),
               expected_exceptions=BadRequest)
    def referential_add_picture_to_entity(self, request, entity_id):
        data = self._handle_request_data(request)
        try:
            self.referential.add_picture_to_entity(entity_id, data['context'], data['format'], data['content'], data['kind'])
        except:
            raise BadRequest('An error occured while adding picture to entity')
        return Response(json.dumps({'id': entity_id}), mimetype='application/json', status=201)

    @cors_http('DELETE', '/api/v1/command/referential/delete_picture_from_entity/<string:entity_id>/<string:context>/<string:format>/<string:kind>',
               allowed_roles=('admin', 'write'), expected_exceptions=BadRequest)
    def referential_delete_picture_from_entity(self, request, entity_id, context, format, kind):
        try:
            self.referential.delete_picture_from_entity(entity_id, context, format, kind)
        except:
            raise BadRequest('An error occured while deleting picture from entity')

        return Response(json.dumps({'id': entity_id}), mimetype='application/json', status=204)

    @cors_http('GET', '/api/v1/query/referential/entity/picture/<string:entity_id>/<string:context>/<string:format>/<string:kind>',
               allowed_roles=('admin', 'write', 'read',), expected_exceptions=NotFound)
    def referential_get_entity_picture(self, request, entity_id, context, format, kind):
        user = self._get_user_from_request(request)
        try:
            entity = bson.json_util.loads(self.referential.get_entity_by_id(entity_id, user))
        except:
            raise NotFound('Entity {} not found'.format(entity_id))

        try:
            pic = self.referential.get_entity_picture(entity_id, context, format, user, kind)
        except:
            raise NotFound('Picture ({}/{}) not found for entity {}'.format(context, format, entity_id))

        if pic is None:
            raise NotFound('Picture ({}/{}) not found for entity {}'.format(context, format, entity_id))            
        
        if kind == 'vectorial':
            Response(pic, mimetype='image/svg+xml', status=200)

        return Response(pic, mimetype='image/png', status=200)

    @cors_http('POST', '/api/v1/command/referential/add_event', allowed_roles=('admin'), expected_exceptions=BadRequest)
    def referential_add_event(self, request):
        data = self._handle_request_data(request)
        try:
            self.referential.add_event(**data)
        except:
            raise BadRequest('An error occured while adding event')
        return Response(json.dumps({'id': data['id']}), mimetype='application/json', status=201)

    @cors_http('GET', '/api/v1/query/referential/entity/<string:entity_id>', allowed_roles=('admin', 'write', 'read'),
               expected_exceptions=(BadRequest, NotFound))
    def referential_get_entity_by_id(self, request, entity_id):
        user = self._get_user_from_request(request)
        entity = bson.json_util.loads(self.referential.get_entity_by_id(entity_id, user))

        if not entity:
            raise NotFound('Entity not found')

        return Response(json.dumps(entity, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/referential/event/<string:event_id>', allowed_roles=('admin', 'write', 'read'),
               expected_exceptions=(BadRequest, NotFound))
    def referential_get_event_by_id(self, request, event_id):
        user = self._get_user_from_request(request)
        event = bson.json_util.loads(self.referential.get_event_by_id(event_id, user))

        if not event:
            raise NotFound('Event not found')

        return Response(json.dumps(event, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/referential/events/<string:start_date>/<string:end_date>', allowed_roles=('admin', 'write', 'read'),
        expected_exceptions=BadRequest)
    def referential_get_events_between_dates(self, request, start_date, end_date):
        user = self._get_user_from_request(request)
        try:
            events = bson.json_util.loads(self.referential.get_events_between_dates(start_date, end_date, user))
        except:
            raise BadRequest('An error occured while retrieving events between {} and {}'.format(start_date, end_date))
            
        return Response(json.dumps(events, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/referential/events/<string:entity_id>', allowed_roles=('admin', 'write', 'read'),
        expected_exceptions=BadRequest)
    def referential_get_events_by_entity_id(self, request, entity_id):
        user = self._get_user_from_request(request)
        limit  = -1
        if 'limit' in request.args:
            limit = int(request.args['limit'])
        try:
            events = bson.json_util.loads(self.referential.get_events_by_entity_id(entity_id, user, limit))
        except:
            raise BadRequest('An error occured while retrieving events for entity_id'.format(entity_id))
            
        return Response(json.dumps(events, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/referential/search_entity', allowed_roles=('admin', 'write', 'read',),
               expected_exceptions=BadRequest)
    def referential_search_entity(self, request):
        user = self._get_user_from_request(request)
        if 'name' not in request.args:
            raise BadRequest('No name in request s arguments')

        name = request.args['name']

        type = None
        if 'type' in request.args:
            type = request.args['type']

        provider = None
        if 'provider' in request.args:
            provider = request.args['provider']

        try:
            entities = bson.json_util.loads(self.referential.search_entity(name, user, type=type, provider=provider))
        except:
            raise BadRequest('An error occured while searching entity')

        return Response(json.dumps(entities, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/referential/search_event', allowed_roles=('admin', 'write', 'read',),
               expected_exceptions=BadRequest)
    def referential_search_event(self, request):
        user = self._get_user_from_request(request)
        if 'name' not in request.args:
            raise BadRequest('No name in request s arguments')

        name = request.args['name']

        if 'date' not in request.args:
            raise BadRequest('No date in request s arguments')

        date = request.args['date']

        type = None
        if 'type' in request.args:
            type = request.args['type']

        provider = None
        if 'provider' in request.args:
            provider = request.args['provider']

        try:
            events = bson.json_util.loads(self.referential.search_event(name, date, user, type=type, provider=provider))
        except:
            raise BadRequest('An error occured while searching event')

        return Response(json.dumps(events, cls=DateEncoder), mimetype='application/json')

    @cors_http('PUT', '/api/v1/command/referential/add_informations_to_entity/<string:entity_id>',
               allowed_roles=('admin'), expected_exceptions=BadRequest)
    def referential_add_informations_to_entity(self, request, entity_id):
        data = self._handle_request_data(request)
        try:
            self.referential.add_informations_to_entity(entity_id, data)
        except:
            raise BadRequest('An error occured while adding informations to entity')

        return Response(json.dumps({'id': entity_id}), mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/command/referential/update_ngrams', allowed_roles=('admin'), expected_exceptions=BadRequest)
    def referential_update_ngrams(self, request):
        result = self.referential.update_ngrams_search_collection()
        return Response(json.dumps({'Status': 'OK'}), mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/command/referential/update_ngrams/<string:entry_id>', allowed_roles=('admin',), 
               expected_exceptions=BadRequest)
    def referential_update_entry_ngrams(self, request, entry_id):
        result = self.referential.update_entry_ngrams(entry_id)
        return Response(json.dumps(result), mimetype='application/json', status=201)

    @cors_http('GET', '/api/v1/query/referential/search', allowed_roles=('admin', 'write', 'read'),
               expected_exceptions=BadRequest)
    def referential_fuzzy_search(self, request):
        user = self._get_user_from_request(request)
        if 'query' not in request.args:
            raise BadRequest('No query in request s arguments')
        query = request.args['query']

        type = None
        if 'type' in request.args:
            type = request.args['type']

        provider = None
        if 'provider' in request.args:
            provider = request.args['provider']

        limit = -1
        if 'limit' in request.args:
            limit = int(request.args['limit'])

        results = bson.json_util.loads(self.referential.fuzzy_search(query, user, type, provider, limit))
        return Response(json.dumps(results), mimetype='application/json')

    @cors_http('POST', '/api/v1/command/export', allowed_roles=('admin', 'write', 'read'), expected_exceptions=BadRequest)
    def exporter_export(self, request):
        data = self._handle_request_data(request)
        user = self._get_user_from_request(request)
        sub = bson.json_util.loads(self.subscription.get_subscription_by_user(user))
        if 'export' not in sub['subscription']:
            raise BadRequest('Export not configured for user {}'.format(user))
        export_config = sub['subscription']['export']
        if 'filename' not in data:
            raise BadRequest('Missing filename in request data')
        filename = data['filename']
        if 'svg' not in data:
            raise BadRequest('Missing svg in request data')
        if 'format' not in data:
            raise BadRequest('Missing format in request data')
        _format = data['format']
        if 'type' not in _format:
            raise BadRequest('Missing type in format dict in request data')
        if not filename.lower().endswith(_format['type'].lower()):
            raise BadRequest('Wrong filename extension {} was expected'.format(_format['type']))
        svg = data['svg']
        clean_svg = self.svg_builder.clean_for_export(svg) if _format['type'] != 'html' else svg
        args = {k:_format[k] for k in _format if k != 'type'}
        try:
            if _format:
                url = self.exporter.export(clean_svg, filename, export_config, **args)
            else:
                url = self.exporter.export(clean_svg, filename, export_config)
        except:
            raise BadRequest('An error occured while exporting SVG string')

        return Response(json.dumps({'url': url}), mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/command/text_to_path', allowed_roles=('admin', 'write', 'read'), expected_exceptions=BadRequest)
    def exporter_text_to_path(self, request):
        data = self._handle_request_data(request)
        if 'svg' not in data:
            raise BadRequest('Missing svg in request data')
        converted = self.exporter.text_to_path(data['svg'])
        return Response(converted, mimetype='image/svg+xml', status=201)
