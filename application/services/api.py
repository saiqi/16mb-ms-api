import json
import datetime
from functools import partial

from nameko.exceptions import serialize
from nameko.web.handlers import HttpRequestHandler
from nameko.standalone.rpc import ClusterRpcProxy
from nameko.dependency_providers import Config
from nameko.extensions import register_entrypoint
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden, NotFound
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

    def response_from_exception(self, exc):
        if isinstance(exc, self.expected_exceptions):
            if isinstance(exc, NotFound):
                status_code = 404
            else:
                status_code = 400
        else:
            status_code = 500

        error_dict = serialize(exc)
        payload = u'Error: {exc_type}: {value}\n'.format(**error_dict)

        return Response(payload, status=status_code)

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
                raise BadRequest('An error occurred while adding Opta F1 file')

        return Response(json.dumps(data), mimetype='application/json', status=201)

    @cors_http('GET', '/api/v1/query/opta/f9/<string:game_id>', allowed_roles=('admin', 'write',),
               expected_exceptions=(BadRequest, NotFound))
    def opta_get_f9(self, request, game_id):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = bson.json_util.loads(rpc.opta_collector.get_f9(game_id))
            except:
                raise BadRequest('An error occured while getting Opta F9 file')

            if result is None:
                raise NotFound('Opta F9 file not found')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/opta/soccer_ids/<string:start>/<string:end>', allowed_roles=('admin', 'write',),
               expected_exceptions=BadRequest)
    def get_opta_soccer_ids(self, request, start, end):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = rpc.opta_collector.get_soccer_ids_by_dates(start, end)
            except:
                raise BadRequest('An error occured while getting Opta soccer game ids')

        return Response(json.dumps(result), mimetype='application/json')

    @cors_http('PUT', '/api/v1/command/opta/ack_f9/<string:game_id>', allowed_roles=('admin'), expected_exceptions=BadRequest)
    def opta_ack_f9(self, request, game_id):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = rpc.opta_collector.ack_f9(game_id, data['checksum'])
            except:
                raise BadRequest('An error occured while acknowledging Opta F9')

        return Response(json.dumps({'id': game_id}), mimetype='application/json', status=201)

    @cors_http('PUT', '/api/v1/command/opta/unack_f9/<string:game_id>', allowed_roles=('admin'), expected_exceptions=BadRequest)
    def opta_unack_f9(self, request, game_id):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = rpc.opta_collector.unack_f9(game_id)
            except:
                raise BadRequest('An error occured while unacknowledging Opta F9')

        return Response(json.dumps({'id': game_id}), mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/command/opta/add_ru1', allowed_roles=('admin', 'write',),
               expected_exceptions=BadRequest)
    def opta_add_ru1(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.opta_collector.add_ru1.call_async(**data)
            except:
                raise BadRequest('An error occurred while adding Opta RU1 file')

        return Response(json.dumps(data), mimetype='application/json', status=201)

    @cors_http('GET', '/api/v1/query/opta/ru7/<string:game_id>', allowed_roles=('admin', 'write',),
               expected_exceptions=(BadRequest, NotFound))
    def opta_get_ru7(self, request, game_id):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = bson.json_util.loads(rpc.opta_collector.get_ru7(game_id))
            except:
                raise BadRequest('An error occured while getting Opta RU7 file')

            if result is None:
                raise NotFound('Opta RU7 file not found')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/opta/rugby_ids/<string:start>/<string:end>', allowed_roles=('admin', 'write',),
               expected_exceptions=BadRequest)
    def get_opta_rugby_ids(self, request, start, end):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = rpc.opta_collector.get_rugby_ids_by_dates(start, end)
            except:
                raise BadRequest('An error occured while getting Opta rugby game ids')

        return Response(json.dumps(result), mimetype='application/json')

    @cors_http('PUT', '/api/v1/command/opta/ack_ru7/<string:game_id>', allowed_roles=('admin'), expected_exceptions=BadRequest)
    def opta_ack_ru7(self, request, game_id):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = rpc.opta_collector.ack_ru7(game_id, data['checksum'])
            except:
                raise BadRequest('An error occured while acknowledging Opta RU7')

        return Response(json.dumps({'id': game_id}), mimetype='application/json', status=201)

    @cors_http('PUT', '/api/v1/command/opta/unack_ru7/<string:game_id>', allowed_roles=('admin'), expected_exceptions=BadRequest)
    def opta_unack_ru7(self, request, game_id):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = rpc.opta_collector.unack_ru7(game_id)
            except:
                raise BadRequest('An error occured while unacknowledging Opta RU7')

        return Response(json.dumps({'id': game_id}), mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/command/metadata/add_transformation', allowed_roles=('admin',),
               expected_exceptions=BadRequest)
    def metadata_add_transformation(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.metadata.add_transformation(**data)
            except:
                raise BadRequest('An error occurred while adding transformation')

        return Response(json.dumps({'id': data['_id']}), mimetype='application/json', status=201)

    @cors_http('DELETE', '/api/v1/command/metadata/delete_transformation/<string:transformation_id>',
               allowed_roles=('admin',), expected_exceptions=BadRequest)
    def metadata_delete_transformation(self, request, transformation_id):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.metadata.delete_transformation(transformation_id)
            except:
                raise BadRequest('An error occurred while deleting transformation: {}'.format(transformation_id))

        return Response(json.dumps({'id': transformation_id}), mimetype='application/json', status=204)

    @cors_http('POST', '/api/v1/command/metadata/deploy_function/<string:transformation_id>', allowed_roles=('admin',),
               expected_exceptions=BadRequest)
    def metadata_deploy_function(self, request, transformation_id):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = rpc.metadata.get_transformation(transformation_id)
            except:
                raise BadRequest('An error occurred while retrieving transformation: {}'.format(transformation_id))

            if not result:
                raise BadRequest('No transformation {} in metadata'.format(transformation_id))

            transformation = bson.json_util.loads(result)

            try:
                rpc.datastore.create_or_replace_python_function(transformation['function_name'],
                                                                transformation['function'])
            except:
                raise BadRequest('An error occurred while creating python function')

        return Response(json.dumps({'id': transformation_id}), mimetype='application/json', status=201)

    @cors_http('GET', '/api/v1/query/metadata/transformations', allowed_roles=('admin',),
               expected_exceptions=BadRequest)
    def metatdata_get_all_transformations(self, request):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = bson.json_util.loads(rpc.metadata.get_all_transformations())
            except:
                raise BadRequest('An error occurred while retrieving all transformations')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/metadata/transformation/<string:transformation_id>', allowed_roles=('admin',),
               expected_exceptions=(BadRequest, NotFound))
    def metadata_get_transformation(self, request, transformation_id):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = bson.json_util.loads(rpc.metadata.get_transformation(transformation_id))
            except:
                raise BadRequest('An error occurred while retrieving transformation: {}'.format(transformation_id))

            if result is None:
                raise NotFound('Transformation not found')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('POST', '/api/v1/command/metadata/add_query', allowed_roles=('admin', 'write',),
               expected_exceptions=BadRequest)
    def metadata_add_query(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.metadata.add_query(**data)
            except:
                raise BadRequest('An error occurred while adding query')

        return Response(json.dumps({'id': data['_id']}), mimetype='application/json', status=201)

    @cors_http('DELETE', '/api/v1/command/metadata/delete_query/<string:query_id>',
               allowed_roles=('admin', 'write',), expected_exceptions=BadRequest)
    def metadata_delete_query(self, request, query_id):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.metadata.delete_query(query_id)
            except:
                raise BadRequest('An error occurred while deleting query: {}'.format(query_id))

        return Response(json.dumps({'id': query_id}), mimetype='application/json', status=204)

    @cors_http('GET', '/api/v1/query/metadata/queries', allowed_roles=('admin', 'write', 'read',),
               expected_exceptions=BadRequest)
    def metatdata_get_all_queries(self, request):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = bson.json_util.loads(rpc.metadata.get_all_queries())
            except:
                raise BadRequest('An error occurred while retrieving all queries')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/metadata/query/<string:query_id>', allowed_roles=('admin', 'write', 'read',),
               expected_exceptions=(BadRequest, NotFound))
    def metadata_get_query(self, request, query_id):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = bson.json_util.loads(rpc.metadata.get_query(query_id))
            except:
                raise BadRequest('An error occurred while retrieving query: {}'.format(query_id))

            if result is None:
                raise NotFound('Query not found')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('POST', '/api/v1/command/metadata/add_template', allowed_roles=('admin', 'write',),
               expected_exceptions=BadRequest)
    def metadata_add_template(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.metadata.add_template(**data)
            except:
                raise BadRequest('An error occurred while adding template')

        return Response(json.dumps({'id': data['_id']}), mimetype='application/json', status=201)

    @cors_http('DELETE', '/api/v1/command/metadata/delete_template/<string:template_id>',
               allowed_roles=('admin', 'write',), expected_exceptions=BadRequest)
    def metadata_delete_template(self, request, template_id):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.metadata.delete_template(template_id)
            except:
                raise BadRequest('An error occurred while deleting template: {}'.format(template_id))

        return Response(json.dumps({'id': template_id}), mimetype='application/json', status=204)

    @cors_http('GET', '/api/v1/query/metadata/templates', allowed_roles=('admin', 'write', 'read',),
               expected_exceptions=BadRequest)
    def metatdata_get_all_templates(self, request):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = bson.json_util.loads(rpc.metadata.get_all_templates())
            except:
                raise BadRequest('An error occurred while retrieving all templates')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/metadata/template/<string:template_id>', allowed_roles=('admin', 'write', 'read',),
               expected_exceptions=(BadRequest, NotFound))
    def metadata_get_template(self, request, template_id):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = bson.json_util.loads(rpc.metadata.get_template(template_id))
            except:
                raise BadRequest('An error occurred while retrieving template: {}'.format(template_id))

            if result is None:
                raise NotFound('Template not found')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('POST', '/api/v1/command/metadata/template/add_query/<string:template_id>',
               allowed_roles=('admin', 'write', 'read',), expected_exceptions=BadRequest)
    def metadata_add_query_to_template(self, request, template_id):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.metadata.add_query_to_template(template_id, **data)
            except:
                raise BadRequest('An error occurred while adding query to template {}'.format(template_id))

        return Response(json.dumps({'id': template_id}), mimetype='application/json', status=201)

    @cors_http('DELETE', '/api/v1/command/metadata/template/delete_query/<string:template_id>/<string:query_id>',
               allowed_roles=('admin', 'write', 'read',), expected_exceptions=BadRequest)
    def metadata_delete_query_from_template(self, request, template_id, query_id):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.metadata.delete_query_from_template(template_id, query_id)
            except:
                raise BadRequest('An error occurred while deleting query from template {}'.format(template_id))

        return Response(json.dumps({'id': template_id}), mimetype='application/json', status=204)

    @cors_http('POST', '/api/v1/command/metadata/template/update_svg/<string:template_id>',
               allowed_roles=('admin', 'write', 'read',), expected_exceptions=BadRequest)
    def metadata_update_svg_in_template(self, request, template_id):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.metadata.update_svg_in_template(template_id, **data)
            except:
                raise BadRequest('An error occurred while updating svg in template {}'.format(template_id))

        return Response(json.dumps({'id': template_id}), mimetype='application/json', status=201)

    @cors_http('GET', '/api/v1/query/metadata/query/resolve/<string:query_id>',
               allowed_roles=('admin', 'read', 'write'), expected_exceptions=(BadRequest, NotFound))
    def metadata_resolve_query(self, request, query_id):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            query = bson.json_util.loads(rpc.metadata.get_query(query_id))

            if query is None:
                raise NotFound('Query not found')

            params = None
            if query['parameters'] is not None:
                if sorted(query['parameters']) != sorted(data.keys()):
                    raise BadRequest('Request arguments are mismatching expected query parameters')
                params = [data[p] for p in query['parameters']]

            try:
                if params is not None:
                    result = bson.json_util.loads(rpc.datareader.select(query['sql'], params))
                else:
                    result = bson.json_util.loads(rpc.datareader.select(query['sql']))
            except:
                raise BadRequest('An error occurred while executing query')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/metadata/template/resolve/<string:template_id>',
               allowed_roles=('admin', 'read', 'write'), expected_exceptions=(BadRequest, NotFound))
    def metadata_resolve_template(self, request, template_id):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            template = bson.json_util.loads(rpc.metadata.get_template(template_id))

            if template is None:
                raise NotFound('Template not found')

            context = template['context']

            language = template['language']
            if 'language' in data:
                language = data['language']

            json_only = False
            if 'json_only' in data:
                json_only = data['json_only']

            referential_search_doc = None
            if 'referential_search_doc' in data:
                referential_search_doc = data['referential_search_doc']

            user_parameters = None
            if 'user_parameters' in data:
                user_parameters = data['user_parameters']

            referential_results = dict()
            if referential_search_doc is not None:
                try:
                    referential_results = bson.json_util.loads(
                        rpc.referential.get_entity_or_event(referential_search_doc))
                except Exception as e:
                    raise BadRequest(str(e))
                for k in referential_search_doc:
                    picture = None
                    if 'picture' in referential_search_doc[k]:
                        picture = rpc.referential.get_entity_picture(
                            referential_results[k]['id'], referential_search_doc[k]['picture']['context'],
                            referential_search_doc[k]['picture']['format'])
                    referential_results[k]['picture'] = picture
                    logo = None
                    if 'logo' in referential_search_doc[k]:
                        logo = rpc.referential.get_entity_logo(
                            referential_results[k]['id'], referential_search_doc[k]['logo']['context'],
                            referential_search_doc[k]['logo']['format'])
                    referential_results[k]['logo'] = logo

            query_results = dict()

            for q in template['queries']:
                current_id = q['id']
                current_query = bson.json_util.loads(rpc.metadata.get_query(q['id']))
                query_results[current_id] = dict()
                current_sql = current_query['sql']
                parameters = list()
                if current_query['parameters']:
                    for p in current_query['parameters']:
                        if user_parameters is not None:
                            if current_id in user_parameters and p in user_parameters[current_id]:
                                parameters.append(user_parameters[current_id][p])
                        if 'referential_parameters' in q and q['referential_parameters']:
                            for ref in q['referential_parameters']:
                                if p in ref:
                                    parameters.append(referential_results[ref[p]]['id'])
                try:
                    current_results = bson.json_util.loads(rpc.datareader.select(current_sql, parameters))
                except:
                    raise BadRequest('An error occured while executing query {}'.format(current_id))
                labelized_results = list()
                for row in current_results:
                    labelized_row = row.copy()
                    if 'labels' in q and q['labels']:
                        current_labels = q['labels']
                        for lab in current_labels:
                            if lab in row:
                                if current_labels[lab] == 'entity':
                                    current_entity = bson.json_util.loads(rpc.referential.get_entity_by_id(row[lab]))
                                    labelized_row[lab] = current_entity['common_name']
                                elif current_labels[lab] == 'label':
                                    current_label = rpc.referential.get_labels_by_id_and_language_and_context(row[lab], language, context)
                                    if current_label is None:
                                        raise BadRequest('Label {} not found'.format(row[lab]))
                                    labelized_row[lab] = current_label['label']
                    labelized_results.append(labelized_row)
                    if 'referential_results' in q and q['referential_results']:
                        current_ref_config = q['referential_results']
                        for cfg in current_ref_config:
                            ref_pic = None
                            ref_logo = None
                            if current_ref_config[cfg]['event_or_entity'] == 'event':
                                current_ref_result = bson.json_util.loads(rpc.referential.get_event_by_id(row[cfg]))
                            else:
                                current_ref_result = bson.json_util.loads(rpc.referential.get_entity_by_id(row[cfg]))
                                if 'picture' in current_ref_config[cfg]:
                                    ref_pic = rpc.referential.get_entity_picture(
                                        row[cfg], current_ref_config[cfg]['picture']['context'],
                                        current_ref_config[cfg]['picture']['format'])
                                if 'logo' in current_ref_config[cfg]:
                                    ref_logo = rpc.referential.get_entity_logo(
                                        row[cfg], current_ref_config[cfg]['logo']['context'],
                                        current_ref_config[cfg]['logo']['format'])
                            current_column_id = current_ref_config[cfg]['column_id']
                            referential_results[row[current_column_id]] = current_ref_result
                            referential_results[row[current_column_id]]['picture'] = ref_pic
                            referential_results[row[current_column_id]]['logo'] = ref_logo

                query_results[current_id] = labelized_results
            results = {'referential': referential_results, 'query': query_results}
            json_results = json.dumps(results, cls=DateEncoder)

            if not json_only:
                infography = rpc.svg_builder.replace_jsonpath(template['svg'], json.loads(json_results))

        if json_only is True:
            return Response(json_results, mimetype='application/json')

        return Response(infography, mimetype='image/svg+xml')

    @cors_http('GET', '/api/v2/query/metadata/template/resolve/<string:template_id>',
               allowed_roles=('admin', 'read', 'write'), expected_exceptions=(BadRequest, NotFound))
    def metadata_resolve_template_with_ids(self, request, template_id):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            template = bson.json_util.loads(rpc.metadata.get_template(template_id))

            if template is None:
                raise NotFound('Template not found')

            context = template['context']

            language = template['language']
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

            referential_results = dict()
            if referential is not None:
                try:
                    for k,v in referential.items():
                        current_ref_str = None
                        if v['event_or_entity'] == 'entity':
                            current_ref_str = rpc.referential.get_entity_by_id(v['id'])
                        else:
                            current_ref_str = rpc.referential.get_event_by_id(v['id'])
                        referential_results[k] = bson.json_util.loads(current_ref_str)
                        picture = None
                        if 'picture' in v:
                            picture = rpc.referential.get_entity_picture(v['id'], v['picture']['context'],
                                                                         v['picture']['format'])
                        referential_results[k]['picture'] = picture
                        logo = None
                        if 'logo' in v:
                            logo = rpc.referential.get_entity_logo(v['id'], v['logo']['context'],
                                                                   v['logo']['format'])
                        referential_results[k]['logo'] = logo
                except Exception as e:
                    raise BadRequest(str(e))

            query_results = dict()

            for q in template['queries']:
                current_id = q['id']
                current_query = bson.json_util.loads(rpc.metadata.get_query(q['id']))
                query_results[current_id] = dict()
                current_sql = current_query['sql']
                parameters = list()
                if current_query['parameters']:
                    for p in current_query['parameters']:
                        if user_parameters is not None:
                            if current_id in user_parameters and p in user_parameters[current_id]:
                                parameters.append(user_parameters[current_id][p])
                        if 'referential_parameters' in q and q['referential_parameters']:
                            for ref in q['referential_parameters']:
                                if p in ref:
                                    parameters.append(referential_results[ref[p]['name']]['id'])
                try:
                    current_results = bson.json_util.loads(rpc.datareader.select(current_sql, parameters))
                except:
                    raise BadRequest('An error occured while executing query {}'.format(current_id))
                labelized_results = list()
                for row in current_results:
                    labelized_row = row.copy()
                    if 'labels' in q and q['labels']:
                        current_labels = q['labels']
                        for lab in current_labels:
                            if lab in row:
                                if current_labels[lab] == 'entity':
                                    current_entity = bson.json_util.loads(rpc.referential.get_entity_by_id(row[lab]))
                                    labelized_row[lab] = current_entity['common_name']
                                elif current_labels[lab] == 'label':
                                    current_label = rpc.referential.get_labels_by_id_and_language_and_context(row[lab], language, context)
                                    if current_label is None:
                                        raise BadRequest('Label {} not found'.format(row[lab]))
                                    labelized_row[lab] = current_label['label']
                    labelized_results.append(labelized_row)
                    if 'referential_results' in q and q['referential_results']:
                        current_ref_config = q['referential_results']
                        for cfg in current_ref_config:
                            ref_pic = None
                            ref_logo = None
                            if current_ref_config[cfg]['event_or_entity'] == 'event':
                                current_ref_result = bson.json_util.loads(rpc.referential.get_event_by_id(row[cfg]))
                            else:
                                current_ref_result = bson.json_util.loads(rpc.referential.get_entity_by_id(row[cfg]))
                                if 'picture' in current_ref_config[cfg]:
                                    ref_pic = rpc.referential.get_entity_picture(
                                        row[cfg], current_ref_config[cfg]['picture']['context'],
                                        current_ref_config[cfg]['picture']['format'])
                                if 'logo' in current_ref_config[cfg]:
                                    ref_logo = rpc.referential.get_entity_logo(
                                        row[cfg], current_ref_config[cfg]['logo']['context'],
                                        current_ref_config[cfg]['logo']['format'])
                            current_column_id = current_ref_config[cfg]['column_id']
                            referential_results[row[current_column_id]] = current_ref_result
                            referential_results[row[current_column_id]]['picture'] = ref_pic
                            referential_results[row[current_column_id]]['logo'] = ref_logo

                query_results[current_id] = labelized_results
            results = {'referential': referential_results, 'query': query_results}
            json_results = json.dumps(results, cls=DateEncoder)

            if not json_only:
                infography = rpc.svg_builder.replace_jsonpath(template['svg'], json.loads(json_results))

        if json_only is True:
            return Response(json_results, mimetype='application/json')

        return Response(infography, mimetype='image/svg+xml')

    @cors_http('POST', '/api/v1/command/crontask/update_opta_soccer', allowed_roles=('admin',),
               expected_exceptions=BadRequest)
    def crontask_update_opta_soccer(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.crontask.update_opta_soccer.call_async(**data)
            except:
                raise BadRequest('An error occurred while submitting update opta soccer task')

        return Response(json.dumps(data), mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/command/crontask/update_opta_rugby', allowed_roles=('admin',),
               expected_exceptions=BadRequest)
    def crontask_update_opta_rugby(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.crontask.update_opta_rugby.call_async(**data)
            except:
                raise BadRequest('An error occurred while submitting update opta rugby task')

        return Response(json.dumps(data), mimetype='application/json', status=201)

    @cors_http('GET', '/api/v1/query/crontask/logs', allowed_roles=('admin',), expected_exceptions=BadRequest)
    def crontask_get_logs(self, request):
        method_name = None
        if 'method_name' in request.args:
            method_name = request.args['method_name']
        tail = 10
        if 'tail' in request.args:
            tail = int(request.args['tail'])
        with ClusterRpcProxy(self.config) as rpc:
            try:
                raw_logs = bson.json_util.loads(rpc.crontask.get_logs(tail=tail, method_name=method_name))
            except:
                raise BadRequest('An error occurred while retrieving crontask logs')

        return Response(json.dumps(raw_logs, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/datareader/select', allowed_roles=('admin', 'write', 'read',),
               expected_exceptions=BadRequest)
    def datareader_select(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                result = bson.json_util.loads(rpc.datareader.select(**data))
            except:
                raise BadRequest('An error occurred while getting result from datareader')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('POST', '/api/v1/command/datastore/create_table', allowed_roles=('admin',),
               expected_exceptions=BadRequest)
    def datastore_create_table(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.datastore.truncate(data['target_table'])
                rpc.datastore.insert(**data)
            except:
                raise BadRequest('An error occured while creating table')

        return Response(json.dumps({'target_table': data['target_table']}), mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/command/datastore/write', allowed_roles=('admin'),
               expected_exceptions=BadRequest)
    def datastore_write(self, request):
        data = json.loads(request.get_data(as_text=True))

        if 'write_policy' not in data:
            raise BadRequest('Missing write_policy paramerter in posted data')

        write_policy = data['write_policy']

        if write_policy not in ('insert', 'upsert', 'bulk_insert', 'delete_insert', 'delete_bulk_insert',
                                'truncate_insert', 'truncate_bulk_insert'):
            raise BadRequest('Wrong value for parameter write_policy')

        with ClusterRpcProxy(self.config) as rpc:
            try:
                if write_policy == 'insert':
                    rpc.datastore.insert(data['target_table'], data['records'], data['meta'])
                elif write_policy == 'upsert':
                    rpc.datastore.upsert(data['target_table'], data['upsert_key'], data['records'], data['meta'])
                elif write_policy == 'bulk_insert':
                    rpc.datastore.bulk_insert(data['target_table'], data['records'], data['meta'])
                elif write_policy == 'delete_insert':
                    rpc.datastore.delete(data['target_table'], data['delete_keys'])
                    rpc.datastore.insert(data['target_table'], data['records'], data['meta'])
                elif write_policy == 'delete_bulk_insert':
                    rpc.datastore.delete(data['target_table'], data['delete_keys'])
                    rpc.datastore.bulk_insert(data['target_table'], data['records'], data['meta'])
                elif write_policy == 'truncate_insert':
                    rpc.datastore.truncate(data['target_table'])
                    rpc.datastore.insert(data['target_table'], data['records'], data['meta'])
                else:
                    rpc.datastore.truncate(data['target_table'])
                    rpc.datastore.bulk_insert(data['target_table'], data['records'], data['meta'])
            except:
                raise BadRequest('An error occured while writing in datastore')

        return Response(json.dumps({'target_table': data['target_table']}), mimetype='application/json',
                        status=201)

    @cors_http('POST', '/api/v1/command/referential/add_label', allowed_roles=('admin', 'write'),
               expected_exceptions=BadRequest)
    def referential_add_label(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.referential.add_label(**data)
            except:
                raise BadRequest('An error occured while adding label')

        return Response(json.dumps(data), mimetype='application/json', status=201)

    @cors_http('DELETE', '/api/v1/command/referential/delete_label/<string:label_id>/<string:language>/<string:context>',
               allowed_roles=('admin', 'write'), expected_exceptions=BadRequest)
    def referential_delete_label(self, request, label_id, language, context):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                rpc.referential.delete_label(label_id, language, context)
            except:
                raise BadRequest('An error occured while deleting label')

        return Response(json.dumps({'id': label_id}), mimetype='application/json', status=204)

    @cors_http('GET', '/api/v1/query/referential/get_label/<string:label_id>/<string:language>/<string:context>',
               allowed_roles=('admin', 'write',), expected_exceptions=(BadRequest, NotFound))
    def referential_get_label(self, request, label_id, language, context):
        with ClusterRpcProxy(self.config) as rpc:
            try:
                label = rpc.referential.get_labels_by_id_and_language_and_context(label_id, language, context)
            except:
                raise BadRequest('An error occured while getting label')

            if label is None:
                raise NotFound('Label not found')

        return Response(json.dumps(label), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/referential/search_entity', allowed_roles=('admin', 'write', 'read',),
               expected_exceptions=BadRequest)
    def referential_search_entity(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                entities = bson.json_util.loads(rpc.referential.search_entity(**data))
            except:
                raise BadRequest('An error occured while searching entity')

        return Response(json.dumps(entities, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/referential/search_event', allowed_roles=('admin', 'write', 'read',),
               expected_exceptions=BadRequest)
    def referential_search_event(self, request):
        data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            try:
                events = bson.json_util.loads(rpc.referential.search_event(**data))
            except:
                raise BadRequest('An error occured while searching entity')

        return Response(json.dumps(events, cls=DateEncoder), mimetype='application/json')
