import json
import datetime
from functools import partial

from nameko.exceptions import serialize
from nameko.web.handlers import HttpRequestHandler
from nameko.rpc import RpcProxy
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
        payload = {'Error': error_dict['value']}

        return Response(json.dumps(payload), mimetype='application/json', status=status_code)

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

    opta_collector = RpcProxy('opta_collector')
    metadata = RpcProxy('metadata')
    datareader = RpcProxy('datareader')
    datastore = RpcProxy('datastore')
    referential = RpcProxy('referential')
    svg_builder = RpcProxy('svg_builder')
    crontask = RpcProxy('crontask')

    def _handle_request_data(self, request):
        if not request.get_data():
            raise BadRequest('No data in request')

        try:
            json_data = json.loads(request.get_data(as_text=True))
        except:
            raise BadRequest('An error occured while loading request data')

        return json_data

    @cors_http('POST', '/api/v1/command/opta/add_f1', allowed_roles=('admin', 'write',), expected_exceptions=BadRequest)
    def opta_add_f1(self, request):
        data = self._handle_request_data(request)
        try:
            self.opta_collector.add_f1(**data)
        except:
            raise BadRequest('An error occurred while adding Opta F1 file')

        return Response(json.dumps(data), mimetype='application/json', status=201)

    @cors_http('GET', '/api/v1/query/opta/f1/<string:game_id>', allowed_roles=('admin', 'write',), expected_exceptions=BadRequest)
    def opta_get_f1(self, request, game_id):
        try:
            game = self.opta_collector.get_f1(game_id)
        except:
            raise BadRequest('An error occured while getting Opta F1 details')

        if game is None:
            raise NotFound('Opta F1 detail not found')

        result = bson.json_util.loads(game)

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('POST', '/api/v1/command/opta/update_all_f1', allowed_roles=('admin', 'write'), expected_exceptions=BadRequest)
    def opta_update_all_f1(self, request):
        try:
            self.opta_collector.update_all_f1()
        except:
            raise BadRequest('An error occured while updating Opta F1 files')
        return Response(json.dumps({'status': 'OK'}), mimetype='application/json', status=201)

    @cors_http('GET', '/api/v1/query/opta/f9/<string:game_id>', allowed_roles=('admin', 'write',),
               expected_exceptions=(BadRequest, NotFound))
    def opta_get_f9(self, request, game_id):
        try:
            game = self.opta_collector.get_f9(game_id)
        except:
            raise BadRequest('An error occured while getting Opta F9 file')

        if game is None:
            raise NotFound('Opta F9 file not found')

        result = bson.json_util.loads(game)

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/opta/soccer_ids/<string:start>/<string:end>', allowed_roles=('admin', 'write',),
               expected_exceptions=BadRequest)
    def get_opta_soccer_ids(self, request, start, end):
        try:
            result = self.opta_collector.get_soccer_ids_by_dates(start, end)
        except:
            raise BadRequest('An error occured while getting Opta soccer game ids')

        return Response(json.dumps(result), mimetype='application/json')

    @cors_http('PUT', '/api/v1/command/opta/ack_f9/<string:game_id>', allowed_roles=('admin'), expected_exceptions=BadRequest)
    def opta_ack_f9(self, request, game_id):
        data = self._handle_request_data(request)
        try:
            result = self.opta_collector.ack_f9(game_id, data['checksum'])
        except:
            raise BadRequest('An error occured while acknowledging Opta F9')

        return Response(json.dumps({'id': game_id}), mimetype='application/json', status=201)

    @cors_http('PUT', '/api/v1/command/opta/unack_f9/<string:game_id>', allowed_roles=('admin'), expected_exceptions=BadRequest)
    def opta_unack_f9(self, request, game_id):
        try:
            result = self.opta_collector.unack_f9(game_id)
        except:
            raise BadRequest('An error occured while unacknowledging Opta F9')

        return Response(json.dumps({'id': game_id}), mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/command/opta/add_ru1', allowed_roles=('admin', 'write',),
               expected_exceptions=BadRequest)
    def opta_add_ru1(self, request):
        data = self._handle_request_data(request)
        try:
            self.opta_collector.add_ru1(**data)
        except:
            raise BadRequest('An error occurred while adding Opta RU1 file')

        return Response(json.dumps(data), mimetype='application/json', status=201)

    @cors_http('GET', '/api/v1/query/opta/ru1/<string:game_id>', allowed_roles=('admin', 'write',), expected_exceptions=BadRequest)
    def opta_get_ru1(self, request, game_id):
        try:
            game = self.opta_collector.get_ru1(game_id)
        except:
            raise BadRequest('An error occured while getting Opta RU1 details')

        if game is None:
            raise NotFound('Opta RU1 detail not found')

        result = bson.json_util.loads(game)

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('POST', '/api/v1/command/opta/update_all_ru1', allowed_roles=('admin', 'write'), expected_exceptions=BadRequest)
    def opta_update_all_ru1(self, request):
        try:
            self.opta_collector.update_all_ru1()
        except:
            raise BadRequest('An error occured while updating Opta RU1 files')
        return Response(json.dumps({'status': 'OK'}), mimetype='application/json', status=201)

    @cors_http('GET', '/api/v1/query/opta/ru7/<string:game_id>', allowed_roles=('admin', 'write',),
               expected_exceptions=(BadRequest, NotFound))
    def opta_get_ru7(self, request, game_id):
        try:
            game = self.opta_collector.get_ru7(game_id)
        except:
            raise BadRequest('An error occured while getting Opta RU7 file')

        if game is None:
            raise NotFound('Opta RU7 file not found')

        result = bson.json_util.loads(game)

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/opta/rugby_ids/<string:start>/<string:end>', allowed_roles=('admin', 'write',),
               expected_exceptions=BadRequest)
    def get_opta_rugby_ids(self, request, start, end):
        try:
            result = self.opta_collector.get_rugby_ids_by_dates(start, end)
        except:
            raise BadRequest('An error occured while getting Opta rugby game ids')

        return Response(json.dumps(result), mimetype='application/json')

    @cors_http('PUT', '/api/v1/command/opta/ack_ru7/<string:game_id>', allowed_roles=('admin'), expected_exceptions=BadRequest)
    def opta_ack_ru7(self, request, game_id):
        data = self._handle_request_data(request)
        try:
            result = self.opta_collector.ack_ru7(game_id, data['checksum'])
        except:
            raise BadRequest('An error occured while acknowledging Opta RU7')

        return Response(json.dumps({'id': game_id}), mimetype='application/json', status=201)

    @cors_http('PUT', '/api/v1/command/opta/unack_ru7/<string:game_id>', allowed_roles=('admin'), expected_exceptions=BadRequest)
    def opta_unack_ru7(self, request, game_id):
        try:
            result = self.opta_collector.unack_ru7(game_id)
        except:
            raise BadRequest('An error occured while unacknowledging Opta RU7')

        return Response(json.dumps({'id': game_id}), mimetype='application/json', status=201)

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
               expected_exceptions=BadRequest)
    def metadata_deploy_function(self, request, transformation_id):
        try:
            result = self.metadata.get_transformation(transformation_id)
        except:
            raise BadRequest('An error occurred while retrieving transformation: {}'.format(transformation_id))

        if not result:
            raise BadRequest('No transformation {} in metadata'.format(transformation_id))

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

    @cors_http('POST', '/api/v1/command/metadata/add_query', allowed_roles=('admin', 'write',),
               expected_exceptions=BadRequest)
    def metadata_add_query(self, request):
        data = self._handle_request_data(request)
        try:
            self.metadata.add_query(**data)
        except:
            raise BadRequest('An error occurred while adding query')

        return Response(json.dumps({'id': data['_id']}), mimetype='application/json', status=201)

    @cors_http('DELETE', '/api/v1/command/metadata/delete_query/<string:query_id>',
               allowed_roles=('admin', 'write',), expected_exceptions=BadRequest)
    def metadata_delete_query(self, request, query_id):
        try:
            self.metadata.delete_query(query_id)
        except:
            raise BadRequest('An error occurred while deleting query: {}'.format(query_id))

        return Response(json.dumps({'id': query_id}), mimetype='application/json', status=204)

    @cors_http('GET', '/api/v1/query/metadata/queries', allowed_roles=('admin', 'write', 'read',),
               expected_exceptions=BadRequest)
    def metatdata_get_all_queries(self, request):
        try:
            result = bson.json_util.loads(self.metadata.get_all_queries())
        except:
            raise BadRequest('An error occurred while retrieving all queries')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/metadata/query/<string:query_id>', allowed_roles=('admin', 'write', 'read',),
               expected_exceptions=(BadRequest, NotFound))
    def metadata_get_query(self, request, query_id):
        try:
            result = bson.json_util.loads(self.metadata.get_query(query_id))
        except:
            raise BadRequest('An error occurred while retrieving query: {}'.format(query_id))

        if result is None:
            raise NotFound('Query not found')

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
        try:
            if 'bundle' in request.args:
                bundle = request.args['bundle']
                result = bson.json_util.loads(self.metadata.get_templates_by_bundle(bundle))
            else:
                result = bson.json_util.loads(self.metadata.get_all_templates())
        except:
            raise BadRequest('An error occurred while retrieving all templates')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/metadata/template/<string:template_id>', allowed_roles=('admin', 'write', 'read',),
               expected_exceptions=(BadRequest, NotFound))
    def metadata_get_template(self, request, template_id):
        try:
            result = bson.json_util.loads(self.metadata.get_template(template_id))
        except:
            raise BadRequest('An error occurred while retrieving template: {}'.format(template_id))

        if result is None:
            raise NotFound('Template not found')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @cors_http('POST', '/api/v1/command/metadata/template/add_query/<string:template_id>',
               allowed_roles=('admin', 'write', 'read',), expected_exceptions=BadRequest)
    def metadata_add_query_to_template(self, request, template_id):
        data = self._handle_request_data(request)
        try:
            self.metadata.add_query_to_template(template_id, **data)
        except:
            raise BadRequest('An error occurred while adding query to template {}'.format(template_id))

        return Response(json.dumps({'id': template_id}), mimetype='application/json', status=201)

    @cors_http('DELETE', '/api/v1/command/metadata/template/delete_query/<string:template_id>/<string:query_id>',
               allowed_roles=('admin', 'write', 'read',), expected_exceptions=BadRequest)
    def metadata_delete_query_from_template(self, request, template_id, query_id):
        try:
            self.metadata.delete_query_from_template(template_id, query_id)
        except:
            raise BadRequest('An error occurred while deleting query from template {}'.format(template_id))

        return Response(json.dumps({'id': template_id}), mimetype='application/json', status=204)

    @cors_http('POST', '/api/v1/command/metadata/template/update_svg/<string:template_id>',
               allowed_roles=('admin', 'write', 'read',), expected_exceptions=BadRequest)
    def metadata_update_svg_in_template(self, request, template_id):
        data = self._handle_request_data(request)
        try:
            self.metadata.update_svg_in_template(template_id, **data)
        except:
            raise BadRequest('An error occurred while updating svg in template {}'.format(template_id))

        return Response(json.dumps({'id': template_id}), mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/query/metadata/query/resolve/<string:query_id>',
               allowed_roles=('admin', 'read', 'write'), expected_exceptions=(BadRequest, NotFound))
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
                result = bson.json_util.loads(self.datareader.select(query['sql'], params))
            else:
                result = bson.json_util.loads(self.datareader.select(query['sql']))
        except:
            raise BadRequest('An error occurred while executing query')

        return Response(json.dumps(result, cls=DateEncoder), mimetype='application/json')

    @staticmethod
    def _get_display_name(entity, language):
        if 'internationalization' in entity and language in entity['internationalization']:
            return entity['internationalization'][language]
        return entity['common_name']

    @staticmethod
    def _get_short_name(entity, language):
        if 'informations' in entity and 'first_name' in entity['informations']\
        and 'last_name' in entity['informations'] and 'known' in entity['informations']:
            if entity['informations']['known']:
                return entity['informations']['known']
            return entity['informations']['last_name']

        return ApiService._get_display_name(entity, language)

    @cors_http('POST', '/api/v1/query/metadata/template/resolve_with_ids/<string:template_id>',
               allowed_roles=('admin', 'read', 'write'), expected_exceptions=(BadRequest, NotFound))
    def metadata_resolve_template_with_ids(self, request, template_id):
        data = self._handle_request_data(request)
        template = bson.json_util.loads(self.metadata.get_template(template_id))

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
                        current_ref_str = self.referential.get_entity_by_id(v['id'])
                    else:
                        current_ref_str = self.referential.get_event_by_id(v['id'])
                    if not current_ref_str:
                        raise NotFound('Referential entry not found: {}'.format(v['id']))
                    referential_results[k] = bson.json_util.loads(current_ref_str)
                    referential_results[k]['display_name'] = self._get_display_name(referential_results[k], language)
                    picture = None
                    if 'picture' in v and json_only is False:
                        pic_context = v['picture']['context']
                        pic_format = v['picture']['format']
                        picture = self.referential.get_entity_picture(v['id'], pic_context, pic_format)
                        if not picture:
                            raise NotFound('Picture not found for referential entry: {} (context: {} / format: {})'.format(v['id'], pic_context, pic_format))
                    referential_results[k]['picture'] = picture
                    logo = None
                    if 'logo' in v and json_only is False:
                        logo = self.referential.get_entity_logo(v['id'], v['logo']['context'],
                                                               v['logo']['format'])
                    referential_results[k]['logo'] = logo
            except Exception as e:
                raise BadRequest(str(e))

        query_results = dict()

        for q in template['queries']:
            current_id = q['id']
            current_query = bson.json_util.loads(self.metadata.get_query(q['id']))
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
                current_results = bson.json_util.loads(self.datareader.select(current_sql, parameters))
            except:
                raise BadRequest('An error occured while executing query {}'.format(current_id))
            if current_results is None:
                raise BadRequest('Query {} returns nothing'.format(current_id))
            labelized_results = list()
            for row in current_results:
                labelized_row = row.copy()
                if 'labels' in q and q['labels']:
                    current_labels = q['labels']
                    for lab in current_labels:
                        if lab in row:
                            if current_labels[lab] == 'entity':
                                current_entity = bson.json_util.loads(self.referential.get_entity_by_id(row[lab]))
                                labelized_row[lab] = current_entity['common_name']
                            elif current_labels[lab] == 'label':
                                current_label = self.referential.get_labels_by_id_and_language_and_context(row[lab], language, context)
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
                            current_ref_result = bson.json_util.loads(self.referential.get_event_by_id(row[cfg]))
                            if not current_ref_result:
                                raise NotFound('Event {} not found'.format(row[cfg]))
                        else:
                            current_ref_result = bson.json_util.loads(self.referential.get_entity_by_id(row[cfg]))
                            if not current_ref_result:
                                raise NotFound('Entity {} not found'.format(row[cfg]))
                            current_ref_result['display_name'] = self._get_display_name(current_ref_result, language)
                            current_ref_result['short_name'] = self._get_short_name(current_ref_result, language)
                            if 'picture' in current_ref_config[cfg] and json_only is False:
                                ref_pic = self.referential.get_entity_picture(
                                    row[cfg], current_ref_config[cfg]['picture']['context'],
                                    current_ref_config[cfg]['picture']['format'])
                            if 'logo' in current_ref_config[cfg] and json_only is False:
                                ref_logo = self.referential.get_entity_logo(
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
            infography = self.svg_builder.replace_jsonpath(template['svg'], json.loads(json_results))

        if json_only is True:
            return Response(json_results, mimetype='application/json')

        return Response(infography, mimetype='image/svg+xml')

    @cors_http('POST', '/api/v1/command/crontask/update_opta_soccer', allowed_roles=('admin',),
               expected_exceptions=BadRequest)
    def crontask_update_opta_soccer(self, request):
        data = self._handle_request_data(request)
        try:
            self.crontask.update_opta_soccer(**data)
        except:
            raise BadRequest('An error occurred while submitting update opta soccer task')

        return Response(json.dumps(data), mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/command/crontask/update_opta_rugby', allowed_roles=('admin',),
               expected_exceptions=BadRequest)
    def crontask_update_opta_rugby(self, request):
        data = self._handle_request_data(request)
        try:
            self.crontask.update_opta_rugby(**data)
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
        try:
            raw_logs = bson.json_util.loads(self.crontask.get_logs(tail=tail, method_name=method_name))
        except:
            raise BadRequest('An error occurred while retrieving crontask logs')

        return Response(json.dumps(raw_logs, cls=DateEncoder), mimetype='application/json')

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

    @cors_http('POST', '/api/v1/command/datastore/write', allowed_roles=('admin'),
               expected_exceptions=BadRequest)
    def datastore_write(self, request):
        data = self._handle_request_data(request)

        if 'write_policy' not in data:
            raise BadRequest('Missing write_policy parameter in request data')

        write_policy = data['write_policy']

        if write_policy not in ('insert', 'upsert', 'bulk_insert', 'delete_insert', 'delete_bulk_insert',
                                'truncate_insert', 'truncate_bulk_insert'):
            raise BadRequest('Wrong value for parameter write_policy')

        try:
            meta = list(map(tuple, data['meta']))
        except:
            raise BadRequest('Bad formated meta')

        try:
            if write_policy == 'insert':
                self.datastore.insert(data['target_table'], data['records'], meta)
            elif write_policy == 'upsert':
                self.datastore.upsert(data['target_table'], data['upsert_key'], data['records'], meta)
            elif write_policy == 'bulk_insert':
                self.datastore.bulk_insert(data['target_table'], data['records'], meta)
            elif write_policy == 'delete_insert':
                self.datastore.delete(data['target_table'], data['delete_keys'])
                self.datastore.insert(data['target_table'], data['records'], meta)
            elif write_policy == 'delete_bulk_insert':
                self.datastore.delete(data['target_table'], data['delete_keys'])
                self.datastore.bulk_insert(data['target_table'], data['records'], meta)
            elif write_policy == 'truncate_insert':
                self.datastore.truncate(data['target_table'])
                self.datastore.insert(data['target_table'], data['records'], meta)
            else:
                self.datastore.truncate(data['target_table'])
                self.datastore.bulk_insert(data['target_table'], data['records'], meta)
        except:
            raise BadRequest('An error occured while writing in datastore')

        return Response(json.dumps({'target_table': data['target_table'], 'count': len(data['records'])}),
                        mimetype='application/json', status=201)

    @cors_http('POST', '/api/v1/command/datastore/update_transformations', allowed_roles=('admin'),
               expected_exceptions=BadRequest)
    def datastore_update_transformations(self, request):
        data = self._handle_request_data(request)

        if 'trigger_table' not in data:
            raise BadRequest('Missing trigger_table parameter in request data')

        trigger_table = data['trigger_table']

        pipeline = bson.json_util.loads(self.metadata.get_update_pipeline(trigger_table))

        if not pipeline:
            return Response(json.dumps({'trigger_table': trigger_table}), mimetype ='application/json',
                            status=200)

        for job in pipeline:
            for t in job['transformations']:
                try:
                    self.datastore.create_or_replace_python_function(t['function_name'], t['function'])
                except:
                    raise BadRequest('An error occured while creating python function in transformation {}'.format(t['id']))

                if t['type'] == 'fit' and t['process_date'] is None:
                    try:
                        last_entry = bson.json_util.loads(self.datareader.select(t['output']))
                        if last_entry and len(last_entry) > 0:
                            self.datastore.delete(t['target_table'], {'id': last_entry[0]['id']})
                        self.datastore.insert_from_select(t['target_table'], t['output'], None)
                    except:
                        raise BadRequest('An error occured while fitting transformation {}'.format(t['id']))
                    self.metadata.update_process_date(t['id'])
                elif t['type'] in ('transform', 'predict',) and t['materialized'] is True:
                    try:
                        if t['parameters'] is None:
                            self.datastore.truncate(t['target_table'])
                            self.datastore.insert_from_select(t['target_table'], t['output'], None)
                        else:
                            if len(t['parameters']) > 1:
                                raise BadRequest('Does not support transformation with multiple parameters')
                            param_name = t['parameters'][0]
                            if 'parameter' not in data:
                                raise BadRequest('Transformation requires a parameter')
                            param_value = data['parameter']
                            self.datastore.delete(t['target_table'], {param_name: param_value})
                            self.datastore.insert_from_select(t['target_table'], t['output'], [param_value])
                    except:
                        raise BadRequest('An error occured while computing transformation {}'.format(t['id']))
                    self.metadata.update_process_date(t['id'])
        return Response(json.dumps({'trigger_table': trigger_table}), mimetype ='application/json',
                        status=201)

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

    @cors_http('POST', '/api/v1/command/referential/add_picture_to_entity/<string:entity_id>', allowed_roles=('admin', 'write'),
               expected_exceptions=BadRequest)
    def referential_add_picture_to_entity(self, request, entity_id):
        data = self._handle_request_data(request)
        try:
            self.referential.add_picture_to_entity(entity_id, data['context'], data['format'], data['picture_b64'])
        except:
            raise BadRequest('An error occured while adding picture to entity')
        return Response(json.dumps({'id': entity_id}), mimetype='application/json', status=201)

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
        entity = bson.json_util.loads(self.referential.get_entity_by_id(entity_id))

        if not entity:
            raise NotFound('Entity not found')

        return Response(json.dumps(entity, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/referential/event/<string:event_id>', allowed_roles=('admin', 'write', 'read'),
               expected_exceptions=(BadRequest, NotFound))
    def referential_get_event_by_id(self, request, event_id):
        event = bson.json_util.loads(self.referential.get_event_by_id(event_id))

        if not event:
            raise NotFound('Event not found')

        return Response(json.dumps(event, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/referential/search_entity', allowed_roles=('admin', 'write', 'read',),
               expected_exceptions=BadRequest)
    def referential_search_entity(self, request):
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
            entities = bson.json_util.loads(self.referential.search_entity(name, type=type, provider=provider))
        except:
            raise BadRequest('An error occured while searching entity')

        return Response(json.dumps(entities, cls=DateEncoder), mimetype='application/json')

    @cors_http('GET', '/api/v1/query/referential/search_event', allowed_roles=('admin', 'write', 'read',),
               expected_exceptions=BadRequest)
    def referential_search_event(self, request):
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
            events = bson.json_util.loads(self.referential.search_event(name, date, type=type, provider=provider))
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

    @cors_http('GET', '/api/v1/query/referential/search', allowed_roles=('admin', 'write', 'read'),
               expected_exceptions=BadRequest)
    def referential_fuzzy_search(self, request):
        if 'query' not in request.args:
            raise BadRequest('No query in request s arguments')
        query = request.args['query']

        if 'type' not in request.args:
            raise BadRequest('No type in request s arguments')
        type = request.args['type']

        if 'provider' not in request.args:
            raise BadRequest('No provider in request s arguments')
        provider = request.args['provider']

        results = bson.json_util.loads(self.referential.fuzzy_search(query, type, provider))
        return Response(json.dumps(results), mimetype='application/json')
