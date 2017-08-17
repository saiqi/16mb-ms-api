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

    @http('POST', '/api/v1/command/opta/add_f1', ('admin', 'write',))
    def opta_add_f1(self, request):
        try:
            data = json.loads(request.get_data(as_text=True))
            season_id = data['season_id']
            competition_id = data['competition_id']
        except:
            raise BadRequest()

        with ClusterRpcProxy(self.config) as rpc:
            rpc.opta_collector.add_f1.call_async(season_id, competition_id)

            return 'Inserting Opta F1 for season {} and competition {}'.format(season_id, competition_id)

    @http('POST', '/api/v1/command/picture/add', ('admin', 'write',))
    def picture_add(self, request):
        try:
            data = json.loads(request.get_data(as_text=True))
            entity_id = data['entity_id']
            context_id = data['context_id']
            format_id = data['format_id']
            picture_b64 = data['picture_b64']
        except:
            raise BadRequest()

        with ClusterRpcProxy(self.config) as rpc:
            rpc.picturestore.add_picture.call_async(entity_id, context_id, format_id, picture_b64)

            return 'Uploading picture for {} in context {} in format {}'.format(entity_id, context_id, format_id)

    @http('POST', '/api/v1/command/picture/delete', ('admin', 'write',))
    def picture_delete(self, request):
        try:
            data = json.loads(request.get_data(as_text=True))
            entity_id = data['entity_id']
            context_id = data['context_id']
            format_id = data['format_id']
        except:
            raise BadRequest()

        with ClusterRpcProxy(self.config) as rpc:
            rpc.picturestore.delete_picture.call_async(entity_id, context_id, format_id)

            return 'Deleting picture for {} in context {} in format {}'.format(entity_id, context_id, format_id)

    @http('POST', '/api/v1/command/formula/add', ('admin', 'write',))
    def formula_add(self, request):
        try:
            data = json.loads(request.get_data(as_text=True))
            raw_formula = data['raw_formula']
            id = data['id']
            is_success_rate = data['is_success_rate']
            is_negative = data['is_negative']
            context = data['context']
            category = data['category']
        except:
            raise BadRequest()

        with ClusterRpcProxy(self.config) as rpc:
            rpc.formulastore.add_formula.call_async(raw_formula, id, is_success_rate, is_negative, context, category)

            return 'Inserting new formula {}'.format(id)

    @http('POST', '/api/v1/command/formula/delete', ('admin', 'write',))
    def formula_delete(self, request):
        try:
            data = json.loads(request.get_data(as_text=True))
            id = data['id']
        except:
            raise BadRequest()

        with ClusterRpcProxy(self.config) as rpc:
            rpc.formulastore.delete_formula.call_async(id)

            return 'Deleting formula {}'.format(id)

    @http('GET', '/api/v1/query/formulas', ('admin', 'write'))
    def get_formulas(self, request):
        data = None
        if request.get_data():
            data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            if data and 'context' in data:
                if 'category' in data:
                    result = rpc.formulastore.get_formulas_by_category(data['context'], data['category'])
                else:
                    result = rpc.formulastore.get_formulas_by_context(data['context'])
            else:
                result = rpc.formulastore.get_formulas()

            return Response(json.dumps(result), mimetype='application/json')

    @http('POST', '/api/v1/command/translation/add', ('admin', 'write',))
    def translation_add(self, request):
        try:
            data = json.loads(request.get_data(as_text=True))
            identifier = data['identifier']
            language = data['language']
            translation = data['translation']
        except:
            raise BadRequest()

        with ClusterRpcProxy(self.config) as rpc:
            rpc.internationalizer.add_translation.call_async(identifier, language, translation)
            
            return 'Inserting translation {} {}'.format(identifier, language)

    @http('POST', '/api/v1/command/translation/delete', ('admin', 'write',))
    def translation_delete(self, request):
        try:
            data = json.loads(request.get_data(as_text=True))
            identifier = data['identifier']
            language = data['language']
        except:
            raise BadRequest()

        with ClusterRpcProxy(self.config) as rpc:
            rpc.internationalizer.delete_translation.call_async(identifier, language)

            return 'Deleting translation {} {}'.format(identifier, language)

    @http('GET', '/api/v1/query/translations', ('admin', 'write',))
    def get_translations(self, request):
        data = None
        if request.get_data():
            data = json.loads(request.get_data(as_text=True))
        with ClusterRpcProxy(self.config) as rpc:
            if data and 'identifier' in data:
                result = rpc.internationalizer.get_translations_by_identifier(data['identifier'])
            else:
                result = rpc.internationalizer.get_all_translations()

            return Response(json.dumps(result), mimetype='application/json')

    @http('POST', '/api/v1/command/algorithm/add', ('admin',))
    def algorithm_add(self, request):
        try:
            data = json.loads(request.get_data(as_text=True))
            id = data['id']
            train_dataset = data['train_dataset']
            run_dataset = data['run_dataset']
            fit_function = data['fit_function']
            predict_function = data['predict_function']
            context = data['context']
            target_table = data['target_table']
            depends_on_id = None
            if 'depends_on_id' in data:
                depends_on_id = data['depends_on_id']
        except:
            raise BadRequest()

        with ClusterRpcProxy(self.config) as rpc:
            rpc.algorithm.add_algorithm.call_async(id, train_dataset, run_dataset, fit_function, predict_function,
                                                   depends_on_id, context, target_table)

            return 'Inserting new algorithm {}'.format(id)

    @http('POST', '/api/v1/command/algorithm/delete', ('admin',))
    def algorithm_delete(self, request):
        try:
            data = json.loads(request.get_data(as_text=True))
            id = data['id']
        except:
            raise BadRequest()

        with ClusterRpcProxy(self.config) as rpc:
            rpc.algorithm.delete_algorithm.call_async(id)

            return 'Deleting algorithm {}'.format(id)

    @http('POST', '/api/v1/command/algorithm/fit', ('admin',))
    def fit_algorithm(self, request):

        try:
            data = json.loads(request.get_data(as_text=True))
            id = data['id']
        except:
            raise BadRequest()

        with ClusterRpcProxy(self.config) as rpc:
            algo = rpc.algorithm.get_algorithm(id)

            rpc.datastore.create_or_replace_python_function(algo['fit_function_name'], algo['fit_function'])
            rpc.datastore.create_or_replace_python_function(algo['predict_function_name'], algo['predict_function'])

            rpc.datastore.delete('PIPELINE', {'id': algo['id']})
            rpc.datastore.insert_from_select.call_async('PIPELINE', algo['train_dataset'], None)

            return 'Fitting algorithm {}'.format(algo['id'])

    @http('GET', '/api/v1/query/playerstats', ('admin', 'read', 'write',))
    def get_soccer_playerstats(self, request):
        try:
            params = json.loads(request.get_data(as_text=True))
            player_id = params['player_id']
            category = params['category']
        except:
            raise BadRequest()

        with ClusterRpcProxy(self.config) as rpc:
            entity = rpc.referential.get_entity_by_id.call_async(player_id)

            formulas = rpc.formulastore.get_formulas_by_category('soccer', category)

            parsed_formulas = rpc.formula_parser.parse(formulas)

            try:
                query = rpc.dsas_query.get_playerstats_query(parsed_formulas, params)
            except:
                raise BadRequest()

            stats = rpc.datareader.select.call_async(query['query'], query['parameters'])

            result = dict()
            result['timestamp'] = datetime.datetime.utcnow().isoformat()

            result['entity_informations'] = bson.json_util.loads(entity.result())
            result['stats'] = bson.json_util.loads(stats.result())

            return Response(json.dumps(result), mimetype='application/json')
