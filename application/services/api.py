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

            return 'Inserting Opta F1 for season {} and competition {} ...'.format(season_id, competition_id)

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

            return 'Inserting new formula {} ...'.format(id)

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

    @http('POST', '/api/v1/command/algorithm/soccer/playerdna/fit', ('admin',))
    def fit_soccer_playerdna(self, request):
        with ClusterRpcProxy(self.config) as rpc:
            fit_function = rpc.dsas_query.get_fit_playerdna_function()
            predict_function = rpc.dsas_query.get_predict_playerdna_function()
            fit_query = rpc.dsas_query.get_fit_playerdna_query()

            rpc.datastore.create_or_replace_python_function('fit_soccer_player_dna', fit_function['function'])
            rpc.datastore.create_or_replace_python_function('predict_soccer_player_dna', predict_function['function'])

            rpc.datastore.delete('PIPELINE', {'id': 'soccer_player_dna'})
            rpc.datastore.insert_from_select.call_async('PIPELINE', fit_query['query'], None)

            return 'Fitting player DNA pipeline'

    @http('POST', '/api/v1/command/algorithm/soccer/playercluster/fit', ('admin',))
    def fit_soccer_playercluster(self, request):
        with ClusterRpcProxy(self.config) as rpc:
            if rpc.datastore.check_if_function_exists('predict_soccer_player_dna'):
                fit_function = rpc.dsas_query.get_fit_playercluster_function()
                predict_function = rpc.dsas_query.get_predict_playercluster_function()
                fit_query = rpc.dsas_query.get_fit_playercluster_query()

                rpc.datastore.create_or_replace_python_function('fit_soccer_player_cluster', fit_function['function'])
                rpc.datastore.create_or_replace_python_function('predict_soccer_player_cluster',
                                                                predict_function['function'])

                rpc.datastore.delete('PIPELINE', {'id': 'soccer_player_cluster'})
                rpc.datastore.insert_from_select.call_async('PIPELINE', fit_query['query'], None)

                return 'Fitting player cluster pipeline'

            raise BadRequest()

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
