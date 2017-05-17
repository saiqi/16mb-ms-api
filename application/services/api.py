import json

from nameko.web.handlers import HttpRequestHandler
from nameko.standalone.rpc import ClusterRpcProxy
from nameko.dependency_providers import Config
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden
import jwt


class HttpAuthenticatedRequestHandler(HttpRequestHandler):
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

        if payload['role'] not in ('admin', 'write',):
            raise Forbidden()

        return super(HttpAuthenticatedRequestHandler, self).handle_request(request)


http = HttpAuthenticatedRequestHandler.decorator


class ApiService(object):
    name = 'api_service'

    config = Config()

    @http('POST', '/api/v1/command/twitter/add_user')
    def twitter_add_user(self, request):
        try:
            user_id = json.loads(request.get_data(as_text=True))['user_id']
        except:
            raise BadRequest()

        with ClusterRpcProxy(self.config) as rpc:
            rpc.tweet_collector.add_user.call_async(user_id)

            return 'Inserting twitter user {} ...'.format(user_id)

    @http('POST', '/api/v1/command/rss/add_feed')
    def rss_add_feed(self, request):
        try:
            feed_url = json.loads(request.get_data(as_text=True))['feed_url']
        except:
            raise BadRequest()

        with ClusterRpcProxy(self.config) as rpc:
            rpc.rss_collector.add_feed.call_async(feed_url)

            return 'Inserting RSS feed {} ...'.format(feed_url)

    @http('POST', '/api/v1/command/opta/add_f1')
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

    @http('POST', '/api/v1/command/opta/update_all_f9')
    def opta_update_all_f9(self, request):
        try:
            data = json.loads(request.get_data(as_text=True))
            season_id = data['season_id']
            competition_id = data['competition_id']
        except:
            raise BadRequest()

        with ClusterRpcProxy(self.config) as rpc:
            rpc.opta_collector.update_all_f9.call_async(season_id, competition_id)

            return 'Inserting Opta F9 for season {} and competition {} ...'.format(season_id, competition_id)

    @http('POST', '/api/v1/command/picture/add')
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

    @http('POST', '/api/v1/command/picture/delete')
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

    @http('POST', '/api/v1/command/formula/add')
    def formula_add(self, request):
        try:
            data = json.loads(request.get_data(as_text=True))
            raw_formula = data['raw_formula']
            name = data['name']
            is_success_rate = data['is_success_rate']
            is_negative = data['is_negative']
            context = data['context']
            category = data['category']
        except:
            raise BadRequest()

        to_parse = '|'.join([raw_formula, name, is_success_rate, is_negative])

        with ClusterRpcProxy(self.config) as rpc:
            formulas = rpc.formula_parser.parse([to_parse])
            rpc.formulastore.add_formula(raw_formula, name, is_success_rate, is_negative, context, category)

            if context == 'soccer':
                rpc.datastore.delete('SOCCER_ADVANCED_PLAYERSTAT', {'FORMULA_ID': name})
                query = rpc.dsas_query.get_playerstats_query(formulas)
                rpc.datastore.insert_from_select.call_async('SOCCER_ADVANCED_PLAYERSTAT', query['query'],
                                                            query['parameters'])

            return 'Inserting new formula {} ...'.format(name)

    @http('POST', '/api/v1/command/formula/delete')
    def formula_delete(self, request):
        try:
            data = json.loads(request.get_data(as_text=True))
            formula_id = data['formula_id']
        except:
            raise BadRequest()

        with ClusterRpcProxy(self.config) as rpc:
            formula = rpc.formulastore.get_formula(formula_id)

            if formula['context'] == 'soccer':
                rpc.datastore.delete.call_async('SOCCER_ADVANCED_PLAYERSTAT', {'FORMULA_ID': formula['name']})

            rpc.formulastore.delete_formula(formula_id)

            return 'Deleting formula {}'.format(formula_id)
