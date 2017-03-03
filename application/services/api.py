import json

from nameko.web.handlers import http
from nameko.rpc import RpcProxy


class ApiService(object):
    name = 'api_service'
    
    twitter_rpc = RpcProxy('tweet_collector')
    rss_rpc = RpcProxy('rss_collector')
    opta_rpc = RpcProxy('opta_collector')
    
    @http('POST', '/api/v1/command/twitter/add_user')
    def twitter_add_user(self, request):
        user_id = json.loads(request.get_data(as_text=True))['user_id']
        
        inserted_id = self.twitter_rpc.add_user(user_id)
        
        return 'Twitter user {} inserted'.format(inserted_id)
        
    @http('POST', '/api/v1/command/rss/add_feed')
    def rss_add_feed(self, request):
        feed_url = json.loads(request.get_data(as_text=True))['feed_url']
        
        self.rss_rpc.add_feed(feed_url)
        
        return 'RSS feed {} inserted'.format(feed_url)
        
    @http('POST', '/api/v1/command/opta/add_f1')
    def opta_add_f1(self, request):
        data = json.loads(request.get_data(as_text=True))
        season_id = data['season_id']
        competition_id = data['competition_id']
        
        self.opta_rpc.add_f1(season_id, competition_id)
        
        return 'Opta F1 for season {} and competition {} inserted'.format(season_id, competition_id)

    @http('POST', '/api/v1/command/opta/update_all_f9')
    def opta_add_f1(self, request):
        data = json.loads(request.get_data(as_text=True))
        season_id = data['season_id']
        competition_id = data['competition_id']

        self.opta_rpc.update_all_f9(season_id, competition_id)

        return 'Opta F9 for season {} and competition {} inserted'.format(season_id, competition_id)
