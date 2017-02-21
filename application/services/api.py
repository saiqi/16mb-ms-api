from nameko.web.handlers import http
from nameko.rpc import RpcProxy


class ApiService(object):
    name = 'api_service'
    
    twitter_rpc = RpcProxy('tweet_collector')
    rss_rpc = RpcProxy('rss_collector')
    
    @http('POST','/api/v1/command/twitter/add_user')
    def twitter_add_user(self, request):
        user_id = request.get_data(as_text=True)
        
        inserted_id = self.twitter_rpc.add_user(user_id)
        
        return 'Twitter user {} inserted'.format(inserted_id)
        
    @http('POST','/api/v1/command/rss/add_feed')
    def rss_add_feed(self, request):
        feed_url = request.get_data(as_text=True)
        
        self.rss_rpc.add_feed(feed_url)
        
        return 'RSS feed {} inserted'.format(feed_url)
        
        
    