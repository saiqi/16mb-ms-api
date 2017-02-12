import os

from flask import Flask
from flask_restful import Api, Resource, reqparse
from nameko.standalone.rpc import ClusterRpcProxy

CONFIG = {
    'AMQP_URI': "amqp://{user}:{password}@{host}:{port}".format(user=os.getenv('RABBITMQ_USER'),
                                                                password=os.getenv('RABBITMQ_PASSWORD'),
                                                                host=os.getenv('RABBITMQ_HOST'),
                                                                port=os.getenv('RABBITMQ_PORT'))}

app = Flask(__name__)
app.config['DEBUG'] = True

api = Api(app)


class TwitterAddUserCommand(Resource):

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('user_id')

        args = parser.parse_args()

        with ClusterRpcProxy(CONFIG) as rpc:
            rpc.tweet_collector.add_user.async(args['user_id'])

        return 'Adding user {user} to referential'.format(user=args['user_id']), 201


class RssAddFeedCommand(Resource):

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('feed_url')

        args = parser.parse_args()

        with ClusterRpcProxy(CONFIG) as rpc:
            rpc.rss_collector.add_feed.async(args['feed_url'])

        return 'Adding feed {feed} to referential'.format(feed=args['feed_url']), 201

api.add_resource(TwitterAddUserCommand, '/api/v1/twitter/command/add_user')
api.add_resource(RssAddFeedCommand, '/api/v1/rss/command/add_feed')

if __name__ == '__main__':
    app.run()
