FROM debian:jessie

RUN apt-get update ; \
	apt-get install -y python3 python3-pip ; \
	pip3 install pip --upgrade ;

RUN pip3 install nameko flask_restful

RUN mkdir /service 

ADD application /service/application
ADD ./cluster.yml /service

WORKDIR /service
