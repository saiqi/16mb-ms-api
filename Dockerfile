FROM debian:jessie

RUN apt-get update ; \
	apt-get install -y python3 python3-pip ; \
	pip3 install pip --upgrade ;

ADD ./requirements.txt /tmp/requirements.txt

RUN pip3 install -r /tmp/requirements.txt

RUN mkdir /service 

ADD application /service/application

EXPOSE 5000

WORKDIR /service

ENTRYPOINT ["gunicorn", "-b", "0.0.0.0:5000","-w","4","application.api:app"]
