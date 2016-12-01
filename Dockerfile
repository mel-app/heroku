FROM alpine:latest

MAINTAINER Edward Muller <edward@heroku.com>

WORKDIR "/opt"

ADD .docker_build/heroku /opt/bin/heroku

CMD ["/opt/bin/heroku"]
