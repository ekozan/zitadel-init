FROM alpine:3.14
#RUN apk add --no-cache mysql-client
COPY init.sh init.sh
ENTRYPOINT ["sh init.sh"]

