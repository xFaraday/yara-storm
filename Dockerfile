#hunter's dockerfile lol
FROM alpine
RUN echo http://dl-cdn.alpinelinux.org/alpine/edge/testing >> /etc/apk/repositories
RUN apk update
RUN apk add yara yara-dev pkgconfig git go
WORKDIR /home/
RUN git clone https://github.com/xFaraday/yara-storm
WORKDIR /home/yara-storm
RUN mkdir -p /srv/yara-storm/rules 
RUN cp all-yara.yar /srv/yara-storm/rules
EXPOSE 42069
#CMD git reset --hard main
ENTRYPOINT git reset --hard main && go run main.go --port=42069