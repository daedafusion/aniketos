FROM java:8

RUN mkdir -p /opt/argos/plugins
RUN mkdir -p /var/log/argos
RUN mkdir -p /etc/argos

VOLUME ["/var/log/argos", "/etc/argos"]

EXPOSE 30012 40012

ENTRYPOINT ["java -jar /opt/argos/aniketos-server.jar"]