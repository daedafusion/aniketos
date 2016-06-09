FROM java:8

ENV PROJECT_VERSION=1.0-SNAPSHOT

RUN mkdir -p /opt/argos/plugins
RUN mkdir -p /var/log/argos
RUN mkdir -p /etc/argos

ADD target/aniketos-default-providers-${PROJECT_VERSION}-plugin.zip /opt/argos/plugins/aniketos-default-providers-plugin.zip
ADD target/aniketos-hibernate-providers-${PROJECT_VERSION}-plugin.zip /opt/argos/plugins/aniketos-hibernate-providers-plugin.zip
ADD target/aniketos-stub-providers-${PROJECT_VERSION}-plugin.zip /opt/argos/plugins/aniketos-stub-providers-plugin.zip
ADD target/aniketos-server.jar /opt/argos/aniketos-server.jar

VOLUME ["/var/log/argos", "/etc/argos"]

EXPOSE 30001 40001

ENTRYPOINT ["java -jar /opt/argos/aniketos-server.jar"]
