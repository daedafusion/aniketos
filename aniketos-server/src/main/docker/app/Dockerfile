FROM daedafusion/java:1.7

RUN mkdir -p /opt/argos/plugins
RUN mkdir -p /var/log/argos
RUN mkdir -p /etc/argos

ADD aniketos-server.jar /opt/argos/aniketos-server.jar
ADD aniketos-default-providers-${project.version}-plugin.zip /opt/argos/plugins/aniketos-default-providers-plugin.zip
ADD aniketos-stub-providers-${project.version}-plugin.zip /opt/argos/plugins/aniketos-stub-providers-plugin.zip
ADD aniketos-hibernate-providers-${project.version}-plugin.zip /opt/argos/plugins/aniketos-hibernate-providers-plugin.zip

VOLUME ["/var/log/argos", "/etc/argos"]

EXPOSE 30001 40001

CMD ["java", "-jar", "/opt/argos/aniketos-server.jar"]
