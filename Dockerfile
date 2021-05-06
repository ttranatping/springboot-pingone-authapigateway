# Maven build container
  
FROM maven:3.6.3-openjdk-11-slim AS maven_build

WORKDIR /tmp/

COPY pom.xml /tmp/
RUN mvn dependency:go-offline

COPY src /tmp/src/

COPY cert /tmp/cert/


RUN mvn package

#pull base image

FROM adoptopenjdk/openjdk11:jdk-11.0.2.9-alpine-slim

RUN apk --no-cache --update add git

# resolving CVE-2019-14697
RUN apk upgrade musl

COPY cert /tmp/cert/

#maintainer
MAINTAINER ttran@pingidentity.com
#expose port 443
EXPOSE 443

COPY --from=maven_build /tmp/target/pingone-auth-gateway-0.0.1-SNAPSHOT.jar /tmp/app.jar

CMD cd /tmp/ && java -jar /tmp/app.jar --debug
