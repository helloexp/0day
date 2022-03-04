#
# Build stage
#
FROM maven:3.6.0-jdk-11-slim AS build
COPY src /app/src
COPY pom.xml /app
RUN mvn -f /app/pom.xml clean package -DskipTests

#
# Package stage
#
FROM openjdk:11-jre-slim
EXPOSE 9000
RUN mkdir /app
COPY --from=0 /app/target/spring-gateway-demo-0.0.1-SNAPSHOT.jar /app 
ENTRYPOINT ["java","-jar","/app/spring-gateway-demo-0.0.1-SNAPSHOT.jar"]
