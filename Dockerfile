FROM eclipse-temurin:21-jre-alpine


RUN apk add --no-cache bash coreutils
WORKDIR /app
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh


COPY target/*.jar app.jar


ENTRYPOINT ["/app/entrypoint.sh"]


CMD ["java", "-jar", "app.jar"]
