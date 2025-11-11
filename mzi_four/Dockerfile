# -------------------------------------------------
# ЭТАП 1: Сборка JAR с Maven + JDK 23
# -------------------------------------------------
FROM maven:3.9.9-eclipse-temurin-23 AS build
WORKDIR /app

# Кэшируем зависимости (ускоряет повторные сборки)
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Копируем исходники
COPY src ./src

# Собираем JAR без тестов
RUN mvn clean package -DskipTests -B

# -------------------------------------------------
# ЭТАП 2: Запуск с JRE 23 (минимальный образ)
# -------------------------------------------------
FROM eclipse-temurin:23-jre-alpine
WORKDIR /app

# Копируем JAR из этапа сборки
COPY --from=build /app/target/*.jar app.jar

# Порт Spring Boot
EXPOSE 8080

# Запуск
ENTRYPOINT ["java", "-jar", "app.jar"]