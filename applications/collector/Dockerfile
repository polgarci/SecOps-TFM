# Backend
FROM golang:1.23 AS backend
WORKDIR /app
COPY /app .
RUN go build -o log-collector

# Frontend
FROM node:16 AS frontend
WORKDIR /frontend
COPY /app/frontend /frontend
RUN chmod +x node_modules/.bin/react-scripts
RUN npm install && npm run build

# Final image
FROM debian:trixie-slim
WORKDIR /
COPY --from=backend /app/log-collector /
COPY --from=frontend /frontend/build /static
RUN apt-get update && apt-get install -y libc6
EXPOSE 8080
ENTRYPOINT ["/log-collector"]