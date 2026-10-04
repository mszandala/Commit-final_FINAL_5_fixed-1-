# Frontend: build Vite i nginx (bez roota), który serwuje interfejs i przekazuje /api oraz /v1 do backendu.
# Kontekst budowania to katalog główny repozytorium (docker compose build frontend).
FROM node:22-alpine AS build
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8080
