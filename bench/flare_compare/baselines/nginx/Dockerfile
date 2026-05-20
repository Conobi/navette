# nginx 1.25.x in single-worker mode, serving GET /plaintext.
# Matches Flare's nginx baseline (worker_processes 1, /plaintext).
FROM nginx:1.25-alpine
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 8080
