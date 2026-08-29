FROM nginx:1.27-alpine

COPY target/index.html /usr/share/nginx/html/index.html

