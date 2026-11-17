FROM postgres:16
# Init scripts are baked into the image (no Windows bind-mount problems)
COPY init/ /docker-entrypoint-initdb.d/
RUN sed -i 's/\r$//' /docker-entrypoint-initdb.d/*.sh && chmod +x /docker-entrypoint-initdb.d/*.sh
