FROM registry.access.redhat.com/ubi9/ubi:latest AS production

ENV API_KEY="api-key"
ENV OPENAPI_SPEC_URL="openapi-spec-url"
ENV SERVER_URL_OVERRIDE="server-url-override"
ENV PYTHONUNBUFFERED=1
ENV DEBUG=True

# Install dependencies
RUN dnf install -y \
    python3.12 \
    python3.12-pip

USER 1000
WORKDIR /var/www

COPY requirements.txt .
COPY mcp-server.py .

# Compile Python/Django application
RUN /usr/bin/python3.12 -m venv /var/www/venv
ENV PATH="/var/www/venv/bin:${PATH}"

RUN /var/www/venv/bin/python3.12 -m pip install --no-cache-dir --no-binary=all -r requirements.txt

# Launch!
ENTRYPOINT ["python3.12", "mcp-server.py", "0.0.0.0", "8000"]
CMD ["python3.12", "mcp-server.py", "0.0.0.0", "8000"]

EXPOSE 8000
