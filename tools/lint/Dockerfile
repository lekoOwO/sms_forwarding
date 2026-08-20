FROM alpine@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

ARG CPPCHECK_VERSION=2.14.2-r1
ARG GIT_VERSION=2.49.1-r0
ARG RUFF_VERSION=0.16.0
ARG SHELLCHECK_VERSION=0.10.0-r2

RUN apk add --no-cache \
        cppcheck="${CPPCHECK_VERSION}" \
        git="${GIT_VERSION}" \
        nodejs \
        npm \
        py3-pip \
        python3 \
        shellcheck="${SHELLCHECK_VERSION}" \
    && python3 -m venv /opt/lint-venv \
    && /opt/lint-venv/bin/pip install --no-cache-dir "ruff==${RUFF_VERSION}"

COPY web/package.json web/package-lock.json /opt/web/
RUN npm ci --prefix /opt/web --ignore-scripts

ENV LINT_NODE_MODULES=/opt/web \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/opt/web/node_modules/.bin:/opt/lint-venv/bin:$PATH

WORKDIR /workspace
CMD ["python3", "tools/run_lint.py"]
