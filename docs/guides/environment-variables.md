This document provides a complete reference of all environment variables used by ChronoGuard.
All configuration is managed via Pydantic Settings and loaded from environment variables with the prefix CHRONOGUARD_.

Variables are grouped by subsystem and include defaults, examples, and security notes where applicable.

Global Environment
| Variable                  | Default       | Description                                                                 |
| ------------------------- | ------------- | --------------------------------------------------------------------------- |
| `CHRONOGUARD_ENVIRONMENT` | `development` | Application environment (`development`, `testing`, `staging`, `production`) |
| `CHRONOGUARD_DEBUG`       | `false`       | Global debug mode                                                           |

Example

CHRONOGUARD_ENVIRONMENT=production
CHRONOGUARD_DEBUG=false

Database Configuration (PostgreSQL / TimescaleDB)

Prefix: CHRONOGUARD_DB_
| Variable                      | Default       | Description                       | Security Notes             |
| ----------------------------- | ------------- | --------------------------------- | -------------------------- |
| `CHRONOGUARD_DB_HOST`         | `localhost`   | Database host                     | —                          |
| `CHRONOGUARD_DB_PORT`         | `5432`        | Database port                     | —                          |
| `CHRONOGUARD_DB_USER`         | `chronoguard` | Database user                     | —                          |
| `CHRONOGUARD_DB_PASSWORD`     | —             | Database password                 | **Required in production** |
| `CHRONOGUARD_DB_DATABASE`     | `chronoguard` | Database name                     | —                          |
| `CHRONOGUARD_DB_POOL_SIZE`    | `10`          | Connection pool size              | —                          |
| `CHRONOGUARD_DB_MAX_OVERFLOW` | `20`          | Max overflow connections          | —                          |
| `CHRONOGUARD_DB_POOL_TIMEOUT` | `30`          | Pool timeout (seconds)            | —                          |
| `CHRONOGUARD_DB_POOL_RECYCLE` | `3600`        | Connection recycle time (seconds) | —                          |
| `CHRONOGUARD_DB_ECHO`         | `false`       | Echo SQL statements               | Disable in production      |

Example

CHRONOGUARD_DB_HOST=postgres
CHRONOGUARD_DB_PORT=5432
CHRONOGUARD_DB_USER=chronoguard
CHRONOGUARD_DB_PASSWORD=strong_password_here
CHRONOGUARD_DB_DATABASE=chronoguard

Redis Configuration

Prefix: CHRONOGUARD_REDIS_
| Variable                             | Default     | Description                 |
| ------------------------------------ | ----------- | --------------------------- |
| `CHRONOGUARD_REDIS_HOST`             | `localhost` | Redis host                  |
| `CHRONOGUARD_REDIS_PORT`             | `6379`      | Redis port                  |
| `CHRONOGUARD_REDIS_DB`               | `0`         | Redis database index        |
| `CHRONOGUARD_REDIS_PASSWORD`         | —           | Redis password (optional)   |
| `CHRONOGUARD_REDIS_MAX_CONNECTIONS`  | `50`        | Max connection pool size    |
| `CHRONOGUARD_REDIS_SOCKET_TIMEOUT`   | `5`         | Socket timeout (seconds)    |
| `CHRONOGUARD_REDIS_SOCKET_KEEPALIVE` | `true`      | Enable TCP keepalive        |
| `CHRONOGUARD_REDIS_DECODE_RESPONSES` | `true`      | Decode responses to strings |

Celery (Background Tasks)

Prefix: CHRONOGUARD_CELERY_
| Variable                                  | Default                    | Description               |
| ----------------------------------------- | -------------------------- | ------------------------- |
| `CHRONOGUARD_CELERY_BROKER_URL`           | `redis://localhost:6379/1` | Celery broker URL         |
| `CHRONOGUARD_CELERY_RESULT_BACKEND`       | `redis://localhost:6379/2` | Result backend            |
| `CHRONOGUARD_CELERY_TASK_SERIALIZER`      | `json`                     | Task serializer           |
| `CHRONOGUARD_CELERY_RESULT_SERIALIZER`    | `json`                     | Result serializer         |
| `CHRONOGUARD_CELERY_ACCEPT_CONTENT`       | `["json"]`                 | Accepted content types    |
| `CHRONOGUARD_CELERY_TIMEZONE`             | `UTC`                      | Timezone                  |
| `CHRONOGUARD_CELERY_ENABLE_UTC`           | `true`                     | Enable UTC timestamps     |
| `CHRONOGUARD_CELERY_TASK_TIME_LIMIT`      | `300`                      | Hard time limit (seconds) |
| `CHRONOGUARD_CELERY_TASK_SOFT_TIME_LIMIT` | `270`                      | Soft time limit (seconds) |

Security & Authentication

Prefix: CHRONOGUARD_SECURITY_
| Variable                                           | Default        | Description          | Security Notes                                       |
| -------------------------------------------------- | -------------- | -------------------- | ---------------------------------------------------- |
| `CHRONOGUARD_SECURITY_SECRET_KEY`                  | auto-generated | JWT signing key      | **Must be set explicitly in production (≥32 chars)** |
| `CHRONOGUARD_SECURITY_ALGORITHM`                   | `HS256`        | JWT algorithm        | —                                                    |
| `CHRONOGUARD_SECURITY_ACCESS_TOKEN_EXPIRE_MINUTES` | `30`           | Access token expiry  | —                                                    |
| `CHRONOGUARD_SECURITY_REFRESH_TOKEN_EXPIRE_DAYS`   | `7`            | Refresh token expiry | —                                                    |
| `CHRONOGUARD_SECURITY_BCRYPT_ROUNDS`               | `12`           | Bcrypt hash rounds   | Higher = slower, safer                               |

Demo Mode (Development Only)

| Variable                                   | Default    | Description                |
| ------------------------------------------ | ---------- | -------------------------- |
| `CHRONOGUARD_SECURITY_DEMO_MODE_ENABLED`   | `false`    | Enable demo authentication |
| `CHRONOGUARD_SECURITY_DEMO_ADMIN_PASSWORD` | —          | Demo admin password        |
| `CHRONOGUARD_SECURITY_DEMO_TENANT_ID`      | fixed UUID | Demo tenant ID             |
| `CHRONOGUARD_SECURITY_DEMO_USER_ID`        | fixed UUID | Demo user ID               |

⚠️ Never enable demo mode in production

Session Cookies

| Variable                                        | Default               | Description        |
| ----------------------------------------------- | --------------------- | ------------------ |
| `CHRONOGUARD_SECURITY_SESSION_COOKIE_NAME`      | `chronoguard_session` | Cookie name        |
| `CHRONOGUARD_SECURITY_SESSION_COOKIE_SECURE`    | `true`                | HTTPS-only cookies |
| `CHRONOGUARD_SECURITY_SESSION_COOKIE_SAME_SITE` | `lax`                 | SameSite policy    |
| `CHRONOGUARD_SECURITY_SESSION_COOKIE_DOMAIN`    | —                     | Optional domain    |
| `CHRONOGUARD_SECURITY_SESSION_COOKIE_PATH`      | `/`                   | Cookie path        |

API Server (FastAPI)

Prefix: CHRONOGUARD_API_
| Variable                      | Default           | Description     |
| ----------------------------- | ----------------- | --------------- |
| `CHRONOGUARD_API_TITLE`       | `ChronoGuard API` | API title       |
| `CHRONOGUARD_API_DESCRIPTION` | —                 | API description |
| `CHRONOGUARD_API_VERSION`     | `1.0.0`           | API version     |
| `CHRONOGUARD_API_HOST`        | `127.0.0.1`       | API bind host   |
| `CHRONOGUARD_API_PORT`        | `8000`            | API port        |
| `CHRONOGUARD_API_WORKERS`     | `4`               | Uvicorn workers |
| `CHRONOGUARD_API_RELOAD`      | `false`           | Auto-reload     |
| `CHRONOGUARD_API_DEBUG`       | `false`           | Debug mode      |

Observability (Logging, Metrics, Tracing)

Prefix: CHRONOGUARD_OBSERVABILITY_
| Variable                                        | Default       | Description       |
| ----------------------------------------------- | ------------- | ----------------- |
| `CHRONOGUARD_OBSERVABILITY_LOG_LEVEL`           | `INFO`        | Log level         |
| `CHRONOGUARD_OBSERVABILITY_LOG_FORMAT`          | `json`        | `json` or `text`  |
| `CHRONOGUARD_OBSERVABILITY_LOG_FILE_PATH`       | —             | Log file path     |
| `CHRONOGUARD_OBSERVABILITY_METRICS_ENABLED`     | `true`        | Enable Prometheus |
| `CHRONOGUARD_OBSERVABILITY_METRICS_PORT`        | `9090`        | Metrics port      |
| `CHRONOGUARD_OBSERVABILITY_TRACING_ENABLED`     | `true`        | Enable tracing    |
| `CHRONOGUARD_OBSERVABILITY_TRACING_ENDPOINT`    | —             | OTLP endpoint     |
| `CHRONOGUARD_OBSERVABILITY_TRACING_SAMPLE_RATE` | `1.0`         | Trace sampling    |
| `CHRONOGUARD_OBSERVABILITY_SERVICE_NAME`        | `chronoguard` | Service name      |

Proxy & OPA Configuration

Prefix: CHRONOGUARD_PROXY_
| Variable                                 | Default                      | Description       |
| ---------------------------------------- | ---------------------------- | ----------------- |
| `CHRONOGUARD_PROXY_ENVOY_XDS_PORT`       | `18000`                      | Envoy xDS port    |
| `CHRONOGUARD_PROXY_ENVOY_ADMIN_PORT`     | `9901`                       | Envoy admin port  |
| `CHRONOGUARD_PROXY_ENVOY_PROXY_PORT`     | `8443`                       | Proxy port        |
| `CHRONOGUARD_PROXY_ENVOY_CLUSTER_NAME`   | `chronoguard_cluster`        | Envoy cluster     |
| `CHRONOGUARD_PROXY_OPA_URL`              | `http://localhost:8181`      | OPA server URL    |
| `CHRONOGUARD_PROXY_OPA_POLICY_PATH`      | `/v1/data/chronoguard/allow` | Policy path       |
| `CHRONOGUARD_PROXY_OPA_DECISION_LOGGING` | `true`                       | Decision logging  |
| `CHRONOGUARD_PROXY_OPA_TIMEOUT`          | `5`                          | Timeout (seconds) |

Storage (Audit Logs & Exports)

Prefix: CHRONOGUARD_STORAGE_
| Variable                         | Default                        | Description        |
| -------------------------------- | ------------------------------ | ------------------ |
| `CHRONOGUARD_STORAGE_BACKEND`    | `local`                        | `local` or `s3`    |
| `CHRONOGUARD_STORAGE_LOCAL_PATH` | `/var/lib/chronoguard/storage` | Local storage path |

S3 (Optional)

| Variable                                   | Default     | Description             |
| ------------------------------------------ | ----------- | ----------------------- |
| `CHRONOGUARD_STORAGE_S3_BUCKET`            | —           | S3 bucket name          |
| `CHRONOGUARD_STORAGE_S3_REGION`            | `us-east-1` | S3 region               |
| `CHRONOGUARD_STORAGE_S3_ACCESS_KEY_ID`     | —           | Access key              |
| `CHRONOGUARD_STORAGE_S3_SECRET_ACCESS_KEY` | —           | Secret key              |
| `CHRONOGUARD_STORAGE_S3_ENDPOINT_URL`      | —           | Custom endpoint (MinIO) |

Notes

All variables are case-insensitive
Defaults are safe for development
Production requires explicit secrets
Validation errors will occur on startup if required values are missing