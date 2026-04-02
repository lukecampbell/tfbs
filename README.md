![CI](https://github.com/lukecampbell/tfbs/actions/workflows/ci.yml/badge.svg)
![Cargo Audit](https://github.com/lukecampbell/tfbs/actions/workflows/audit.yml/badge.svg)
![Gitleaks](https://github.com/lukecampbell/tfbs/actions/workflows/gitleaks.yml/badge.svg)

tfbs
====

A web application with a Rust (actix-web) backend serving REST APIs and a Vite PWA frontend.

- REST API with OpenAPI/Swagger documentation
- User management with argon2 password hashing
- SQLite for development, Postgres for production (via sqlx)
- Optional TLS with automatic self-signed certificate generation

Copyright 2026 Luke Campbell

See LICENSE for details.

Building
--------

Prerequisites: [Rust](https://www.rust-lang.org/tools/install) and [Node.js](https://nodejs.org/) (for the frontend).

Build the backend:

    cargo build

Build and bundle the frontend:

    make bundle

Run the server:

    cargo run

Run with TLS:

    cargo run -- --tls

API documentation is available at `/swagger-ui/` when the server is running.

For details about `cargo`, see [The Cargo Book](https://doc.rust-lang.org/cargo/commands/index.html).

Database
--------

By default, tfbs uses a local SQLite database. To use Postgres, set the `DATABASE_URL` environment variable:

    export DATABASE_URL=postgres://user:pass@localhost:5432/tfbs

A `docker-compose.yml` is provided to run Postgres locally:

    docker compose up -d

Migrations run automatically on startup.

Docker
------

To build the docker image:

    docker build -t tfbs .

To run the image as a docker container:

    docker run -it --rm tfbs
