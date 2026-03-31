![Pipeline Status](http://git.axiom/axiom/tfbs/badges/main/pipeline.svg)
![Cargo Audit](http://git.axiom/axiom/tfbs/-/jobs/artifacts/main/raw/cargo-audit.svg?job=badger-cargo-audit)
![Trivy](http://git.axiom/axiom/tfbs/-/jobs/artifacts/main/raw/trivy-audit.svg?job=badger-trivy)


tfbs
===============

I don't really know just yet

Copyright 2026 Luke Campbell

See LICENSE for details.

Building
--------

In order to build the project, contributors need rust, see
[Install Rust](https://www.rust-lang.org/tools/install) for details about
installing the rust development environment on your system.

To build the project:

    cargo build

To run the binary without building a release version or installing to a locally available path:

    cargo run

For details about `cargo` and using `cargo`, please see [The Cargo Book](https://doc.rust-lang.org/cargo/commands/index.html)

Docker
------

To build the docker image:

    docker build -t tfbs .

To run the image as a docker container

    docker run -it --rm tfbs
