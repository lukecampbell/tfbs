.PHONY: docker-local docker-scan clean

IMAGE_NAME := tfbs

clean:
	rm -rf target reports

reports:
	mkdir -p reports

docker-local:
	docker build --ssh default -t $(IMAGE_NAME):latest .
	

docker-scan: docker-local reports
	docker run -it -v $${HOME}/.cache/trivy-docker:/cache -v $${PWD}/reports:/reports -v /var/run/docker.sock:/var/run/docker.sock --rm aquasec/trivy --cache-dir /cache image --format json --output=reports/trivy-$$(date +%Y%m%d%H%M%S).json $(IMAGE_NAME):latest
