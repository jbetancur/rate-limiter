.PHONY: fresh clean

generate:
	go generate

build: 
	go build

compile: generate build

build-image: compile
	docker build -t rate-limiter .

run-container: build-image
	sudo docker run --privileged --network host rate-limiter

run: generate build
	sudo ./rate-limiter

clean:
	rm -f *.o $(EXEC)
	rm rate-limiter

fresh: clean

testapp:
	go run web/main.go

# mon:
# 	sudo prometheus --config.file=monitoring/prometheus.yml
