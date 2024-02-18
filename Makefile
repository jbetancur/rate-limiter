.PHONY: clearscr fresh clean

generate:
	go generate

build: 
	go build

compile: generate build

run: 
	sudo ./rate-limiter

clean:
	rm -f *.o $(EXEC)
	rm rate-limiter

fresh: clean 