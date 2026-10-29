.PHONY: setup test build clean

setup:
	mvn -q dependency:resolve

test:
	mvn -q test

build:
	mvn -q verify

clean:
	mvn -q clean
