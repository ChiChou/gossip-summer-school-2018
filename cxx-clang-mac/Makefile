build: prepare
	clang main.cpp -lstdc++ -o build/demo -framework CoreFoundation

prepare:
	mkdir -p build

run: build
	./build/demo

format:
	clang-format -i main.cpp

dump:
	clang -cc1 -fdump-record-layouts main.cpp

clean:
	rm -rf build/