.PHONY: all bridge shield nose core mouth clean

all: bridge shield nose core mouth

bridge:
	cmake -B build -S bridge -DCMAKE_BUILD_TYPE=Release
	cmake --build build --config Release

shield:
	cargo build --release --manifest-path shield/Cargo.toml

nose:
	cd nose && go build -o ../dist/nose_dashboard.exe .

core:
	zig build

mouth:
	rustc -O mouth/windows_sec_monitor.rs -o dist/windows_sec_monitor.exe

clean:
	-rm -rf build/ zig-out/ shield/target/ dist/
	-del /Q /S build\* zig-out\* shield\target\* dist\* 2>nul
