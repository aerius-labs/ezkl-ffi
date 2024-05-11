DEPS:=ezkl-ffi.h libezkl-ffi.a

all: $(DEPS)
.PHONY: all

$(DEPS): .install-ezkl-ffi  ;

.install-ezkl-ffi: rust
	cd rust && cargo build --release --all; cd ..
	find ./rust/target/release -type f -name "ezkl-ffi.h" -print0 | xargs -0 ls -t | head -n 1 | xargs -I {} cp {} ./cgo/ezkl-ffi.h
	find ./rust/target/release -type f -name "libezkl_ffi.a" -print0 | xargs -0 ls -t | head -n 1 | xargs -I {} cp {} ./cgo/libezkl_ffi.a
	c-for-go --ccincl ezkl-ffi.yml
	@touch $@

clean:
	rm -rf $(DEPS) .install-ezkl-ffi
	rm -rf ./rust/target/release/build/ezkl-ffi-*
	rm -rf cgo/*.go
	rm -rf cgo/*.h
	rm -rf cgo/*.a
.PHONY: clean