current_dir = $(shell pwd)
export RUST_BACKTRACE := 1
export SODIUM_LIB_DIR := $(current_dir)/local/lib/
export SODIUM_STATIC := yes

SPEC_TEST_DIR=tests/spec
TMP_DIR=/tmp/mysteryshack
APP_BINARY=./target/debug/mysteryshack
TEST_CMD=$(APP_BINARY) -c $(TMP_DIR)/config

all: libsodium
	$(MAKE) release-build

release-build:
	cargo build --release

debug-build:
	cargo build

libsodium:
	[ -d libsodium ] || git clone https://github.com/jedisct1/libsodium libsodium
	set -ex && cd libsodium && \
		git fetch && \
		git checkout origin/stable && \
		rm -rf lib && \
		./autogen.sh && \
		./configure --prefix=$$PWD/../local/ --disable-shared && \
		$(MAKE) && \
		$(MAKE) install

install-test: install-spectest

test: spectest unittest

install-spectest:
	set -ex; \
	[ -d $(SPEC_TEST_DIR)/suite ] || git clone https://github.com/remotestorage/api-test-suite $(SPEC_TEST_DIR)/suite
	cd $(SPEC_TEST_DIR)/suite && bundle install --path vendor/bundle

testserver-config: debug-build
	rm -r $(TMP_DIR) || true
	mkdir -p $(TMP_DIR)
	echo '[main]' > $(TMP_DIR)/config
	echo 'listen = "localhost:6767"' >> $(TMP_DIR)/config
	echo "data_path = \"$(TMP_DIR)\"" >> $(TMP_DIR)/config
	# Insecure but useful for weird hacks to avoid SSL setup
	echo "use_proxy_headers = true" >> $(TMP_DIR)/config
	yes password123 | $(TEST_CMD) user testuser create

spectest: testserver-config
	($(MAKE) testserver &);
	wget -q --retry-connrefused --waitretry=1 http://localhost:6767/ -O /dev/null
	set e && ( \
		echo 'storage_base_url: http://localhost:6767/storage/testuser'; \
		echo 'storage_base_url_other: http://localhost:6767/storage/wronguser'; \
		echo 'category: api-test'; \
		echo -n 'token: '; \
		$(TEST_CMD) user testuser authorize https://example.com api-test:rw; \
		echo -n 'read_only_token: '; \
		$(TEST_CMD) user testuser authorize https://example.com api-test:r; \
		echo -n 'root_token: '; \
		$(TEST_CMD) user testuser authorize https://example.com \*:rw; \
	) > $(SPEC_TEST_DIR)/suite/config.yml
	cd $(SPEC_TEST_DIR)/suite && rake test

testserver: debug-build
	killall mysteryshack || true
	$(TEST_CMD) serve

serve: testserver-config
	$(MAKE) testserver

install-codegen:
	true

codegen:
	scripts/make_templates.py
	scripts/make_staticfiles.py

install-clippy:
	true

clippy:
	cargo build --features clippy


sh:
	$$SHELL

install-unittest:
	true

unittest:
	cargo test

.PHONY: test libsodium
