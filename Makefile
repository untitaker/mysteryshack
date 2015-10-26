export RUST_BACKTRACE := 1

SPEC_TEST_DIR=tests/spec
TMP_DIR=/tmp/mysteryshack
APP_BINARY=./target/debug/mysteryshack

install-test: install-spectest

test: spectest

install-spectest:
	set -ex; \
	[ -d $(SPEC_TEST_DIR)/suite ] || ( \
		git clone https://github.com/remotestorage/api-test-suite $(SPEC_TEST_DIR)/suite; \
		cd $(SPEC_TEST_DIR)/suite; \
		bundle install --path vendor/bundle; \
	)
	cargo build

spectest:
	cargo build
	killall mysteryshack || true
	rm -r $(TMP_DIR) || true
	mkdir -p $(TMP_DIR)
	echo '[main]' > $(TMP_DIR)/config
	echo 'listen = "localhost:6767"' >> $(TMP_DIR)/config
	echo "data_path = \"$(TMP_DIR)\"" >> $(TMP_DIR)/config
	cp $(SPEC_TEST_DIR)/suite-config.yml $(SPEC_TEST_DIR)/suite/config.yml
	set -ex; \
	bin="$(APP_BINARY) -c $(TMP_DIR)/config"; \
	yes password123 | $$bin user create testuser; \
	cp $(SPEC_TEST_DIR)/sessions.json $(TMP_DIR)/testuser/sessions.json; \
	($$bin serve &); \
	( \
		cd $(SPEC_TEST_DIR)/suite; \
		rake test; \
	)

serve:
	killall mysteryshack || true
	cargo run -- serve

.PHONY: test
