set -euo pipefail
export PATH=/opt/traflens-rust/bin:$PATH
printf 'TRAFLENS_PHASE=environment\n'
rustc --version
cargo --version
cc --version | head -1
nproc
git rev-parse HEAD
git status --porcelain
sha256sum Cargo.lock
printf 'TRAFLENS_PHASE=default-release-build\n'
if cargo build --release --locked --offline --bin deepflow-agent; then
  printf 'TRAFLENS_BUILD_EXIT=0\n'
else
  code=$?; printf 'TRAFLENS_BUILD_EXIT=%s\n' "$code"; exit "$code"
fi
/target/release/deepflow-agent -v
printf 'TRAFLENS_PHASE=rebuild-native-c-fixture\n'
make -B -C resources/test/plugins
sha256sum resources/test/plugins/so_plugin_test resources/test/plugins/so_plugin_test.c src/plugin/shared_obj/so_plugin.h
printf 'TRAFLENS_PHASE=default-release-cffi-tests\n'
if cargo test --release --locked --offline --lib plugin::c_ffi::process_kname_tests -- --nocapture --test-threads=1; then
  printf 'TRAFLENS_TEST_EXIT=0\n'
else
  code=$?; printf 'TRAFLENS_TEST_EXIT=%s\n' "$code"; exit "$code"
fi
printf 'TRAFLENS_PHASE=finished\n'
git status --porcelain
