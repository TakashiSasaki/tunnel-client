#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly GENERATOR="${SCRIPT_DIR}/generate_homebrew_formula.sh"

fail() {
  echo "generate_homebrew_formula_test.sh: $*" >&2
  exit 1
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  [[ "${haystack}" == *"${needle}"* ]] ||
    fail "expected output to contain ${needle}"
}

assert_fails_with() {
  local expected="$1"
  shift

  local output
  if output="$("$@" 2>&1)"; then
    fail "expected command to fail: $*"
  fi
  assert_contains "${output}" "${expected}"
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

checksums="${tmp_dir}/SHA256SUMS.txt"
formula="${tmp_dir}/tunnel-client.rb"
cat > "${checksums}" <<'EOF'
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  tunnel-client-v1.2.3-darwin-amd64.zip
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  tunnel-client-v1.2.3-darwin-arm64.zip
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  tunnel-client-v1.2.3-linux-amd64.zip
dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd  tunnel-client-v1.2.3-linux-arm64.zip
eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee  tunnel-client-v1.2.3-all.tar.gz
EOF

"${GENERATOR}" --tag v1.2.3 --checksums "${checksums}" --output "${formula}"
generated="$(<"${formula}")"

assert_contains "${generated}" 'class TunnelClient < Formula'
assert_contains "${generated}" '# typed: strict'
assert_contains "${generated}" 'version "1.2.3"'
assert_contains "${generated}" 'url "https://persistent.oaistatic.com/tunnel-client/v#{version}/tunnel-client-v#{version}-darwin-amd64.zip"'
assert_contains "${generated}" 'sha256 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
assert_contains "${generated}" 'sha256 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"'
assert_contains "${generated}" 'sha256 "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"'
assert_contains "${generated}" 'sha256 "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"'
assert_contains "${generated}" 'if Hardware::CPU.is_64_bit?'
assert_contains "${generated}" 'libexec.install "tunnel-client", "cloudflared", "cloudflared-manifest.json"'
assert_contains "${generated}" 'bin.write_exec_script libexec/"tunnel-client"'
assert_contains "${generated}" 'service do'
assert_contains "${generated}" 'run [opt_bin/"tunnel-client", "run", "--profile-file", etc/"tunnel-client.yaml"]'
assert_contains "${generated}" 'keep_alive true'
assert_contains "${generated}" 'environment_variables PATH: std_service_path_env'
assert_contains "${generated}" 'log_path var/"log/tunnel-client.log"'
assert_contains "${generated}" 'error_log_path var/"log/tunnel-client.log"'
assert_contains "${generated}" 'assert_match version.to_s, shell_output("#{bin}/tunnel-client --version")'

command -v ruby >/dev/null 2>&1 || fail "ruby is required for formula syntax validation"
ruby -c "${formula}" >/dev/null

# Exercise the generated install method before Homebrew's cleanup makes bin
# wrappers executable. The packaged program is executable when installed.
ruby - "${formula}" "${tmp_dir}/install" <<'RUBY'
require "fileutils"
require "pathname"
require "shellwords"

class InstallPath < Pathname
  def install(*sources)
    mkpath
    sources.each { |source| FileUtils.cp(source, self/source, preserve: true) }
  end

  def write_exec_script(target)
    mkpath
    wrapper = self/target.basename
    wrapper.write("#!/bin/sh\nexec #{target.to_s.shellescape} \"$@\"\n")
    wrapper.chmod(0o644)
  end
end

class InstallFixture
  attr_reader :bin, :libexec, :completions

  def initialize(prefix)
    @bin = InstallPath.new(Pathname.new(prefix)/"bin")
    @libexec = InstallPath.new(Pathname.new(prefix)/"libexec")
    @completions = {}
  end

  def generate_completions_from_executable(*command)
    %w[bash zsh fish].each do |shell|
      output = IO.popen([*command.map(&:to_s), shell], &:read)
      abort "completion generation failed for #{shell}" unless $?.success?
      @completions[shell] = output
    end
  end
end

formula = File.read(ARGV.fetch(0))
install = formula[/^  def install\n.*?^  end\n/m]
abort "generated formula has no install method" unless install
InstallFixture.class_eval(install, ARGV.fetch(0))
staging = Pathname.new(ARGV.fetch(1))
staging.mkpath
Dir.chdir(staging) do
  Pathname("tunnel-client").write(<<~SH)
    #!/bin/sh
    test "$1" = completion || exit 1
    printf 'completion for %s\\n' "$2"
  SH
  File.chmod(0o755, "tunnel-client")
  Pathname("cloudflared").write("fixture\n")
  Pathname("cloudflared-manifest.json").write("{}\n")
  fixture = InstallFixture.new(staging/"prefix with spaces")
  fixture.install
  %w[bash zsh fish].each do |shell|
    expected = "completion for #{shell}\n"
    abort "missing or incorrect #{shell} completion" unless fixture.completions[shell] == expected
  end
end
RUBY

missing_checksums="${tmp_dir}/missing.txt"
grep -v 'darwin-arm64' "${checksums}" > "${missing_checksums}"
assert_fails_with "expected exactly one checksum for tunnel-client-v1.2.3-darwin-arm64.zip, found 0" \
  "${GENERATOR}" --tag v1.2.3 --checksums "${missing_checksums}" --output "${formula}"

duplicate_checksums="${tmp_dir}/duplicate.txt"
cp "${checksums}" "${duplicate_checksums}"
printf '%s\n' 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  tunnel-client-v1.2.3-linux-amd64.zip' >> "${duplicate_checksums}"
assert_fails_with "expected exactly one checksum for tunnel-client-v1.2.3-linux-amd64.zip, found 2" \
  "${GENERATOR}" --tag v1.2.3 --checksums "${duplicate_checksums}" --output "${formula}"

invalid_checksums="${tmp_dir}/invalid.txt"
sed 's/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc/not-a-digest/' \
  "${checksums}" > "${invalid_checksums}"
assert_fails_with "checksum for tunnel-client-v1.2.3-linux-amd64.zip is not a lowercase SHA-256 digest" \
  "${GENERATOR}" --tag v1.2.3 --checksums "${invalid_checksums}" --output "${formula}"

assert_fails_with "prerelease tags do not produce a Homebrew formula" \
  "${GENERATOR}" --tag v1.2.3-rc.1 --checksums "${checksums}" --output "${formula}"

prerelease_checksums="${tmp_dir}/prerelease-SHA256SUMS.txt"
sed 's/v1\.2\.3/v1.2.3-rc.1/g' "${checksums}" > "${prerelease_checksums}"
"${GENERATOR}" \
  --tag v1.2.3-rc.1 \
  --checksums "${prerelease_checksums}" \
  --output "${formula}" \
  --allow-prerelease
generated_prerelease="$(<"${formula}")"
assert_contains "${generated_prerelease}" 'version "1.2.3-rc.1"'
assert_contains "${generated_prerelease}" 'url "https://persistent.oaistatic.com/tunnel-client/v#{version}/tunnel-client-v#{version}-darwin-arm64.zip"'
