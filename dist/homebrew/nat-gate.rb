class NatGate < Formula
  desc "CLI tool for iptables port forwarding through Tailscale tunnels"
  homepage "https://github.com/h3nr1-d14z/nat-gate"
  url "https://github.com/h3nr1-d14z/nat-gate/archive/refs/tags/v1.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "MIT"
  head "https://github.com/h3nr1-d14z/nat-gate.git", branch: "main"

  depends_on "rust" => :build
  depends_on :linux

  def install
    system "cargo", "install", *std_cargo_args

    # Install shell completions
    generate_completions_from_executable(bin/"nat-gate", "completions")

    # Install systemd service file
    (lib/"systemd/system").install "dist/nat-gate.service"
  end

  def post_install
    ohai "nat-gate has been installed!"
    ohai ""
    ohai "To enable the systemd service:"
    ohai "  sudo systemctl enable nat-gate"
    ohai "  sudo systemctl start nat-gate"
    ohai ""
    ohai "Or use the built-in service management:"
    ohai "  sudo nat-gate service install"
  end

  test do
    assert_match "nat-gate", shell_output("#{bin}/nat-gate --version")
    assert_match "Usage:", shell_output("#{bin}/nat-gate --help")
  end
end
