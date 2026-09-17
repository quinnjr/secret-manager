# Verify `docs/install-debian.md` on a real Debian machine.
#
# The Debian instructions were written from packaging and reasoning rather
# than from a Debian box; this exists so they are checked rather than
# believed. `make vagrant-verify` follows the documented steps verbatim and
# then proves the result works: a daemon on a session bus, a vault, a secret
# stored and read back, `secret-tool` interop, and the PAM module where the
# docs say it lands.
#
#   make vagrant-verify           # provision and verify; see Makefile for why
#                                 # this and not a bare `vagrant up`
#   vagrant provision --provision-with verify   # re-run just the checks
#   vagrant ssh                   # poke at it
#   vagrant destroy -f            # done
#
# See docs/vagrant.md.

Vagrant.configure("2") do |config|
  # Debian 12. Deliberately the oldest supported stable rather than testing:
  # if the documented steps work here they work on the newer ones, and this
  # is where an old toolchain or a missing package shows up.
  config.vm.box = "debian/bookworm64"
  config.vm.hostname = "secret-manager-debian"

  # No forwarded ports and no public network. The daemon is a session-bus
  # service; nothing here should be reachable from outside the VM.
  config.vm.network "private_network", type: "dhcp"

  config.vm.provider "virtualbox" do |vb|
    vb.name = "secret-manager-debian"
    vb.memory = 4096
    vb.cpus = 4
    # A release build of this crate is not small.
    vb.customize ["modifyvm", :id, "--audio-driver", "none"]
  end

  # rsync rather than the default shared folder: the box has no guest
  # additions, and `target/` must not cross into the VM — it holds host
  # artifacts for a different toolchain and would be both enormous and wrong.
  config.vm.synced_folder ".", "/home/vagrant/secret-manager",
    type: "rsync",
    rsync__exclude: [
      ".git/", "target/", "fuzz/target/", ".worktrees/",
      "*.vault", "aliases.toml",
    ],
    rsync__args: ["--verbose", "--archive", "--delete", "-z", "--copy-links"]

  config.vm.provision "deps",    type: "shell", path: "vagrant/provision.sh"
  config.vm.provision "build",   type: "shell", path: "vagrant/build.sh",
    privileged: false
  config.vm.provision "verify",  type: "shell", path: "vagrant/verify.sh",
    privileged: false
end
