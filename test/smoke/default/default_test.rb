# encoding: utf-8

# Inspec test for recipe base::default

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/
#
case os[:family]
when 'redhat'
  packages = %w(
    bzip2
    curl
    findutils
    gawk
    gnupg2
    gzip
    iproute
    lsof
    net-tools
    sed
    tar
    tcpdump
    tmux
    traceroute
    unzip
    vim-enhanced
    wget
    xz
    zip
    zsh
  )
end

packages.each do |pkg|
  describe package pkg do
    it { should be_installed }
  end
end
