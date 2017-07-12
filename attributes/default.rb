case node['platform']
when 'centos'
  default['base']['packages'] = %w(
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
