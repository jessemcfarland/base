#
# Cookbook:: base
# Recipe:: default
#
include_recipe 'openssh::default'

case node['platform_family']
when 'rhel'
  yum_globalconfig '/etc/yum.conf' do
    gpgcheck true
  end

  include_recipe 'yum-epel::default'

  packages = %w(bzip2 curl findutils gawk gnupg2 gzip iproute lsof net-tools sed
                tar tcpdump tmux traceroute unzip vim-enhanced wget xz zip zsh)
end

package packages
