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

# Disable unused filesystems
cookbook_file '/etc/modprobe.d/fs.conf' do
  action :create
  owner 'root'
  group 'root'
  mode '0644'
  source 'modprobe.d-fs.conf'
end

# Ensure sticky bit is set on /tmp
directory '/tmp' do
  action :create
  owner 'root'
  group 'root'
  mode '1777'
end
