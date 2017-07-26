#
# Cookbook:: base
# Recipe:: default
#
include_recipe 'openssh::default'
include_recipe 'sysctl::default'
include_recipe 'xinetd::builtin_services'

case node['platform_family']
when 'rhel'
  yum_globalconfig '/etc/yum.conf' do
    gpgcheck true
  end

  include_recipe 'yum-epel::default'

  packages = %w(bzip2 curl findutils gawk gnupg2 gzip iproute lsof net-tools sed
                tar tcpdump tmux traceroute unzip vim-enhanced wget xz zip zsh)

  remove_packages = %w(mcstrans prelink setroubleshoot)

  disable_services = ['xinetd']
end

package packages

package remove_packages do
  action :remove
end

disable_services.each do |svc|
  service svc do
    action [:disable, :stop]
  end
end

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

grub_dir = '/boot/grub2'
grub_config = "#{grub_dir}/grub.cfg"
grub_user_config = "#{grub_dir}/user.cfg"

# Ensure grub permissions are correct
file grub_config do
  action :create
  owner 'root'
  group 'root'
  mode '0600'
end

# Set grub password
grub2_secrets = data_bag_item('secrets', 'grub2')
grub2_password = grub2_secrets['password_pbkdf2']
file grub_user_config do
  action :create
  owner 'root'
  group 'root'
  mode '0600'
  content "GRUB2_PASSWORD=#{grub2_password}"
end

# Restrict core dumps
set_limit '*' do
  type 'hard'
  item 'core'
  value 0
  use_system true
end

# Prevent setuid programs from dumping core
sysctl_param 'fs.suid_dumpable' do
  value 0
end

# Enable ASLR
sysctl_param 'kernel.randomize_va_space' do
  value 2
end

# Set SELinux to enforcing in targeted mode
selinux_state 'SELinux Enforcing' do
  action :enforcing
end

# Configure banner
banner_files = %w(/etc/motd /etc/issue /etc/issue.net)
banner_files.each do |file|
  cookbook_file file do
    action :create
    owner 'root'
    group 'root'
    mode '0644'
    source 'banner'
  end
end
