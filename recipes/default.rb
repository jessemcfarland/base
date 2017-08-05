#
# Cookbook:: base
# Recipe:: default
#
include_recipe 'ntp::default'
include_recipe 'openssh::default'
include_recipe 'xinetd::builtin_services'

case node['platform_family']
when 'rhel'
  yum_globalconfig '/etc/yum.conf' do
    gpgcheck true
  end

  include_recipe 'yum-epel::default'

  packages = %w(bzip2 curl findutils gawk gnupg2 gzip iproute lsof net-tools sed
                tar tcpdump tmux traceroute unzip vim-enhanced wget xz zip zsh)

  remove_packages = %w(mcstrans openldap-clients prelink rsh setroubleshoot talk
                       telnet)

  disable_services = %w(avahi-daemon cups dhcp dovecot httpd named ntalk
                        rexec.socket rlogin.socket rsh.socket rsyncd slapd smb
                        snmpd squid telnet.socket tftp.socket vsftpd xinetd
                        ypserv)
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

include_recipe 'postfix::default'

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
grub_defaults = '/etc/default/grub'

execute 'grub2-mkconfig' do
  action :nothing
  command "grub2-mkconfig -o #{grub_config}"
end

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

include_recipe 'sysctl::default'

# Prevent setuid programs from dumping core
sysctl_param 'fs.suid_dumpable' do
  value 0
end

# Enable ASLR
sysctl_param 'kernel.randomize_va_space' do
  value 2
end

# Ensure IP forwarding is disabled
sysctl_param 'net.ipv4.ip_forward' do
  value 0
end

# Ensure broadcast ICMP requests are ignored
sysctl_param 'net.ipv4.icmp_echo_ignore_broadcasts' do
  value 1
end

# Ensure bogus ICMP responses are ignored
sysctl_param 'net.ipv4.icmp_ignore_bogus_error_responses' do
  value 1
end

# Ensure TCP SYN cookies is enabled
sysctl_param 'net.ipv4.tcp_syncookies' do
  value 1
end

net_ipv4_conf_params = {
  'send_redirects' => 0, # Ensure packet redirect sending is disabled
  'accept_source_route' => 0, # Ensure source routed packets are not accepted
  'accept_redirects' => 0, # Ensure ICMP redirects are not accepted
  'secure_redirects' => 0, # Ensure secure ICMP redirects are not accepted
  'log_martians' => 1, # Ensure suspicious packets are logged
  'rp_filter' => 1 # Ensure reverse path filtering is enabled
}

net_ipv4_conf_params.each do |param, value|
  sysctl_param "net.ipv4.conf.all.#{param}" do
    value value
  end

  sysctl_param "net.ipv4.conf.default.#{param}" do
    value value
  end
end

net_ipv6_conf_params = {
  'accept_ra' => 0, # Ensure IPv6 router advertisements are not accepted
  'accept_redirects' => 0, # Ensure IPv6 redirects are not accepted
  'disable_ipv6' => 1 # Ensure IPv6 is disabled
}

net_ipv6_conf_params.each do |param, value|
  sysctl_param "net.ipv6.conf.all.#{param}" do
    value value
  end

  sysctl_param "net.ipv6.conf.default.#{param}" do
    value value
  end
end

cookbook_file '/etc/modprobe.d/ipv6.conf' do
  action :create
  owner 'root'
  group 'root'
  mode '0644'
  source 'modprobe.d-ipv6.conf'
end

ruby_block 'disable ipv6 on kernel boot command' do
  block do
    grub_cmdline_linux_value = ''
    grub_cmdline_linux_regex = /^GRUB_CMDLINE_LINUX="(.*)"$/
    File.open(grub_defaults).each do |line|
      if line =~ grub_cmdline_linux_regex
        grub_cmdline_linux_value = grub_cmdline_linux_regex.match(line)[1]
      end
    end
    a = grub_cmdline_linux_value.split
    unless a.include?('ipv6.disable=1')
      a.push('ipv6.disable=1')
    end
    grub_cmdline_linux_value = a.join(' ')
    grub_cmdline_linux = "GRUB_CMDLINE_LINUX=\"#{grub_cmdline_linux_value}\""
    f = Chef::Util::FileEdit.new(grub_defaults)
    f.search_file_replace_line(grub_cmdline_linux_regex, grub_cmdline_linux)
    f.write_file
  end
  notifies :run, 'execute[grub2-mkconfig]', :immediately
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
