# encoding: utf-8

# Inspec test for recipe base::default

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/
#
case os[:family]
when 'redhat'
  describe parse_config_file('/etc/yum.conf').params('main') do
    its('gpgcheck') { should eq '1' }
  end

  describe yum.repo 'epel'  do
    it { should exist }
    it { should be_enabled }
  end

  packages = %w(bzip2 curl findutils gawk gnupg2 gzip iproute lsof net-tools sed
                tar tcpdump tmux traceroute unzip vim-enhanced wget xz zip zsh)

  remove_packages = %w(mcstrans openldap-clients prelink rsh setroubleshoot talk
                       telnet)

  disable_services = %w(avahi-daemon cups dhcp dovecot httpd named ntalk
                        rexec.socket rlogin.socket rsh.socket rsyncd slapd smb
                        snmpd squid telnet.socket tftp.socket vsftpd xinetd
                        ypserv)
end

packages.each do |pkg|
  describe package pkg do
    it { should be_installed }
  end
end

remove_packages.each do |pkg|
  describe package pkg do
    it { should_not be_installed }
  end
end

disable_services.each do |svc|
  describe service svc do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

describe parse_config_file '/etc/postfix/main.cf' do
  its('inet_interfaces') { should match /loopback-only|localhost/ }
end

describe port 25 do
  it { should be_listening }
  its('addresses') { should cmp ['127.0.0.1', '::1'] }
  its('processes') { should cmp 'master' }
  its('protocols') { should cmp ['tcp', 'tcp6'] }
end

describe file '/etc/modprobe.d/fs.conf' do
  it { should be_file }
  it { should be_owned_by 'root' }
  it { should be_grouped_into 'root' }
  its('mode') { should cmp '0644' }
end

filesystems = %w(cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat)
filesystems.each do |fs|
  describe file '/etc/modprobe.d/fs.conf' do
    its('content') { should include "install #{fs} /bin/true" }
  end
end

describe directory '/tmp' do
  it { should be_directory }
  it { should be_owned_by 'root' }
  it { should be_grouped_into 'root' }
  its('mode') { should cmp '1023' }
end

grub_dir = '/boot/grub2'
grub_config = "#{grub_dir}/grub.cfg"
grub_user_config = "#{grub_dir}/user.cfg"

describe parse_config_file '/etc/default/grub' do
  its('GRUB_CMDLINE_LINUX') { should_not include 'selinux=0' }
  its('GRUB_CMDLINE_LINUX') { should_not include 'enforcing=0' }
  its('GRUB_CMDLINE_LINUX') { should include 'ipv6.disable=1' }
end

describe file grub_config do
  it { should be_file }
  it { should be_owned_by 'root' }
  it { should be_grouped_into 'root' }
  its('mode') { should cmp '0600' }
  its('content') { should_not match /^\s*linux.*selinux=0/ }
  its('content') { should_not match /^\s*linux.*enforcing=0/ }
end

describe file grub_user_config do
  it { should be_file }
  it { should be_owned_by 'root' }
  it { should be_grouped_into 'root' }
  its('mode') { should cmp '0600' }
  its('content') { should include 'GRUB2_PASSWORD=' }
end

describe limits_conf '/etc/security/limits.conf' do
  its('*') { should include ['hard', 'core', '0'] }
end

describe kernel_parameter 'fs.suid_dumpable' do
  its('value') { should cmp 0 }
end

describe kernel_parameter 'kernel.randomize_va_space' do
  its('value') { should cmp 2 }
end

describe kernel_parameter 'net.ipv4.ip_forward' do
  its('value') { should cmp 0 }
end

describe kernel_parameter 'net.ipv4.icmp_echo_ignore_broadcasts' do
  its('value') { should cmp 1 }
end

describe kernel_parameter 'net.ipv4.icmp_ignore_bogus_error_responses' do
  its('value') { should cmp 1 }
end

describe kernel_parameter 'net.ipv4.tcp_syncookies' do
  its('value') { should cmp 1 }
end

net_ipv4_conf_params = {
  'send_redirects' => 0,
  'accept_source_route' => 0,
  'accept_redirects' => 0,
  'secure_redirects' => 0,
  'log_martians' => 1,
  'rp_filter' => 1
}

net_ipv4_conf_params.each do |param, value|
  describe kernel_parameter "net.ipv4.conf.all.#{param}" do
    its('value') { should cmp value }
  end

  describe kernel_parameter "net.ipv4.conf.default.#{param}" do
    its('value') { should cmp value }
  end
end

net_ipv6_conf_params = {
  'accept_ra' => 0,
  'accept_redirects' => 0,
  'disable_ipv6' => 1
}

net_ipv6_conf_params.each do |param, value|
  describe kernel_parameter "net.ipv6.conf.all.#{param}" do
    its('value') { should cmp value }
  end

  describe kernel_parameter "net.ipv6.conf.default.#{param}" do
    its('value') { should cmp value }
  end
end

describe file '/etc/modprobe.d/ipv6.conf' do
  it { should be_file }
  it { should be_owned_by 'root' }
  it { should be_grouped_into 'root' }
  its('mode') { should cmp '0644' }
  its('content') { should include 'options ipv6 disable=1' }
end

describe package 'libselinux' do
  it { should be_installed }
end

describe parse_config_file '/etc/selinux/config' do
  its('SELINUX') { should eq 'enforcing' }
  its('SELINUXTYPE') { should eq 'targeted' }
end

describe command 'sestatus' do
  its('stdout') { should match /Loaded policy name:\s+targeted/ }
  its('stdout') { should match /Current mode:\s+enforcing/ }
end

describe processes /.*/ do
  its('labels') { should_not match /initrc/ }
end

banner = <<EOF
********************************************************************
*                                                                  *
* This system is for the use of authorized users only. Usage of    *
* this system may be monitored and recorded by system personnel.   *
*                                                                  *
* Anyone using this system expressly consents to such monitoring   *
* and is advised that if such monitoring reveals possible          *
* evidence of criminal activity, system personnel may provide the  *
* evidence from such monitoring to law enforcement officials.      *
*                                                                  *
********************************************************************
EOF
banner_files = %w(/etc/motd /etc/issue /etc/issue.net)
banner_files.each do |file|
  describe file file do
    it { should be_file }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    its('mode') { should cmp 0644 }
    its('content') { should eq banner }
    its('content') { should_not match /'(\\v|\\r|\\m|\\s)/ }
  end
end

builtin_xinetd_services = %w(chargen daytime discard echo time)
builtin_xinetd_services.each do |svc|
  describe xinetd_conf "#{svc}-dgram" do
    it { should be_disabled }
  end

  describe xinetd_conf "#{svc}-stream" do
    it { should be_disabled }
  end
end

describe xinetd_conf 'tcpmux-server' do
  it { should be_disabled }
end

describe package 'ntp' do
  it { should be_installed }
end

ntp_conf_restrict_options = 'default kod notrap nomodify nopeer noquery'

describe ntp_conf '/etc/ntp.conf' do
  its('server') { should_not eq nil }
  its('restrict') { should include ntp_conf_restrict_options }
end

describe.one do
  describe parse_config_file '/etc/sysconfig/ntpd' do
    its('OPTIONS') { should include '-u ntp:ntp' }
  end

  ntp_service = '/usr/lib/systemd/system/ntpd.service'
  describe parse_config_file(ntp_service).params('Service') do
    its('ExecStart') { should include '-u ntp:ntp' }
  end
end

describe service 'sshd' do
  it { should be_enabled }
  it { should be_installed }
  it { should be_running }
end

describe port 22 do
  it { should be_listening }
  its('processes') { should cmp 'sshd' }
  its('protocols') { should cmp 'tcp' }
end

sshd_config_ciphers = 'aes256-gcm@openssh.com,aes128-gcm@openssh.com,'\
  'aes256-ctr,aes192-ctr,aes128-ctr'
sshd_config_macs = 'hmac-sha2-512-etm@openssh.com,'\
  'hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,'\
  'hmac-sha2-256,umac-128@openssh.com'
sshd_config_kex_algorithms = 'curve25519-sha256@libssh.org,ecdh-sha2-nistp521,'\
    'ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256'
describe sshd_config '/etc/ssh/sshd_config' do
  its('Port') { should cmp 22 }
  its('Protocol') { should cmp 2 }
  its('AddressFamily') { should eq 'inet' }
  its('UsePAM') { should eq 'yes' }
  its('MaxAuthTries') { should cmp 3 }
  its('ClientAliveInterval') { should cmp 300 }
  its('ClientAliveCountMax') { should cmp 0 }
  its('PermitRootLogin') { should eq 'no' }
  its('IgnoreRhosts') { should eq 'yes' }
  its('HostbasedAuthentication') { should eq 'no' }
  its('PubkeyAuthentication') { should eq 'yes' }
  its('PasswordAuthentication') { should eq 'yes' }
  its('PrintMotd') { should eq 'yes' }
  its('PrintLastLog') { should eq 'yes' }
  its('X11Forwarding') { should eq 'no' }
  its('StrictModes') { should eq 'yes' }
  its('PermitEmptyPasswords') { should eq 'no' }
  its('UsePrivilegeSeparation') { should eq 'yes' }
  its('UseDNS') { should eq 'yes' }
  its('Ciphers') { should eq sshd_config_ciphers }
  its('MACs') { should eq sshd_config_macs }
  its('KexAlgorithms') { should eq sshd_config_kex_algorithms }
  its('LogLevel') { should eq 'INFO' }
  its('SyslogFacility') { should eq 'AUTHPRIV' }
end
