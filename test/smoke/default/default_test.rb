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
end

packages.each do |pkg|
  describe package pkg do
    it { should be_installed }
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
