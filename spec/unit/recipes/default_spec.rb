#
# Cookbook:: base
# Spec:: default
#
require 'spec_helper'

grub2_password = 'fakegrub2password'

shared_examples 'base_test' do |platform, metadata|
  context "when run on #{platform} #{metadata['version']}" do
    let(:chef_run) do
      runner = ChefSpec::ServerRunner.new(platform: platform, version: metadata['version'])
      runner.create_data_bag('secrets', {
        'grub2' => {'password_pbkdf2' => grub2_password}
      })
      runner.converge(described_recipe)
    end

    it 'converges successfully' do
      expect { chef_run }.to_not raise_error
    end

    it 'includes recipe ntp::default' do
      expect(chef_run).to include_recipe('ntp::default')
    end

    it 'includes recipe openssh::default' do
      expect(chef_run).to include_recipe('openssh::default')
    end

    before do
      stub_command('/usr/bin/test /etc/alternatives/mta -ef /usr/sbin/sendmail.postfix').and_return(true)
    end

    it 'includes recipe postfix::default' do
      expect(chef_run).to include_recipe('postfix::default')
    end

    it 'includes recipe sysctl::default' do
      expect(chef_run).to include_recipe('sysctl::default')
    end

    it 'includes recipe xinetd::builtin_services' do
      expect(chef_run).to include_recipe('xinetd::builtin_services')
    end

    it 'includes recipe yum-epel::default' do
      expect(chef_run).to include_recipe('yum-epel::default')
    end

    it 'installs packages' do
      expect(chef_run).to install_package metadata['packages']
    end

    it 'removes packages' do
      expect(chef_run).to remove_package metadata['remove_packages']
    end

    metadata['disable_services'].each do |svc|
      it "disables #{svc} service" do
        expect(chef_run).to disable_service svc
      end

      it "stops #{svc} service" do
        expect(chef_run).to stop_service svc
      end
    end

    it 'creates /etc/modprobe.d/fs.conf with the correct permissions' do
      expect(chef_run).to create_cookbook_file('/etc/modprobe.d/fs.conf').with(
        user: 'root',
        group: 'root',
        mode: '0644'
      )
    end

    it 'creates /tmp directory with correct permissions' do
      expect(chef_run).to create_directory('/tmp').with(
        user: 'root',
        group: 'root',
        mode: '1777'
      )
    end

    grub_dir = '/boot/grub2'
    grub_config = "#{grub_dir}/grub.cfg"
    grub_user_config = "#{grub_dir}/user.cfg"

    it "sets the correct permissions for #{grub_config}" do
      expect(chef_run).to create_file(grub_config).with(
        user: 'root',
        group: 'root',
        mode: '0600'
      )
    end

    it "creates #{grub_user_config} with the correct permissions and content" do
      expect(chef_run).to create_file(grub_user_config).with(
        user: 'root',
        group: 'root',
        mode: '0600',
        content: "GRUB2_PASSWORD=#{grub2_password}"
      )
    end

    banner_files = %w(/etc/motd /etc/issue /etc/issue.net)
    banner_files.each do |file|
      it "creates #{file} with the correct permissions" do
        expect(chef_run).to create_cookbook_file(file).with(
          user: 'root',
          group: 'root',
          mode: '0644'
        )
      end
    end

    it 'creates /etc/modprobe.d/ipv6.conf with the correct permissions and content' do
      expect(chef_run).to create_cookbook_file('/etc/modprobe.d/ipv6.conf').with(
        user: 'root',
        group: 'root',
        mode: '0644'
      )
    end

    it 'disables ipv6 on the kernel boot command' do
      expect(chef_run).to run_ruby_block('disable ipv6 on kernel boot command')
    end
  end
end

describe 'base::default' do
  platforms = {
    'centos' => {
      'version' => '7.3.1611',
      'packages' => %w(bzip2 curl findutils gawk gnupg2 gzip iproute lsof
                       net-tools sed tar tcpdump tmux traceroute unzip
                       vim-enhanced wget xz zip zsh),
      'remove_packages' => %w(mcstrans openldap-clients prelink rsh
                              setroubleshoot talk telnet),
      'disable_services' => %w(avahi-daemon cups dhcp dovecot httpd named ntalk
                               rexec.socket rlogin.socket rsh.socket rsyncd
                               slapd smb snmpd squid telnet.socket tftp.socket
                               vsftpd xinetd ypserv)
    }
  }

  platforms.each do |platform, metadata|
    include_examples 'base_test', platform, metadata
  end
end
