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
  end
end

describe 'base::default' do
  platforms = {
    'centos' => {
      'version' => '7.3.1611',
      'packages' => %w(bzip2 curl findutils gawk gnupg2 gzip iproute lsof
                       net-tools sed tar tcpdump tmux traceroute unzip
                       vim-enhanced wget xz zip zsh),
      'remove_packages' => %w(mcstrans prelink setroubleshoot),
      'disable_services' => ['xinetd']
    }
  }

  platforms.each do |platform, metadata|
    include_examples 'base_test', platform, metadata
  end
end
