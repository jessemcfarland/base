#
# Cookbook:: base
# Spec:: default
#
require 'spec_helper'

shared_examples 'base_test' do |platform, metadata|
  context "when run on #{platform} #{metadata['version']}" do
    let(:chef_run) do
      runner = ChefSpec::ServerRunner.new(platform: platform, version: metadata['version'])
      runner.converge(described_recipe)
    end

    it 'converges successfully' do
      expect { chef_run }.to_not raise_error
    end

    it 'installs packages' do
      expect(chef_run).to install_package metadata['packages']
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
  end
end

describe 'base::default' do
  platforms = {
    'centos' => {
      'version' => '7.3.1611',
      'packages' => %w(bzip2 curl findutils gawk gnupg2 gzip iproute lsof
                       net-tools sed tar tcpdump tmux traceroute unzip
                       vim-enhanced wget xz zip zsh)
    }
  }

  platforms.each do |platform, metadata|
    include_examples 'base_test', platform, metadata
  end
end
