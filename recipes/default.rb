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
end

package node['base']['packages']
