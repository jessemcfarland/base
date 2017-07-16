#
# Cookbook:: base
# Recipe:: default
#
include_recipe 'openssh::default'
include_recipe 'yum-epel::default'

package node['base']['packages']
