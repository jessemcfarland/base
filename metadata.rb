name 'base'
maintainer 'Jesse McFarland'
maintainer_email 'jesse@mcfarland.sh'
license 'MIT'
description 'Installs/Configures base'
long_description 'Installs/Configures base'
version '0.2.0'
chef_version '>= 12.1' if respond_to?(:chef_version)
issues_url 'https://github.com/jessemcfarland/base/issues'
source_url 'https://github.com/jessemcfarland/base'
supports 'centos'

depends 'yum-epel', '~> 2.1.2'
