default['openssh']['server'] = {
  'port': '22',
  'protocol': '2',
  'addressfamily': 'inet',
  'use_pam': 'yes',
  'max_auth_tries': '3',
  'client_alive_interval': '300',
  'client_alive_count_max': '0',
  'permit_root_login': 'no',
  'ignore_rhosts': 'yes',
  'hostbased_authentication': 'no',
  'pubkey_authentication': 'yes',
  'password_authentication': 'yes',
  'print_motd': 'yes',
  'print_last_log': 'yes',
  'x11_forwarding': 'no',
  'strict_modes': 'yes',
  'permit_empty_passwords': 'no',
  'use_privilege_separation': 'yes',
  'use_dns': 'yes',
  'ciphers': 'aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,'\
    'aes192-ctr,aes128-ctr',
  'macs': 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,'\
    'umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com',
  'kex_algorithms': 'curve25519-sha256@libssh.org,ecdh-sha2-nistp521,'\
    'ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256',
  'log_level': 'INFO',
  'syslog_facility': 'AUTHPRIV'
}
default['openssh']['server']['match'] = {}

default['selinux']['selinuxtype'] = 'targeted'

default['xinetd']['builtin_services']['chargen-stream']['enabled'] = false
default['xinetd']['builtin_services']['chargen-dgram']['enabled'] = false
default['xinetd']['builtin_services']['daytime-stream']['enabled'] = false
default['xinetd']['builtin_services']['daytime-dgram']['enabled'] = false
default['xinetd']['builtin_services']['discard-stream']['enabled'] = false
default['xinetd']['builtin_services']['discard-dgram']['enabled'] = false
default['xinetd']['builtin_services']['echo-stream']['enabled'] = false
default['xinetd']['builtin_services']['echo-dgram']['enabled'] = false
default['xinetd']['builtin_services']['time-stream']['enabled'] = false
default['xinetd']['builtin_services']['time-dgram']['enabled'] = false
default['xinetd']['builtin_services']['tcpmux-server']['enabled'] = false

default['ntp']['servers'] = %w(0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org
                               3.pool.ntp.org)

default['postfix']['main']['inet_interfaces'] = 'loopback-only'
