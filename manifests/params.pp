# == Class: fail2ban::params
#
class fail2ban::params {
  $config_dir_path = '/etc/fail2ban'
  $config_dir_filter_path = "${config_dir_path}/filter.d"
  $config_file_path = "${config_dir_path}/jail.conf"
  $config_file_owner = 'root'
  $config_file_group = 'root'
  $config_file_mode = '0644'
  $config_file_notify = 'Service[fail2ban]'
  $config_file_require = 'Package[fail2ban]'
  $service_name = 'fail2ban'

  $before_file = $facts['os']['family'] ? {
    'Debian' => 'paths-debian.conf',
    'RedHat' => 'paths-fedora.conf'
  }
}
