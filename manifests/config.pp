# == Class: fail2ban::config
#
class fail2ban::config {
  # Load custom jails/actions definition
  $config_custom_jails = hiera_hash('fail2ban::custom_jails', {})
  $config_custom_actions = hiera_hash('fail2ban::custom_actions', {})

  file { 'fail2ban.dir':
    ensure  => directory,
    path    => $::fail2ban::config_dir_path,
    force   => $::fail2ban::config_dir_purge,
    purge   => $::fail2ban::config_dir_purge,
    recurse => $::fail2ban::config_dir_recurse,
    source  => $::fail2ban::config_dir_source,
    notify  => $::fail2ban::config_file_notify,
    require => $::fail2ban::config_file_require,
  }

  if $::fail2ban::config_file_path {
    file { 'fail2ban.conf':
      ensure  => file,
      path    => $::fail2ban::config_file_path,
      owner   => $::fail2ban::config_file_owner,
      group   => $::fail2ban::config_file_group,
      mode    => $::fail2ban::config_file_mode,
      source  => $::fail2ban::config_file_source,
      content => $::fail2ban::config_file_content,
      notify  => $::fail2ban::config_file_notify,
      require => $::fail2ban::config_file_require,
    }
  }

  create_resources('fail2ban::jail', $config_custom_jails)
  create_resources('fail2ban::action', $config_custom_actions)

  # Operating system specific configuration
  case $facts['os']['family'] {
    'RedHat': {
      # Not using firewalld by now
      file { '00-firewalld.conf':
        ensure  => 'absent',
        path    => "${::fail2ban::config_dir_path}/jail.d/00-firewalld.conf",
        notify  => $::fail2ban::config_file_notify,
        require => $::fail2ban::config_file_require,
      }
    }
    'Debian': {
      # Remove debian defaults conf
      file { 'defaults-debian.conf':
        ensure  => absent,
        path    => "${fail2ban::config_dir_path}/jail.d/defaults-debian.conf",
        require => $fail2ban::config_file_require,
      }
    }
    default: {
      fail("${facts['os']['family']} not supported.")
    }
  }
}
