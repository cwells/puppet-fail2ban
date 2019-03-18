# == Class: fail2ban::service
#
class fail2ban::service {
  if $::fail2ban::service_name {
    service { 'fail2ban':
      name       => $::fail2ban::service_name,
      ensure     => $::fail2ban::service_ensure,
      enable     => $::fail2ban::service_enable,
      hasrestart => true,
    }
  }
}
