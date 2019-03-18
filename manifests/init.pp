# == Class: fail2ban
#
type Ensured      = Enum['absent', 'latest', 'present', 'purged']
type ServiceState = Enum['running', 'stopped']
type PackageList  = Optional[Array[String]]
type AbsPath      = Stdlib::Absolutepath
type Config       = Hash[String, Variant[String, Numeric]]
type JailConfigs  = Hash[String, Config]
type IPList       = Array[Stdlib::IP::Address]

class fail2ban (
  AbsPath               $config_dir_path          = $::fail2ban::params::config_dir_path,
  AbsPath               $config_dir_filter_path   = $::fail2ban::params::config_dir_filter_path,
  Boolean               $config_dir_purge         = false,
  Boolean               $config_dir_recurse       = true,
  Optional[String]      $config_dir_source        = undef,

  AbsPath               $config_file_path         = $::fail2ban::params::config_file_path,
  String                $config_file_owner        = $::fail2ban::params::config_file_owner,
  String                $config_file_group        = $::fail2ban::params::config_file_group,
  String                $config_file_mode         = $::fail2ban::params::config_file_mode,
  String                $config_file_before       = $::fail2ban::params::before_file,
  Optional[String]      $config_file_source       = undef,
  Optional[String]      $config_file_string       = undef,
  Optional[String]      $config_file_template     = "fail2ban/${facts['os']['distro']['id']}/${split($facts['os']['distro']['release']['major'], '\.')[0]}/etc/fail2ban/jail.conf.epp",
  String                $config_file_notify       = $::fail2ban::params::config_file_notify,
  String                $config_file_require      = $::fail2ban::params::config_file_require,
  Config                $config_file_hash         = {},
  Hash                  $config_file_options_hash = {},

  ServiceState          $service_ensure           = 'running',
  String                $service_name             = $::fail2ban::params::service_name,
  Boolean               $service_enable           = true,

  String                $action                   = 'action_mb',
  Integer[0]            $bantime                  = 432000,
  String                $email                    = "fail2ban@${::domain}",
  String                $sender                   = "fail2ban@${::fqdn}",
  String                $iptables_chain           = 'INPUT',
  Array[String]         $jails                    = ['ssh', 'ssh-ddos'],
  Integer[0]            $maxretry                 = 3,
  Array                 $whitelist                = ['127.0.0.1/8', '192.168.56.0/24'],
  Optional[JailConfigs] $custom_jails             = undef,
  String                $banaction                = 'iptables-multiport'

) inherits ::fail2ban::params {

  case $facts['os']['family'] {
    /Debian|RedHat/: {}
    default: { fail("${::operatingsystem} not supported.") }
  }

  $config_file_content = default_content($config_file_string, $config_file_template)

  create_resources('fail2ban::define', $config_file_hash)

  if $package_ensure == 'absent' {
    $config_dir_ensure  = 'directory'
    $config_file_ensure = 'present'
    $_service_ensure    = 'stopped'
    $_service_enable    = false
  }

  elsif $package_ensure == 'purged' {
    $config_dir_ensure  = 'absent'
    $config_file_ensure = 'absent'
    $_service_ensure    = 'stopped'
    $_service_enable    = false
  }

  else {
    $config_dir_ensure  = 'directory'
    $config_file_ensure = 'present'
    $_service_ensure    = $service_ensure
    $_service_enable    = $service_enable
  }

  anchor { 'fail2ban::begin': }
  -> class { '::fail2ban::config': }
  ~> class { '::fail2ban::service': }
  -> anchor { 'fail2ban::end': }
}
