# platformd Linux platform-authentication components.
project('platformd', 'c',
        version : '0.1.4',
        license : 'LGPL-2.1-or-later',
        meson_version : '>= 1.1',
        default_options : [
                'c_std=gnu11',
                'warning_level=2',
        ])

# systemd builds with _GNU_SOURCE and does not treat unused function parameters
# as errors (Varlink method handlers take a fixed signature).
add_project_arguments('-D_GNU_SOURCE', '-Wno-unused-parameter',
                      '-DPROGRAM_VERSION="@0@"'.format(meson.project_version()), language : 'c')

libsystemd = dependency('libsystemd', version : '>= 258')

subdir('src/verify')
subdir('man')

# Install the system unit.
conf = configuration_data()
conf.set('LIBEXECDIR', get_option('prefix') / get_option('libexecdir'))

systemd = dependency('systemd', required : false)
systemd_system_unit_dir = systemd.found() ? systemd.get_variable(pkgconfig : 'systemdsystemunitdir') : get_option('prefix') / 'lib/systemd/system'
configure_file(
        input : 'units/platformd-verifyd.service.in',
        output : 'platformd-verifyd.service',
        configuration : conf,
        install : true,
        install_dir : systemd_system_unit_dir,
)

pam_vendor_dir = get_option('pamvendordir')
if pam_vendor_dir == ''
        pam = dependency('pam', required : false)
        pam_vendor_dir = pam.found() ? pam.get_variable(pkgconfig : 'vendordir', default_value : '') : ''
        if pam_vendor_dir == ''
                pam_vendor_dir = get_option('prefix') / 'lib/pam.d'
        endif
endif
install_data('pam/platformd-verify', install_dir : pam_vendor_dir)
install_data('src/verify/io.platformd.Verify.varlink', install_dir : get_option('datadir') / 'varlink')
