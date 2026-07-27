# platformd — Linux-first platform-authentication components, built as systemd
# would build them (libsystemd + meson). `platformd` is a placeholder for
# `systemd`: the rename test is `s/platformd/systemd/`.
project('platformd', 'c',
        version : '0.1.2',
        license : 'LGPL-2.1-or-later',
        meson_version : '>= 1.1',
        default_options : [
                'c_std=gnu11',
                'warning_level=2',
        ])

# systemd builds with _GNU_SOURCE and does not treat unused function parameters
# as errors (Varlink method handlers take a fixed signature).
add_project_arguments('-D_GNU_SOURCE', '-Wno-unused-parameter', language : 'c')

libsystemd = dependency('libsystemd', version : '>= 257')

subdir('src/verify')
subdir('man')

# --- installed integration: the systemd system unit
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

# The PAM stack that names the presence factors, installed to the vendor PAM
# directory (the administrator overrides it under /etc/pam.d/ if desired). PAM's
# search path is fixed at /usr/lib/pam.d, so derive it from systemd's prefix.
pam_vendor_dir = systemd.found() ? systemd.get_variable(pkgconfig : 'prefix') / 'lib/pam.d' : get_option('prefix') / 'lib/pam.d'
install_data('pam/platformd-verify', install_dir : pam_vendor_dir)
