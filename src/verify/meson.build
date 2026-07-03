# platformd-verifyd — user-presence verification service.
# (Sources live in src/verify/, as systemd keeps src/login/, src/home/, etc.)

cc = meson.get_compiler('c')
libpam = cc.find_library('pam')

verifyd = executable(
        'platformd-verifyd',
        'verifyd.c',
        dependencies : [libsystemd, libpam],
        install : true,
        install_dir : get_option('libexecdir'),
)

verifyctl = executable(
        'verifyctl',
        'verifyctl.c',
        dependencies : libsystemd,
        install : true,
)

# --- tests (meson test) ---
test('smoke', find_program('sh'),
     args : [meson.current_source_dir() / 'test-smoke.sh', verifyd, verifyctl],
     timeout : 60)
