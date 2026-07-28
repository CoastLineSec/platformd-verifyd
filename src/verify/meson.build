# platformd-verifyd user-presence verification service.

cc = meson.get_compiler('c')
libpam = cc.find_library('pam')

verifyd = executable(
        'platformd-verifyd',
        'verifyd.c',
        'verify-util.c',
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

# Tests.
test_conversation = executable(
        'test-conversation',
        'test-conversation.c',
        'verify-util.c',
        dependencies : [libsystemd, libpam],
)
test('conversation', test_conversation)
test('smoke', find_program('sh'),
     args : [
             meson.current_source_dir() / 'test-smoke.sh',
             verifyd,
             verifyctl,
             meson.current_source_dir() / 'testdata',
     ],
     timeout : 60)
