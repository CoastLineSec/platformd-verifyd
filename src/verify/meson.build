# platformd-verifyd user-presence verification service.

cc = meson.get_compiler('c')
libpam = cc.find_library('pam')

verifyd = executable(
        'platformd-verifyd',
        'verifyd.c',
        'verify-util.c',
        'verify-worker.c',
        dependencies : [libsystemd, libpam],
        install : true,
        install_dir : get_option('libexecdir'),
)

verifyd_test = executable(
        'platformd-verifyd-test',
        'verifyd.c',
        'verify-util.c',
        'verify-worker.c',
        c_args : ['-DVERIFYD_TESTING'],
        dependencies : [libsystemd, libpam],
)

verifyctl = executable(
        'verifyctl',
        'verifyctl.c',
        dependencies : libsystemd,
        install : true,
)

# Tests.
test_deadline = executable(
        'test-deadline',
        'test-deadline.c',
        'verify-util.c',
        'verify-worker.c',
        dependencies : [libsystemd, libpam],
        link_args : ['-Wl,--wrap=sd_varlink_reply', '-Wl,--wrap=sd_varlink_error', '-Wl,--wrap=sd_journal_send'],
)
test('deadline', find_program('sh'),
     args : [meson.current_source_dir() / 'test-env.sh', test_deadline])

test_logind = executable(
        'test-logind',
        'test-logind.c', 'verify-util.c', 'verify-worker.c',
        dependencies : [libsystemd, libpam],
        link_args : ['-Wl,--wrap=sd_varlink_reply', '-Wl,--wrap=sd_varlink_error', '-Wl,--wrap=sd_journal_send'],
)
test('logind', find_program('sh'),
     args : [meson.current_source_dir() / 'test-logind.sh', test_logind])

test_session_selection = executable(
        'test-session-selection',
        'test-session-selection.c', 'verify-util.c', 'verify-worker.c',
        dependencies : [libsystemd, libpam],
        link_args : ['-Wl,--wrap=sd_varlink_reply', '-Wl,--wrap=sd_varlink_error', '-Wl,--wrap=sd_journal_send'],
)
test('session-selection', find_program('sh'),
     args : [meson.current_source_dir() / 'test-logind.sh', test_session_selection])

test_conversation = executable(
        'test-conversation',
        'test-conversation.c',
        'verify-util.c',
        dependencies : [libsystemd, libpam],
)
test('conversation', find_program('sh'),
     args : [
             meson.current_source_dir() / 'test-env.sh',
             test_conversation,
     ])

test_pam_result_module = shared_module(
        'test-pam-result-module',
        'test-pam-result-module.c',
        dependencies : libpam,
        name_prefix : '',
)
test_pam_result = executable(
        'test-pam-result',
        'test-pam-result.c',
        'verify-util.c',
        'verify-worker.c',
        dependencies : [libsystemd, libpam],
)
test('pam-result', find_program('sh'),
     args : [
             meson.current_source_dir() / 'test-env.sh',
             test_pam_result,
             test_pam_result_module,
     ],
     timeout : 60)

test_response_erasure = executable(
        'test-response-erasure',
        'test-response-erasure.c',
        'verify-util.c',
        dependencies : [libsystemd, libpam, cc.find_library('dl')],
        link_args : ['-Wl,--wrap=sd_varlink_call', '-Wl,--wrap=strdup'],
)
test('response-erasure', find_program('sh'),
     args : [meson.current_source_dir() / 'test-env.sh', test_response_erasure],
     timeout : 30)

test_worker = executable('test-worker', 'test-worker.c', 'verify-worker.c',
        link_args : ['-Wl,--wrap=close_range'])
test('worker', find_program('sh'),
     args : [meson.current_source_dir() / 'test-env.sh', test_worker],
     timeout : 60)

test_worker_lifecycle_module = shared_module(
        'test-worker-lifecycle-module',
        'test-worker-lifecycle-module.c',
        dependencies : libpam,
        name_prefix : '',
)
test_worker_lifecycle = executable(
        'test-worker-lifecycle',
        'test-worker-lifecycle.c',
        dependencies : libsystemd,
)
test('worker-lifecycle', find_program('sh'),
     args : [
             meson.current_source_dir() / 'test-worker-lifecycle.sh',
             test_worker_lifecycle,
             verifyd_test,
             test_worker_lifecycle_module,
     ],
     timeout : 60)

test_worker_exec = executable(
        'test-worker-exec',
        'test-worker-exec.c',
        'verify-util.c',
        'verify-worker.c',
        c_args : ['-DVERIFYD_TESTING'],
        dependencies : [libsystemd, libpam, cc.find_library('dl')],
)
test_worker_exec_module = shared_module(
        'test-worker-exec-module',
        'test-worker-exec-module.c',
        dependencies : [libsystemd, libpam],
        name_prefix : '',
)
test('worker-exec', find_program('sh'),
     args : [
             meson.current_source_dir() / 'test-worker-exec.sh',
             test_worker_exec,
             test_worker_exec_module,
             verifyctl,
     ],
     timeout : 30)

test('environment', find_program('sh'),
     args : [
             meson.current_source_dir() / 'test-env-regression.sh',
             verifyd_test,
             verifyctl,
             meson.current_source_dir() / 'testdata',
     ],
     timeout : 60)
test('smoke', find_program('sh'),
     args : [
             meson.current_source_dir() / 'test-smoke.sh',
             verifyd_test,
             verifyctl,
             meson.current_source_dir() / 'testdata',
     ],
     timeout : 60)
