# Man pages, authored in DocBook XML and rendered with xsltproc against the
# DocBook manpages stylesheet — the same toolchain systemd uses. Requires
# docbook-xsl (the stylesheet) and xsltproc; skipped if xsltproc is absent.

xsltproc = find_program('xsltproc', required : false)

if xsltproc.found()
        # [stem, manvolnum, [alias pages generated from extra <refname>s]]
        manpages = [
                ['verifyctl', '1', []],
                ['platformd-verifyd.service', '8', ['platformd-verifyd.8']],
        ]

        xsltproc_flags = [
                '--nonet',
                '--xinclude',
                '--stringparam', 'man.output.quietly', '1',
                '--stringparam', 'man.authors.section.enabled', '0',
                '--stringparam', 'man.copyright.section.enabled', '0',
        ]
        manpages_stylesheet = 'http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl'

        foreach page : manpages
                stem = page[0]
                section = page[1]
                custom_target(
                        stem + '.' + section,
                        input : stem + '.xml',
                        output : [stem + '.' + section] + page[2],
                        command : [xsltproc, xsltproc_flags, '-o', '@OUTPUT0@', manpages_stylesheet, '@INPUT@'],
                        install : true,
                        install_dir : get_option('mandir') / ('man' + section),
                )
        endforeach
else
        warning('xsltproc not found; man pages will not be built.')
endif
