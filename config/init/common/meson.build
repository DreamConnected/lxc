# SPDX-License-Identifier: LGPL-2.1+

lxc_containers = configure_file(
    configuration: conf,
    input: 'lxc-containers.in',
    output: 'lxc-containers',
    install: true,
    install_dir: lxclibexec)

lxc_net = configure_file(
    configuration: conf,
    input: 'lxc-net.in',
    output: 'lxc-net',
    install: true,
    install_dir: lxclibexec)

if want_android_network
    lxc_net_android = configure_file(
        configuration: conf,
        input: 'lxc-net-android.in',
        output: 'lxc-net-android',
        install: true,
        install_dir: lxclibexec)
endif
