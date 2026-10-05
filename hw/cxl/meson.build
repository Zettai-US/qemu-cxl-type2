system_ss.add(when: 'CONFIG_CXL',
               if_true: files(
                   'cxl-component-utils.c',
                   'zettbridge.c',
                   'cxl-device-utils.c',
                   'cxl-mailbox-utils.c',
                   'cxl-host.c',
                   'cxl-cdat.c',
                   'cxl-events.c',
                   'switch-mailbox-cci.c',
                   'cxl-vcs-switch.c',
                   'cxl_type1.c',
                   'cxl_type2.c',
                   'cxl_slugarch.c',
                   'cxl_type2_coherency.c',
                   'cxl_p2p_dma.c',
                   'cxl_hetgpu.c',
                   'cxl-vcs-switch.c'
               ),
               if_false: files(
                   'cxl-host-stubs.c',
               ))
