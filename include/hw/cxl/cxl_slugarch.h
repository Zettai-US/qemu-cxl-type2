/* SlugArch opt-in endpoint experiment. SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CXL_SLUGARCH_H
#define CXL_SLUGARCH_H

#define SLUGARCH_MMIO_BASE 0x200000
#define SLUGARCH_MMIO_SIZE 0x21000

typedef struct CXLType2State CXLType2State;
void cxl_slugarch_init(CXLType2State *d);
void cxl_slugarch_cleanup(CXLType2State *d);
uint64_t cxl_slugarch_read(CXLType2State *d, hwaddr addr, unsigned size);
void cxl_slugarch_write(CXLType2State *d, hwaddr addr, uint64_t v, unsigned size);
#endif
