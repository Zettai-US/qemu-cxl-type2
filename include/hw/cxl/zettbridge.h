/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HW_CXL_ZETTBRIDGE_H
#define HW_CXL_ZETTBRIDGE_H
#include "hw/pci/pci_device.h"
#define TYPE_ZETTBRIDGE "zettbridge"
OBJECT_DECLARE_SIMPLE_TYPE(ZettBridge, ZETTBRIDGE)
MemTxResult zettbridge_access(ZettBridge *s, uint64_t dpa, void *buf,
                              unsigned size, bool write);
bool zettbridge_is_consumer(ZettBridge *s, uint64_t capacity);
void zettbridge_set_hdm(ZettBridge *s, uint64_t base, uint64_t size);
#endif
