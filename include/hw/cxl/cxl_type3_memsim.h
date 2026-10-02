/*
 * Experimental CXLMemSim Type-3 atomic command BAR ABI.
 *
 * This interface is intentionally separate from the CXL fixed memory window.
 * KVM_EXIT_MMIO does not preserve enough information for QEMU to distinguish
 * a guest LOCK XADD/CMPXCHG from an ordinary read followed by a write.
 */
#ifndef HW_CXL_TYPE3_MEMSIM_H
#define HW_CXL_TYPE3_MEMSIM_H

#define CXL_T3_MEMSIM_ATOMIC_BAR_IDX 5
#define CXL_T3_MEMSIM_ATOMIC_BAR_SIZE 0x1000

#define CXL_T3_MEMSIM_ATOMIC_MAGIC 0x54415843U /* "CXAT" */
#define CXL_T3_MEMSIM_ATOMIC_VERSION 1U

#define CXL_T3_MEMSIM_REG_MAGIC 0x00
#define CXL_T3_MEMSIM_REG_VERSION 0x04
#define CXL_T3_MEMSIM_REG_CAPS 0x08
#define CXL_T3_MEMSIM_REG_STATUS 0x0c
#define CXL_T3_MEMSIM_REG_OP 0x10
#define CXL_T3_MEMSIM_REG_SERVER_STATUS 0x14
#define CXL_T3_MEMSIM_REG_ADDR 0x18
#define CXL_T3_MEMSIM_REG_VALUE 0x20
#define CXL_T3_MEMSIM_REG_EXPECTED 0x28
#define CXL_T3_MEMSIM_REG_OLD_VALUE 0x30
#define CXL_T3_MEMSIM_REG_DOORBELL 0x38

#define CXL_T3_MEMSIM_CAP_FAA (1U << 0)
#define CXL_T3_MEMSIM_CAP_CAS (1U << 1)
#define CXL_T3_MEMSIM_CAP_FENCE (1U << 2)

#define CXL_T3_MEMSIM_STATUS_IDLE 0U
#define CXL_T3_MEMSIM_STATUS_BUSY 1U
#define CXL_T3_MEMSIM_STATUS_DONE 2U
#define CXL_T3_MEMSIM_STATUS_ERROR 3U

/* Match the existing CXLMemSim wire protocol operation numbers. */
#define CXL_T3_MEMSIM_OP_NONE 0U
#define CXL_T3_MEMSIM_OP_FAA 3U
#define CXL_T3_MEMSIM_OP_CAS 4U
#define CXL_T3_MEMSIM_OP_FENCE 5U

#define CXL_T3_MEMSIM_SERVER_STATUS_TRANSPORT_ERROR UINT32_MAX

#endif /* HW_CXL_TYPE3_MEMSIM_H */
