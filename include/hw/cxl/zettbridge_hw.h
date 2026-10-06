/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ZETTBRIDGE_HW_H
#define ZETTBRIDGE_HW_H
/* Frozen Zettai RPU v0.2 ABI. All BAR/wire values are little endian. */
#define ZB_VENDOR 0x1b36
#define ZB_PROVIDER_DEVICE 0x10f0
#define ZB_CONSUMER_DEVICE 0x10f1
#define ZB_ID_VERSION 0x5a520002
#define ZB_BAR_SIZE 0x4000
#define ZB_MAX_EXTENTS 65536
#define ZB_ALIGN 4096
#define ZB_CAPS 0x1f
#define ZB_ID 0x0000
#define ZB_CAP 0x0008
#define ZB_STATUS 0x0010
#define ZB_CONTROL 0x0018
#define ZB_EPOCH 0x0020
#define ZB_EXPORTED 0x0028
#define ZB_TABLE_BASE 0x0030
#define ZB_TABLE_COUNT 0x0038
#define ZB_COMMIT 0x0040
#define ZB_FAULT 0x0048
#define ZB_STAGED_EPOCH 0x0050
#define ZB_CMD_SEQ 0x0058
#define ZB_ACK_SEQ 0x0060
#define ZB_ACK_STATUS 0x0068
#define ZB_SNAPSHOT_SEQ 0x0070
#define ZB_MAX 0x0078
#define ZB_MIN_ALIGN 0x0080
#define ZB_USAGE_PUBLISH 0x0090
#define ZB_USAGE_SELECT 0x0098
#define ZB_QUERY_TARGET 0x00a0
#define ZB_QUERY_EPOCH 0x00a8
#define ZB_QUERY_SEQ 0x00b0
#define ZB_QUERY_DOORBELL 0x00b8
#define ZB_QUERY_ACK 0x00c0
#define ZB_ACK_EPOCH 0x00c8
#define ZB_INVENTORY 0x1000
#define ZB_QUERY_RESULT 0x1100
#define ZB_USAGE 0x2000
/* QEMU platform extension, identified independently; not standard CXL ABI. */
#define ZB_MODEL 0x02f0
#define ZB_MODEL_V1 0x5a424d01
#define ZB_SESSION_LO 0x0300
#define ZB_SESSION_HI 0x0308
#define ZB_ATTACH_SIZE 0x0310
#define ZB_ATTACHED 0x0318
#define ZB_REVOKE_REQUEST 0x0320
#define ZB_RANGE_START 0x0330
#define ZB_RANGE_LENGTH 0x0338
#define ZB_TIER0_BYTES 0x0340
#define ZB_TIER1_BYTES 0x0348
#define ZB_HDM_BASE 0x0350
#define ZB_HDM_SIZE 0x0358
#define ZB_CAPACITY 0x0360 /* read-only configured aperture, before publication */
/* ATS status bits: 0 configured, 1 enabled, 2 invalidation notifier live. */
#define ZB_ATS_STATUS 0x0368
#define ZB_ATS_REQUESTS 0x0370
#define ZB_ATS_HITS 0x0378
#define ZB_ATS_INVALIDATIONS 0x0380
#define ZB_ATS_ENTRIES 0x0388
#define ZB_ATS_FLUSHES 0x0390
#define ZB_ATS_FAULTS 0x0398
#define ZB_ATS_TRANSITIONS 0x03a0
#define ZB_ATS_TEST_VALUE 0x03a8 /* read-only synchronous TEST_ATS result */
#define ZB_ENABLE 1
#define ZB_QUIESCE 2
#define ZB_DRAIN 3
#define ZB_RETIRE 4
#define ZB_SNAPSHOT 6
#define ZB_LEASE_BARRIER 7
#define ZB_READ_USAGE 8
#define ZB_ATTACH 0x100
#define ZB_DETACH 0x101
#define ZB_TEST_DMA 0x102
#define ZB_ZERO_RANGE 0x103
#define ZB_REQUEST_REVOKE 0x104
#define ZB_TEST_ATS 0x105
#define ZB_OK 0
#define ZB_BUSY 1
#define ZB_BAD_ABI 2
#define ZB_BAD_TABLE 3
#define ZB_BAD_EPOCH 4
#define ZB_NOT_QUIESCED 5
#define ZB_DMA_FAULT 6
#define ZB_TIMEOUT 7
#define ZB_DENIED 8
#define ZB_EXTENT_SIZE 64
#define ZB_USAGE_SIZE 128
#define ZB_COMMIT_OP 0x200
#define ZB_PUBLISH_OP 0x201
#endif
