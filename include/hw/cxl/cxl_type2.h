/*
 * CXL Type 2 Device (Accelerator with Coherent Memory) Header
 * Designed for GPU passthrough with CPU-GPU coherency
 *
 * Supports two GPU backends:
 * 1. VFIO passthrough - Direct hardware access
 * 2. hetGPU - Software CUDA translation layer for any GPU
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CXL_TYPE2_H
#define CXL_TYPE2_H

#include "hw/pci/pci_device.h"
#include "hw/cxl/cxl_device.h"
#include "hw/cxl/cxl_component.h"
#include "hw/cxl/cxl_hetgpu.h"
#include "hw/cxl/cxl_type2_coherency.h"
#include "hw/cxl/cxl_p2p_dma.h"
#include "qemu/thread.h"
#include "io/channel-socket.h"

#define TYPE_CXL_TYPE2 "cxl-type2"
#define CXL_TYPE2_VENDOR_ID 0x8086
#define CXL_TYPE2_DEVICE_ID 0x0d92

/* Type 2 combines Type 1 (accelerator/cache) + Type 3 (memory) */
#define CXL_TYPE2_DEFAULT_CACHE_SIZE (128 * MiB)
#define CXL_TYPE2_DEFAULT_MEM_SIZE (4 * GiB)
#define CXL_TYPE2_DCD_DEFAULT_GRANULARITY (1 * MiB)
#define CXL_TYPE2_DCD_INIT_AUTO UINT64_MAX
#define CXL_TYPE2_MAX_DCD_EXTENTS 64
#define CXL_TYPE2_MAX_GFAM_HOSTS 16
#define CXL_TYPE2_MAX_GFAM_MAPPINGS 128
#define CXL_TYPE2_MAX_MHSLD_LINES 4096

/* Coherency states for cache lines */
typedef enum {
    CXL_COHERENCY_INVALID = 0,
    CXL_COHERENCY_SHARED = 1,
    CXL_COHERENCY_EXCLUSIVE = 2,
    CXL_COHERENCY_MODIFIED = 3,
} CXLCoherencyState;

/* Cache line metadata for coherency tracking */
typedef struct CXLCacheLine {
    uint64_t tag;
    CXLCoherencyState state;
    bool dirty;
    uint8_t data[64];  /* Standard cache line size */
    uint64_t timestamp;
} CXLCacheLine;

/* GPU backend mode */
typedef enum {
    CXL_TYPE2_GPU_MODE_NONE = 0,    /* No GPU backend */
    CXL_TYPE2_GPU_MODE_VFIO = 1,    /* VFIO passthrough */
    CXL_TYPE2_GPU_MODE_HETGPU = 2,  /* hetGPU software translation */
    CXL_TYPE2_GPU_MODE_AUTO = 3,    /* Auto-detect best backend */
} CXLType2GPUMode;

/* GPU passthrough information */
typedef struct CXLType2GPUInfo {
    char *vfio_device;      /* VFIO device path (e.g., "0000:01:00.0") */
    bool passthrough_enabled;
    uint64_t gpu_mem_base;
    uint64_t gpu_mem_size;
    void *vfio_container;
    void *vfio_group;
    int vfio_device_fd;
    QemuThread irq_thread;  /* IRQ forwarding thread */
    bool irq_thread_running;

    /* hetGPU backend support */
    uint32_t mode;                  /* GPU backend mode (CXLType2GPUMode) */
    char *hetgpu_lib_path;          /* Path to hetGPU library */
    HetGPUState hetgpu_state;       /* hetGPU backend state */
    int32_t hetgpu_device_index;    /* hetGPU device index */
    uint32_t hetgpu_backend;        /* hetGPU backend type (HetGPUBackendType) */
} CXLType2GPUInfo;

/* Coherency protocol state */
typedef struct CXLType2CoherencyState {
    QemuMutex lock;
    GHashTable *cache_lines;  /* Maps address -> CXLCacheLine */
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t coherency_ops;
    uint64_t snoops;
    bool coherency_enabled;
} CXLType2CoherencyState;

/* CXLMemSim connection for coherency protocol */
typedef struct CXLType2MemSimConn {
    QIOChannelSocket *socket;
    char *server_addr;
    uint16_t server_port;
    QemuThread recv_thread;
    bool connected;
    QemuMutex lock;

    /* Shared memory mode support */
    bool use_shm;
    void *shm_base;
    size_t shm_size;
    char *shm_name;
} CXLType2MemSimConn;

/* Free block for coherent pool allocator */
typedef struct CXLCohFreeBlock {
    uint64_t offset;            /* Offset within BAR4 */
    uint64_t size;
    struct CXLCohFreeBlock *next;
} CXLCohFreeBlock;

/* Dynamic Capacity Device extent state for Type2 CXL.mem BAR4 */
typedef struct CXLType2DCDExtent {
    uint64_t base;
    uint64_t size;
    uint64_t tag;
    bool active;
} CXLType2DCDExtent;

typedef struct CXLType2DCDState {
    bool enabled;
    uint64_t granularity;
    uint64_t initial_size;
    uint64_t allocated;
    uint64_t next_tag;
    uint64_t add_requests;
    uint64_t release_requests;
    uint64_t failed_requests;
    CXLType2DCDExtent extents[CXL_TYPE2_MAX_DCD_EXTENTS];
    QemuMutex lock;
} CXLType2DCDState;

typedef struct CXLType2GFAMMapping {
    uint32_t host_id;
    uint32_t permissions;
    uint64_t base;
    uint64_t size;
    bool active;
} CXLType2GFAMMapping;

typedef struct CXLType2GFAMState {
    bool enabled;
    uint32_t local_host_id;
    uint32_t num_hosts;
    uint32_t default_permissions;
    uint32_t fabric_latency_ns;
    uint32_t bandwidth_mbps;
    uint64_t allowed_accesses;
    uint64_t denied_accesses;
    uint64_t total_latency_ns;
    CXLType2GFAMMapping mappings[CXL_TYPE2_MAX_GFAM_MAPPINGS];
    QemuMutex lock;
} CXLType2GFAMState;

typedef struct CXLType2MHSLDLine {
    uint64_t line_addr;
    uint32_t owner_head;
    uint32_t sharer_mask;
    bool valid;
    bool modified;
} CXLType2MHSLDLine;

typedef struct CXLType2MHSLDState {
    bool enabled;
    uint32_t num_heads;
    uint32_t local_head_id;
    uint32_t coherency_latency_ns;
    uint64_t reads;
    uint64_t writes;
    uint64_t atomics;
    uint64_t conflicts;
    uint64_t invalidations;
    CXLType2MHSLDLine lines[CXL_TYPE2_MAX_MHSLD_LINES];
    QemuMutex lock;
} CXLType2MHSLDState;

/* Main Type 2 device state */
typedef struct CXLType2State {
    PCIDevice parent_obj;

    /* CXL component and device states */
    CXLComponentState cxl_cstate;
    CXLDeviceState cxl_dstate;

    /* Memory regions */
    MemoryRegion bar0;                 /* Component registers */
    MemoryRegion cache_mem;            /* Type 1: Cache for coherent access */
    MemoryRegion cache_io;             /* Cache access interceptor */
    MemoryRegion device_mem;           /* Type 3: Device-attached memory */
    MemoryRegion device_mem_io;        /* Device memory interceptor */
    MemoryRegion gpu_cmd_region;       /* GPU command registers */

    /* GPU command state */
    struct {
        uint32_t status;
        uint32_t cmd_status;
        uint32_t cmd_result;
        uint64_t params[8];
        uint64_t results[4];
        uint8_t  *data;                /* Data buffer - dynamically allocated (1MB) */
        size_t   data_size;            /* Size of data buffer */
        void    *modules[64];          /* Loaded PTX modules */
        void    *functions[256];       /* Kernel function handles */
        uint32_t num_modules;
        uint32_t num_functions;
        uint32_t capabilities;         /* Device capabilities (bulk transfer, etc.) */
    } gpu_cmd;

    /* Bulk transfer region for large memory operations */
    MemoryRegion bulk_transfer_region;
    void *bulk_transfer_ptr;           /* Mapped pointer for bulk transfers */
    size_t bulk_transfer_size;

    /* Device configuration */
    uint64_t cache_size;
    uint64_t device_mem_size;
    bool direct_shared_mem;              /* Map memdev directly into BAR4 */
    uint64_t sn;                       /* Serial number */

    PCIExpLinkSpeed speed;
    PCIExpLinkWidth width;
    bool flitmode;
    bool hdmdb;
    bool bi_enabled;

    /* Fabric memory feature models */
    CXLType2DCDState dcd;
    CXLType2GFAMState gfam;
    CXLType2MHSLDState mhsld;

    /* GPU passthrough */
    CXLType2GPUInfo gpu_info;

    /* Coherency protocol */
    CXLType2CoherencyState coherency;

    /* Enhanced BAR coherency tracking */
    CXLBARCoherencyState bar_coherency;

    /* P2P DMA engine for Type2 <-> Type3 transfers */
    CXLP2PDMAEngine p2p_engine;

    /* CXLMemSim connection */
    CXLType2MemSimConn memsim;

    /* Memory backend for device memory */
    HostMemoryBackend *hostmem;

    /* Coherent shared memory pool (carved from top of BAR4) */
    struct {
        uint64_t base_offset;       /* device_mem_size - pool_size */
        uint64_t size;              /* Configurable, default 256MB */
        uint64_t used;
        GHashTable *allocations;    /* bar4_offset -> alloc_size */
        struct CXLCohFreeBlock *free_list;
        QemuMutex lock;
    } coherent_pool;

    /* Opt-in SlugArch native endpoint experiment. */
    bool slugarch_enabled, slugarch_enforce;
    uint32_t slugarch_compute_ns, slugarch_record_ns;
    uint32_t slugarch_bandwidth, slugarch_link_ns;
    struct CXLSlugArchState *slugarch;

    /* Statistics and monitoring */
    struct {
        uint64_t read_ops;
        uint64_t write_ops;
        uint64_t gpu_accesses;
        uint64_t cpu_accesses;
        uint64_t coherency_violations;
    } stats;

    /* Latency simulation and modeled-timing accounting, calibrated against
     * the C2 Sight CXL Type-2 characterization (paper.pdf; see
     * calibration/c2sight_type2 in the CXLMemSim tree).
     *   read_latency_ns      device-cache hit rail (paper HMC hit, 120ns)
     *   write_latency_ns     HDM media write rail (derived host->HDM, 250ns)
     *   coherency_latency_ns H2D notification/snoop round trip and the
     *                        miss-fill CXL.mem cost (derived 45+22+45, 112ns)
     *   bandwidth_gbps       serialized CXL link ceiling (paper 51 GB/s) */
    bool latency_enabled;
    uint32_t read_latency_ns;
    uint32_t write_latency_ns;
    uint32_t coherency_latency_ns;
    uint32_t bandwidth_gbps;
    /* DCOH allocation backpressure: device-cache fills serialize at one
     * install per hmc_install_ns (C2 Sight: 7.9ns -> 8.1 GB/s fill ceiling,
     * the 6.2x allocating-vs-non-allocating gap).  allocate_on_miss off
     * models non-allocating requests (RdCurr class): no fill, no install. */
    uint32_t hmc_install_ns;
    bool allocate_on_miss;

    /* Cumulative modeled device time in ns; reported via TIMING_GET. */
    struct {
        uint64_t acc_ns;
        uint64_t hit_count;
        uint64_t hit_ns;
        uint64_t miss_count;
        uint64_t miss_ns;
        uint64_t write_count;
        uint64_t write_ns;
        uint64_t notify_count;
        uint64_t notify_batch_count;
        uint64_t notify_ns;
        uint64_t notify_completion_ns;
        uint64_t bulk_read_ns;   /* device-directed consume (DTOH) */
        uint64_t bulk_write_ns;  /* device-directed push (HTOD) */
        uint64_t install_count;
        uint64_t install_ns;
    } timing;

} CXLType2State;

#define CXL_TYPE2(obj) OBJECT_CHECK(CXLType2State, (obj), TYPE_CXL_TYPE2)

/* Message types for CXLMemSim communication */
enum CXLType2MsgType {
    CXL_T2_MSG_READ = 1,
    CXL_T2_MSG_WRITE = 2,
    CXL_T2_MSG_CACHE_FLUSH = 3,
    CXL_T2_MSG_COHERENCY_REQ = 4,
    CXL_T2_MSG_SNOOP_REQ = 5,
    CXL_T2_MSG_SNOOP_RESP = 6,
    CXL_T2_MSG_INVALIDATE = 7,
    CXL_T2_MSG_WRITEBACK = 8,
    CXL_T2_MSG_GPU_ACCESS = 9,
    CXL_T2_MSG_RESPONSE = 10,
};

/* Message structure for CXLMemSim protocol */
typedef struct CXLType2Message {
    uint32_t type;
    uint32_t size;
    uint64_t addr;
    uint64_t timestamp;
    uint8_t coherency_state;
    uint8_t source_id;
    uint8_t data[64];
} CXLType2Message;

/* Coherency protocol functions */
void cxl_type2_coherency_init(CXLType2State *ct2d);
void cxl_type2_coherency_cleanup(CXLType2State *ct2d);
CXLCacheLine *cxl_type2_cache_lookup(CXLType2State *ct2d, uint64_t addr);
void cxl_type2_cache_insert(CXLType2State *ct2d, uint64_t addr,
                            const uint8_t *data, CXLCoherencyState state);
void cxl_type2_cache_invalidate(CXLType2State *ct2d, uint64_t addr);
void cxl_type2_cache_writeback(CXLType2State *ct2d, uint64_t addr);
bool cxl_type2_snoop_request(CXLType2State *ct2d, uint64_t addr, bool invalidate);

/* GPU passthrough functions */
int cxl_type2_gpu_init(CXLType2State *ct2d, Error **errp);
void cxl_type2_gpu_cleanup(CXLType2State *ct2d);
int cxl_type2_gpu_read(CXLType2State *ct2d, uint64_t offset, void *buf, size_t size);
int cxl_type2_gpu_write(CXLType2State *ct2d, uint64_t offset, const void *buf, size_t size);

/* hetGPU backend functions */
int cxl_type2_hetgpu_init(CXLType2State *ct2d, Error **errp);
void cxl_type2_hetgpu_cleanup(CXLType2State *ct2d);
int cxl_type2_hetgpu_load_ptx(CXLType2State *ct2d, const char *ptx_source,
                               void **module);
int cxl_type2_hetgpu_launch_kernel(CXLType2State *ct2d, void *function,
                                    uint32_t grid_x, uint32_t grid_y, uint32_t grid_z,
                                    uint32_t block_x, uint32_t block_y, uint32_t block_z,
                                    uint32_t shared_mem, void **args, size_t num_args);
int cxl_type2_hetgpu_malloc(CXLType2State *ct2d, size_t size, uint64_t *dev_ptr);
int cxl_type2_hetgpu_free(CXLType2State *ct2d, uint64_t dev_ptr);
int cxl_type2_hetgpu_memcpy_htod(CXLType2State *ct2d, uint64_t dst, const void *src, size_t size);
int cxl_type2_hetgpu_memcpy_dtoh(CXLType2State *ct2d, void *dst, uint64_t src, size_t size);
int cxl_type2_hetgpu_sync(CXLType2State *ct2d);

#endif /* CXL_TYPE2_H */
