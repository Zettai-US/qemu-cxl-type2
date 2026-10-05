/*
 * Zettai RPU v0.2, two independent QEMU requester domains.
 * The provider's BQL serializes table switching, DMA, both control banks and
 * barriers. Each completed pci_dma_write is globally visible in this model;
 * this is a functional model, not a PCIe posted-write timing simulation.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/cutils.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "qemu/bswap.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "hw/qdev-properties.h"
#include "hw/pci/pci.h"
#include "hw/pci/pcie.h"
#include "hw/cxl/zettbridge.h"
#include "hw/cxl/zettbridge_hw.h"
#include "migration/vmstate.h"

/* Fixed local IPC wire protocol; no pointers, host addresses or shared RAM. */
typedef struct ZBPacket {
    uint32_t magic, op, size, status;
    uint64_t addr, value;
    uint8_t data[64];
} ZBPacket;
G_STATIC_ASSERT(sizeof(ZBPacket) == 96);

typedef struct ZBBank {
    uint8_t reg[ZB_BAR_SIZE];
    uint32_t last_seq, last_status;
    uint64_t last_epoch;
} ZBBank;

typedef struct ZBExtent {
    uint64_t dpa, length, dma;
    uint16_t tier;
} ZBExtent;

struct ZettBridge {
    PCIDevice parent_obj;
    MemoryRegion bar;
    bool provider;
    char *socket_path;
    uint64_t capacity;
    uint32_t timeout_ms;
    uint32_t drop_ack_op; /* deterministic completion-loss injection */
    bool query_unknown;
    int listener, peer;
    bool realized;
    ZBBank banks[2]; /* B=0, A=1, separate staging/completion/query banks */
    ZBExtent *extents;
    uint32_t count;
    uint64_t epoch, exported, snapshot_seq;
    uint64_t session_lo, session_hi;
    uint64_t tier_bytes[2];
    uint64_t hdm_base, hdm_size;
    uint8_t usage[2][128];
    bool usage_present[2];
    bool attached, ever_attached, revoke, drained;
    uint32_t state, fault;
};

static uint64_t reg64(ZBBank *b, unsigned off)
{
    return ldq_le_p(b->reg + off);
}

static void fault(ZettBridge *s, unsigned code)
{
    if (!s->fault) {
        s->fault = code;
    }
    s->state = 6;
}

static uint32_t table_fetch(ZettBridge *s, ZBBank *b, ZBExtent **out,
                            uint32_t *out_count)
{
    uint64_t base = reg64(b, ZB_TABLE_BASE);
    uint64_t count = reg64(b, ZB_TABLE_COUNT);
    uint64_t epoch = reg64(b, ZB_STAGED_EPOCH), end = 0;
    ZBExtent *table;
    if (!count || count > ZB_MAX_EXTENTS || (base & 63) ||
        base > UINT64_MAX - count * 64 || !epoch || epoch <= s->epoch) {
        return ZB_BAD_TABLE;
    }
    table = g_new0(ZBExtent, count);
    for (uint32_t i = 0; i < count; i++) {
        uint8_t raw[64];
        uint64_t dpa, len, dma;
        if (pci_dma_read(PCI_DEVICE(s), base + i * 64, raw, 64)) {
            g_free(table);
            return ZB_DMA_FAULT;
        }
        dpa = ldq_le_p(raw);
        len = ldq_le_p(raw + 8);
        dma = ldq_le_p(raw + 16);
        if (dpa != end || !len || ((dpa | len | dma) & (ZB_ALIGN - 1)) ||
            len > UINT64_MAX - dpa || len > UINT64_MAX - dma ||
            ldq_le_p(raw + 24) != epoch || ldl_le_p(raw + 36) != 7 ||
            lduw_le_p(raw + 40) > 1 || !buffer_is_zero(raw + 42, 22)) {
            g_free(table);
            return ZB_BAD_TABLE;
        }
        table[i] = (ZBExtent){dpa, len, dma, lduw_le_p(raw + 40)};
        end = dpa + len;
    }
    if (end != s->capacity) {
        g_free(table);
        return ZB_BAD_TABLE;
    }
    *out = table;
    *out_count = count;
    return ZB_OK;
}

static uint32_t dma_range(ZettBridge *s, uint64_t dpa, uint8_t *buf,
                          unsigned size, bool write, bool zero)
{
    if (!size || dpa >= s->exported || size > s->exported - dpa) {
        return ZB_BAD_TABLE;
    }
    while (size) {
        ZBExtent *e = NULL;
        /* A binary search keeps page-granular tables usable. */
        uint32_t lo = 0, hi = s->count;
        while (lo < hi) {
            uint32_t mid = lo + (hi - lo) / 2;
            if (s->extents[mid].dpa <= dpa) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if (lo) {
            e = &s->extents[lo - 1];
        }
        if (!e || dpa - e->dpa >= e->length) {
            return ZB_BAD_TABLE;
        }
        unsigned n = MIN(size, e->length - (dpa - e->dpa));
        uint64_t dma = e->dma + (dpa - e->dpa);
        MemTxResult result = write ? pci_dma_write(PCI_DEVICE(s), dma, buf, n)
                                   : pci_dma_read(PCI_DEVICE(s), dma, buf, n);
        if (result != MEMTX_OK) {
            fault(s, ZB_DMA_FAULT);
            return ZB_DMA_FAULT;
        }
        size -= n;
        dpa += n;
        if (!zero) {
            buf += n;
        }
    }
    return ZB_OK;
}

static uint32_t publish(ZettBridge *s, ZBBank *b)
{
    uint32_t tier = ldl_le_p(b->reg + ZB_USAGE_SELECT);
    uint8_t *u;
    uint64_t capacity, a, r, q, requested, seq;
    if (tier > 1 || !s->attached || s->state != 3) {
        return ZB_DENIED;
    }
    u = b->reg + ZB_USAGE + tier * 128;
    if (ldq_le_p(u) != s->epoch || ldq_le_p(u + 8) != s->session_lo ||
        ldq_le_p(u + 16) != s->session_hi) {
        return ZB_BAD_EPOCH;
    }
    seq = ldq_le_p(u + 24);
    if (!seq || ldl_le_p(u + 32) != tier || ldl_le_p(u + 36) != 3 ||
        !buffer_is_zero(u + 80, 48)) {
        return ZB_BAD_ABI;
    }
    capacity = ldq_le_p(u + 40);
    a = ldq_le_p(u + 48);
    r = ldq_le_p(u + 56);
    q = ldq_le_p(u + 64);
    requested = ldq_le_p(u + 72);
    if (capacity != s->tier_bytes[tier] || a > capacity || r > capacity - a ||
        q > capacity - a - r || requested > a) {
        return ZB_BAD_ABI;
    }
    if (s->usage_present[tier] && seq <= ldq_le_p(s->usage[tier] + 24)) {
        return seq == ldq_le_p(s->usage[tier] + 24) ? ZB_OK : ZB_BAD_EPOCH;
    }
    memcpy(s->usage[tier], u, 128);
    s->usage_present[tier] = true;
    return ZB_OK;
}

static uint32_t execute(ZettBridge *s, unsigned port, unsigned op)
{
    ZBBank *b = &s->banks[port];
    uint64_t epoch = reg64(b, ZB_STAGED_EPOCH);
    ZBExtent *table = NULL;
    uint32_t count, status;
    if (port && op != ZB_SNAPSHOT && op != ZB_LEASE_BARRIER &&
        op != ZB_PUBLISH_OP && op != ZB_ATTACH && op != ZB_DETACH &&
        op != ZB_ZERO_RANGE) {
        return ZB_DENIED;
    }
    if (!port && (op == ZB_PUBLISH_OP || op == ZB_ATTACH || op == ZB_DETACH ||
                  op == ZB_ZERO_RANGE || op == ZB_LEASE_BARRIER)) {
        return ZB_DENIED;
    }
    if (op == ZB_SNAPSHOT) {
        uint8_t *p = b->reg + ZB_INVENTORY;
        memset(p, 0, 64);
        stq_le_p(p, s->epoch);
        stq_le_p(p + 8, s->exported);
        stl_le_p(p + 16, s->state);
        stl_le_p(p + 20, s->fault);
        stl_le_p(p + 24, b->last_seq);
        stl_le_p(p + 28, b->last_status);
        stq_le_p(p + 32, ++s->snapshot_seq);
        return ZB_OK;
    }
    if (s->fault) {
        return ZB_DMA_FAULT;
    }
    if (op == ZB_COMMIT_OP || op == ZB_TEST_DMA) {
        if (s->attached || (s->state != 0 && s->state != 1 && s->state != 5)) {
            return ZB_NOT_QUIESCED;
        }
        status = table_fetch(s, b, &table, &count);
        if (status) {
            return status;
        }
        if (op == ZB_TEST_DMA) {
            /*
             * Full-range bidirectional reachability before any publication.
             * Invert initialized bytes; CPU verifies every byte after sync.
             */
            uint8_t data[4096];
            for (unsigned i = 0; i < count && !status; i++) {
                for (uint64_t off = 0; off < table[i].length;
                     off += sizeof(data)) {
                    if (pci_dma_read(PCI_DEVICE(s), table[i].dma + off, data,
                                     sizeof(data))) {
                        status = ZB_DMA_FAULT;
                        break;
                    }
                    for (unsigned j = 0; j < sizeof(data); j++) {
                        data[j] ^= 0xff;
                    }
                    if (pci_dma_write(PCI_DEVICE(s), table[i].dma + off, data,
                                      sizeof(data))) {
                        status = ZB_DMA_FAULT;
                        break;
                    }
                }
            }
            g_free(table);
            if (!status) {
                s->state = 1;
            }
            return status;
        }
        g_free(s->extents);
        s->extents = table;
        s->count = count;
        s->epoch = epoch;
        s->exported = s->capacity;
        s->tier_bytes[0] = s->tier_bytes[1] = 0;
        for (unsigned i = 0; i < count; i++) {
            s->tier_bytes[table[i].tier] += table[i].length;
        }
        memset(s->usage_present, 0, sizeof(s->usage_present));
        s->state = 2;
        s->drained = false;
        s->ever_attached = s->revoke = false;
        return ZB_OK;
    }
    if (epoch != s->epoch || !epoch) {
        return ZB_BAD_EPOCH;
    }
    switch (op) {
    case ZB_ATTACH:
        if (!port || s->state != 2 || s->attached || s->ever_attached ||
            reg64(b, ZB_ATTACH_SIZE) != s->exported ||
            !(reg64(b, ZB_SESSION_LO) | reg64(b, ZB_SESSION_HI))) {
            return ZB_DENIED;
        }
        s->session_lo = reg64(b, ZB_SESSION_LO);
        s->session_hi = reg64(b, ZB_SESSION_HI);
        s->attached = s->ever_attached = true;
        return ZB_OK;
    case ZB_ENABLE:
        if (s->state != 2 || !s->attached) {
            return ZB_BUSY;
        }
        s->state = 3;
        return ZB_OK;
    case ZB_REQUEST_REVOKE:
        s->revoke = true;
        return ZB_OK;
    case ZB_DETACH:
        if (!port || !s->attached || reg64(b, ZB_SESSION_LO) != s->session_lo ||
            reg64(b, ZB_SESSION_HI) != s->session_hi) {
            return ZB_DENIED;
        }
        s->attached = false;
        return ZB_OK;
    case ZB_QUIESCE:
        if (s->attached) {
            return ZB_NOT_QUIESCED;
        }
        s->state = 4;
        return ZB_OK;
    case ZB_DRAIN:
        if (s->state != 4 || s->attached) {
            return ZB_NOT_QUIESCED;
        }
        /* All admitted DMA is synchronous on this BQL. */
        s->drained = true;
        return ZB_OK;
    case ZB_RETIRE:
        if (!s->drained || s->attached || s->state != 4) {
            return ZB_NOT_QUIESCED;
        }
        g_clear_pointer(&s->extents, g_free);
        s->count = 0;
        s->exported = 0;
        s->state = 5;
        return ZB_OK;
    case ZB_LEASE_BARRIER:
        return s->attached && s->state == 3 ? ZB_OK : ZB_NOT_QUIESCED;
    case ZB_ZERO_RANGE: {
        uint8_t zero[4096] = {0};
        uint64_t start = reg64(b, ZB_RANGE_START),
                 length = reg64(b, ZB_RANGE_LENGTH);
        if (!s->attached || s->state != 3 || !length || start >= s->exported ||
            length > s->exported - start) {
            return ZB_DENIED;
        }
        while (length) {
            unsigned n = MIN(length, sizeof(zero));
            status = dma_range(s, start, zero, n, true, true);
            if (status) {
                return status;
            }
            length -= n;
            start += n;
        }
        return ZB_OK;
    }
    case ZB_PUBLISH_OP:
        return publish(s, b);
    case ZB_READ_USAGE: {
        unsigned tier = ldl_le_p(b->reg + ZB_USAGE_SELECT);
        if (tier > 1 || !s->usage_present[tier]) {
            return ZB_BUSY;
        }
        memcpy(b->reg + ZB_USAGE + tier * 128, s->usage[tier], 128);
        return ZB_OK;
    }
    default:
        return ZB_BAD_ABI;
    }
}

static void command(ZettBridge *s, unsigned port, unsigned op)
{
    ZBBank *b = &s->banks[port];
    uint32_t seq = ldl_le_p(b->reg + ZB_CMD_SEQ);
    uint64_t epoch = reg64(b, ZB_STAGED_EPOCH);
    /* Repeated doorbells do not execute a second transaction. */
    if (!seq || seq <= b->last_seq) {
        return;
    }
    b->last_status = execute(s, port, op);
    b->last_epoch = epoch;
    b->last_seq = seq;
    if (s->drop_ack_op == op) {
        s->drop_ack_op = 0;
        return;
    }
    stl_le_p(b->reg + ZB_ACK_STATUS, b->last_status);
    stq_le_p(b->reg + ZB_ACK_EPOCH, epoch);
    stl_le_p(b->reg + ZB_ACK_SEQ, seq);
}

static uint32_t bar_read(ZettBridge *s, unsigned port, unsigned addr)
{
    ZBBank *b = &s->banks[port];
    uint64_t value;
    switch (addr & ~7u) {
    case ZB_ID:
        value = ZB_ID_VERSION;
        break;
    case ZB_CAP:
        value = ZB_CAPS;
        break;
    case ZB_STATUS:
        value = (s->state == 2 || s->state == 3) | ((s->state == 3) << 1) |
                (!!s->fault << 2);
        break;
    case ZB_EPOCH:
        value = s->epoch;
        break;
    case ZB_EXPORTED:
        value = s->exported;
        break;
    case ZB_CAPACITY:
        value = s->capacity;
        break;
    case ZB_FAULT:
        value = s->fault;
        break;
    case ZB_SNAPSHOT_SEQ:
        value = s->snapshot_seq;
        break;
    case ZB_MAX:
        value = ZB_MAX_EXTENTS;
        break;
    case ZB_MIN_ALIGN:
        value = ZB_ALIGN;
        break;
    case ZB_MODEL:
        value = ZB_MODEL_V1;
        break;
    case ZB_TIER0_BYTES:
        value = s->tier_bytes[0];
        break;
    case ZB_TIER1_BYTES:
        value = s->tier_bytes[1];
        break;
    case ZB_ATTACHED:
        value = s->attached;
        break;
    case ZB_REVOKE_REQUEST:
        value = s->revoke;
        break;
    default:
        return ldl_le_p(b->reg + addr);
    }
    return addr & 4 ? value >> 32 : value;
}

static void bar_write(ZettBridge *s, unsigned port, unsigned addr,
                      uint32_t value)
{
    ZBBank *b = &s->banks[port];
    if (addr == ZB_CONTROL || addr == ZB_COMMIT || addr == ZB_USAGE_PUBLISH) {
        if (addr == ZB_CONTROL || value == 1) {
            command(s, port,
                    addr == ZB_COMMIT          ? ZB_COMMIT_OP
                    : addr == ZB_USAGE_PUBLISH ? ZB_PUBLISH_OP
                                               : value);
        }
        return;
    }
    if (addr == ZB_QUERY_DOORBELL && value == 1) {
        uint8_t *p = b->reg + ZB_QUERY_RESULT;
        uint32_t seq = ldl_le_p(b->reg + ZB_QUERY_SEQ);
        uint32_t target = ldl_le_p(b->reg + ZB_QUERY_TARGET);
        uint64_t epoch = reg64(b, ZB_QUERY_EPOCH);
        bool found = !s->query_unknown && target && target == b->last_seq &&
                     epoch == b->last_epoch;
        memset(p, 0, 64);
        stl_le_p(p, seq);
        stl_le_p(p + 4, target);
        stq_le_p(p + 8, epoch);
        stl_le_p(p + 16, found ? 2 : 0);
        stl_le_p(p + 20, found ? b->last_status : 0);
        stl_le_p(b->reg + ZB_QUERY_ACK, seq);
        return;
    }
    if (addr == ZB_CMD_SEQ || addr == ZB_USAGE_SELECT ||
        addr == ZB_QUERY_TARGET || addr == ZB_QUERY_SEQ ||
        (addr >= ZB_QUERY_EPOCH && addr < ZB_QUERY_EPOCH + 8) ||
        (addr >= ZB_STAGED_EPOCH && addr < ZB_STAGED_EPOCH + 8) ||
        (!port && addr >= ZB_TABLE_BASE && addr < ZB_TABLE_COUNT + 8) ||
        (port && addr >= ZB_SESSION_LO && addr < ZB_ATTACH_SIZE + 8) ||
        (port && addr >= ZB_RANGE_START && addr < ZB_RANGE_LENGTH + 8) ||
        (port && addr >= ZB_USAGE && addr < ZB_USAGE + 256)) {
        stl_le_p(b->reg + addr, value);
    }
}

static void disconnect_peer(ZettBridge *s)
{
    if (s->peer >= 0) {
        if (s->provider) {
            qemu_set_fd_handler(s->peer, NULL, NULL, NULL);
        }
        close(s->peer);
        s->peer = -1;
    }
    if (s->ever_attached && s->state != 5) {
        fault(s, ZB_DMA_FAULT);
    }
}

static void receive_packet(void *opaque)
{
    ZettBridge *s = opaque;
    ZBPacket p;
    ssize_t n = recv(s->peer, &p, sizeof(p), MSG_DONTWAIT | MSG_TRUNC);
    if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
        return;
    }
    if (n != sizeof(p) || le32_to_cpu(p.magic) != ZB_MODEL_V1) {
        disconnect_peer(s);
        return;
    }
    unsigned op = le32_to_cpu(p.op), size = le32_to_cpu(p.size);
    uint64_t addr = le64_to_cpu(p.addr);
    unsigned status = ZB_BAD_ABI;
    if (op <= 1 && size == 4 && !(addr & 3) && addr < ZB_BAR_SIZE) {
        if (op) {
            bar_write(s, 1, addr, le64_to_cpu(p.value));
        } else {
            p.value = cpu_to_le64(bar_read(s, 1, addr));
        }
        status = ZB_OK;
    } else if ((op == 2 || op == 3) && size && size <= sizeof(p.data)) {
        status = s->state == 3 && s->attached && !s->fault
                     ? dma_range(s, addr, p.data, size, op == 3, false)
                     : ZB_DENIED;
    }
    p.status = cpu_to_le32(status);
    if (send(s->peer, &p, sizeof(p), MSG_NOSIGNAL | MSG_DONTWAIT) !=
        sizeof(p)) {
        disconnect_peer(s);
    }
}

static void accept_peer(void *opaque)
{
    ZettBridge *s = opaque;
    int fd = accept(s->listener, NULL, NULL);
    if (fd < 0) {
        return;
    }
    if (s->peer >= 0 || s->fault) {
        close(fd);
        return;
    }
    s->peer = fd;
    qemu_set_fd_handler(fd, receive_packet, NULL, s);
}

static bool transact(ZettBridge *s, ZBPacket *p)
{
    struct pollfd fd = {.fd = s->peer, .events = POLLIN};
    if (s->peer < 0 ||
        send(s->peer, p, sizeof(*p), MSG_NOSIGNAL | MSG_DONTWAIT) !=
            sizeof(*p) ||
        poll(&fd, 1, s->timeout_ms) != 1 || !(fd.revents & POLLIN)) {
        disconnect_peer(s);
        return false;
    }
    ZBPacket reply;
    if (recv(s->peer, &reply, sizeof(reply), MSG_DONTWAIT | MSG_TRUNC) !=
            sizeof(reply) ||
        reply.magic != p->magic || reply.op != p->op || reply.addr != p->addr ||
        reply.size != p->size) {
        disconnect_peer(s);
        return false;
    }
    s->ever_attached = true;
    *p = reply;
    return le32_to_cpu(p->status) == ZB_OK;
}

void zettbridge_set_hdm(ZettBridge *s, uint64_t base, uint64_t size)
{
    if (s->hdm_size && (base != s->hdm_base || size != s->hdm_size) &&
        s->ever_attached) {
        disconnect_peer(s);
    }
    s->hdm_base = base;
    s->hdm_size = size;
}

static uint64_t mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    ZettBridge *s = opaque;
    if (!s->provider && (addr & ~7u) == ZB_HDM_BASE) {
        return addr & 4 ? s->hdm_base >> 32 : (uint32_t)s->hdm_base;
    }
    if (!s->provider && (addr & ~7u) == ZB_HDM_SIZE) {
        return addr & 4 ? s->hdm_size >> 32 : (uint32_t)s->hdm_size;
    }
    if (s->provider) {
        return bar_read(s, 0, addr);
    }
    ZBPacket p = {.magic = cpu_to_le32(ZB_MODEL_V1),
                  .size = cpu_to_le32(size),
                  .addr = cpu_to_le64(addr)};
    return transact(s, &p) ? le64_to_cpu(p.value) : UINT32_MAX;
}

static void mmio_write(void *opaque, hwaddr addr, uint64_t value, unsigned size)
{
    ZettBridge *s = opaque;
    if (s->provider) {
        bar_write(s, 0, addr, value);
    } else {
        ZBPacket p = {.magic = cpu_to_le32(ZB_MODEL_V1),
                      .op = cpu_to_le32(1),
                      .size = cpu_to_le32(size),
                      .addr = cpu_to_le64(addr),
                      .value = cpu_to_le64(value)};
        transact(s, &p);
    }
}

MemTxResult zettbridge_access(ZettBridge *s, uint64_t dpa, void *buf,
                              unsigned size, bool write)
{
    ZBPacket p = {.magic = cpu_to_le32(ZB_MODEL_V1),
                  .op = cpu_to_le32(write ? 3 : 2),
                  .size = cpu_to_le32(size),
                  .addr = cpu_to_le64(dpa)};
    if (s->provider || !size || size > sizeof(p.data) || dpa >= s->capacity ||
        size > s->capacity - dpa) {
        return MEMTX_ERROR;
    }
    if (write) {
        memcpy(p.data, buf, size);
    }
    if (!transact(s, &p)) {
        return MEMTX_ERROR;
    }
    if (!write) {
        memcpy(buf, p.data, size);
    }
    return MEMTX_OK;
}

bool zettbridge_is_consumer(ZettBridge *s, uint64_t capacity)
{
    return s->realized && !s->provider && capacity == s->capacity;
}

static const MemoryRegionOps zb_ops = {
    .read = mmio_read,
    .write = mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {.min_access_size = 4, .max_access_size = 4},
    .impl = {.min_access_size = 4, .max_access_size = 4},
};

static void zb_realize(PCIDevice *pdev, Error **errp)
{
    ZettBridge *s = ZETTBRIDGE(pdev);
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    s->listener = s->peer = -1;
    if (!s->socket_path || strlen(s->socket_path) >= sizeof(addr.sun_path) ||
        !s->capacity || (s->capacity & ((256 * MiB) - 1)) || !s->timeout_ms ||
        s->timeout_ms > 30000) {
        error_setg(errp, "zettbridge requires socket and capacity aligned to "
                         "256 MiB, timeout 1..30000 ms");
        return;
    }
    pstrcpy(addr.sun_path, sizeof(addr.sun_path), s->socket_path);
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        error_setg_errno(errp, errno, "zettbridge socket");
        return;
    }
    if (s->provider) {
        /* Never unlink somebody else's live/stale socket automatically. */
        if (bind(fd, (void *)&addr, sizeof(addr)) || listen(fd, 1)) {
            error_setg_errno(errp, errno, "zettbridge listen %s",
                             addr.sun_path);
            close(fd);
            return;
        }
        chmod(addr.sun_path, 0600);
        s->listener = fd;
        qemu_set_fd_handler(fd, accept_peer, NULL, s);
    } else {
        if (connect(fd, (void *)&addr, sizeof(addr))) {
            error_setg_errno(errp, errno, "zettbridge connect %s",
                             addr.sun_path);
            close(fd);
            return;
        }
        s->peer = fd;
    }
    pci_set_word(pdev->config + PCI_DEVICE_ID,
                 s->provider ? ZB_PROVIDER_DEVICE : ZB_CONSUMER_DEVICE);
    pcie_endpoint_cap_init(pdev, 0x80);
    memory_region_init_io(&s->bar, OBJECT(s), &zb_ops, s, "zettai-rpu-mgmt",
                          ZB_BAR_SIZE);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->bar);
    s->realized = true;
}

static void zb_exit(PCIDevice *pdev)
{
    ZettBridge *s = ZETTBRIDGE(pdev);
    disconnect_peer(s);
    if (s->listener >= 0) {
        qemu_set_fd_handler(s->listener, NULL, NULL, NULL);
        close(s->listener);
        unlink(s->socket_path);
    }
    g_free(s->extents);
    pcie_cap_exit(pdev);
}

static void zb_reset(DeviceState *dev)
{
    ZettBridge *s = ZETTBRIDGE(dev);
    if (s->realized && (s->epoch || s->ever_attached)) {
        /* A reset never authorizes old backing/mapping reuse. */
        fault(s, ZB_DMA_FAULT);
        disconnect_peer(s);
    }
}

static const Property zb_props[] = {
    DEFINE_PROP_BOOL("provider", ZettBridge, provider, false),
    DEFINE_PROP_STRING("socket", ZettBridge, socket_path),
    DEFINE_PROP_SIZE("capacity", ZettBridge, capacity, 256 * MiB),
    DEFINE_PROP_UINT32("timeout-ms", ZettBridge, timeout_ms, 2000),
    DEFINE_PROP_UINT32("x-drop-ack-op", ZettBridge, drop_ack_op, 0),
    DEFINE_PROP_BOOL("x-query-unknown", ZettBridge, query_unknown, false),
};
static const VMStateDescription zb_vmstate = {
    .name = "zettbridge",
    .unmigratable = 1,
};
static void zb_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(klass);
    pc->realize = zb_realize;
    pc->exit = zb_exit;
    pc->vendor_id = ZB_VENDOR;
    pc->device_id = ZB_PROVIDER_DEVICE;
    pc->revision = 2;
    pc->class_id = PCI_CLASS_MEMORY_OTHER;
    dc->desc = "Zettai RPU v0.2 dual-host management/DMA function";
    dc->vmsd = &zb_vmstate;
    device_class_set_legacy_reset(dc, zb_reset);
    device_class_set_props(dc, zb_props);
}
static const TypeInfo zb_info = {
    .name = TYPE_ZETTBRIDGE,
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(ZettBridge),
    .class_init = zb_class_init,
    .interfaces = (const InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE }, { }
    },
};
static void zb_register(void)
{
    type_register_static(&zb_info);
}
type_init(zb_register)
