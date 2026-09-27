/*
 * SlugArch native endpoint gate and virtual-time vector engine.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Experimental coverage: only the opt-in vector-job interface. This is not
 * enforcement for legacy BAR writes or GPU commands, nor a hardware JIT.
 * All access and timer callbacks run under QEMU's main-loop/BQL serialization.
 * A shared output-link FIFO models contention; endpoint compute can overlap.
 */
#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "qemu/bswap.h"
#include "hw/cxl/cxl_type2.h"
#include "hw/cxl/cxl_slugarch.h"

#define MAX_RECORDS 1024
#define RECORD_SIZE 128
#define POLICY_ID 0x534c554700000001ULL
#define MAX_WORDS 65536

enum { IDLE, BUSY, DONE, PREFAIL, POSTFAIL };
enum { E_NONE, E_EPOCH, E_RANGE, E_CAPACITY, E_REQUEST, E_COMPLETION, E_DESCRIPTOR };
enum { COMPUTE_END, LINK_END, RECORD_END };

struct CXLSlugArchState {
    QEMUTimer *timer;
    CXLType2State *device;
    uint64_t state, error, epoch, job_epoch, job, src, dst, words, scalar;
    uint64_t release, fault, capacity, count, committed, finished;
    uint64_t compute_start, compute_end, link_start, link_end, queue_wait;
    uint64_t rejected, requests, completions, failures;
    unsigned phase;
    uint8_t *input, *output;
    uint8_t log[MAX_RECORDS][RECORD_SIZE];
    uint8_t failure[RECORD_SIZE]; /* Reserved even when the main log is full. */
};

/* One explicitly modeled output link for enabled devices in this process.
 * Serialization occupies bytes/bandwidth; propagation can overlap later sends.
 * No state survives the last device's destruction. */
static uint64_t link_free_ns;
static unsigned link_users;

static void digest(const uint8_t *data, size_t size, uint8_t *out)
{
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    gsize len = 32;
    g_checksum_update(sum, data, size);
    g_checksum_get_digest(sum, out, &len);
    g_checksum_free(sum);
}

static void record(struct CXLSlugArchState *s, uint8_t *out, uint64_t kind,
                   const uint8_t *data)
{
    uint64_t fields[] = { kind, s->device->sn, s->epoch, s->count + 1,
        s->job, s->src, s->dst, s->words, s->scalar, POLICY_ID,
        qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), s->committed };
    for (unsigned i = 0; i < G_N_ELEMENTS(fields); i++) {
        stq_le_p(out + i * 8, fields[i]);
    }
    if (data) {
        digest(data, s->words * 8, out + 96);
    } else {
        memset(out + 96, 0, 32);
    }
}

static void fail(struct CXLSlugArchState *s, uint64_t error)
{
    s->error = error;
    s->state = s->committed ? POSTFAIL : PREFAIL;
    s->finished = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    s->failures++;
    record(s, s->failure, s->committed ? 4 : 3,
           s->committed ? s->output : NULL);
}

static void complete(void *opaque)
{
    struct CXLSlugArchState *s = opaque;
    CXLType2State *d = s->device;
    uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    uint64_t bytes = s->words * 8;
    uint8_t *ram = memory_region_get_ram_ptr(&d->device_mem);

    switch (s->phase) {
    case COMPUTE_END:
        for (uint64_t i = 0; i < s->words; i++) {
            stq_le_p(s->output + i * 8,
                     3 * ldq_le_p(s->input + i * 8) + s->scalar + i);
        }
        s->link_start = MAX(now, link_free_ns);
        s->queue_wait = s->link_start - now;
        link_free_ns = s->link_start +
            DIV_ROUND_UP(bytes, d->slugarch_bandwidth);
        s->link_end = link_free_ns + d->slugarch_link_ns;
        s->phase = LINK_END;
        timer_mod(s->timer, s->link_end);
        break;
    case LINK_END:
        memcpy(ram + s->dst, s->output, bytes);
        for (uint64_t a = s->dst & ~63ULL; a < s->dst + bytes; a += 64) {
            cxl_type2_cache_invalidate(d, a);
        }
        if (d->bar_coherency.enabled) {
            cxl_bar_notify_gpu_access(&d->bar_coherency, s->dst, bytes, true);
        }
        s->committed = 1;
        s->phase = RECORD_END;
        timer_mod(s->timer, now +
                  (d->slugarch_enforce ? d->slugarch_record_ns : 0));
        break;
    case RECORD_END:
        if (d->slugarch_enforce && (s->fault & 2)) {
            fail(s, E_COMPLETION);
            break;
        }
        if (d->slugarch_enforce) {
            record(s, s->log[s->count], 2, s->output);
            s->count++;
            s->completions++;
        }
        s->finished = now;
        s->state = DONE;
        break;
    }
}

static bool range_valid(CXLType2State *d, uint64_t base, uint64_t bytes)
{
    return !(base & 7) && base <= d->device_mem_size &&
           bytes <= d->device_mem_size - base;
}

static void submit(struct CXLSlugArchState *s)
{
    CXLType2State *d = s->device;
    uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    uint64_t bytes;

    s->committed = s->error = s->finished = 0;
    s->compute_start = s->compute_end = 0;
    s->link_start = s->link_end = s->queue_wait = 0;
    memset(s->failure, 0, sizeof(s->failure));
    if (s->job_epoch != s->epoch) {
        fail(s, E_EPOCH);
        return;
    }
    if (!s->words || s->words > MAX_WORDS || s->fault > 3 ||
        s->release < now || s->release - now > NANOSECONDS_PER_SECOND) {
        fail(s, E_DESCRIPTOR);
        return;
    }
    bytes = s->words * 8;
    if (!range_valid(d, s->src, bytes) || !range_valid(d, s->dst, bytes)) {
        fail(s, E_RANGE);
        return;
    }
    if (d->slugarch_enforce && s->count + 2 > s->capacity) {
        fail(s, E_CAPACITY);
        return;
    }
    if (d->slugarch_enforce && (s->fault & 1)) {
        fail(s, E_REQUEST);
        return;
    }
    g_free(s->input);
    g_free(s->output);
    s->input = g_memdup2((uint8_t *)memory_region_get_ram_ptr(&d->device_mem)
                        + s->src, bytes);
    s->output = g_malloc(bytes);
    if (d->slugarch_enforce) {
        record(s, s->log[s->count], 1, s->input);
        s->count++;
        s->requests++;
    }
    s->compute_start = s->release +
        (d->slugarch_enforce ? d->slugarch_record_ns : 0);
    s->compute_end = s->compute_start + s->words * d->slugarch_compute_ns;
    s->phase = COMPUTE_END;
    s->state = BUSY;
    timer_mod(s->timer, s->compute_end);
}

void cxl_slugarch_init(CXLType2State *d)
{
    if (!d->slugarch_enabled) {
        return;
    }
    d->slugarch = g_new0(struct CXLSlugArchState, 1);
    d->slugarch->device = d;
    d->slugarch->epoch = 1;
    d->slugarch->capacity = MAX_RECORDS;
    d->slugarch->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, complete, d->slugarch);
    if (!link_users++) {
        link_free_ns = 0;
    }
}

void cxl_slugarch_cleanup(CXLType2State *d)
{
    if (d->slugarch) {
        timer_free(d->slugarch->timer);
        g_free(d->slugarch->input);
        g_free(d->slugarch->output);
        g_free(d->slugarch);
        d->slugarch = NULL;
        if (!--link_users) {
            link_free_ns = 0;
        }
    }
}

uint64_t cxl_slugarch_read(CXLType2State *d, hwaddr addr, unsigned size)
{
    struct CXLSlugArchState *s = d->slugarch;
    uint64_t value = 0;
    const uint8_t *data = NULL;
    uint64_t offset = 0, available = 0;
    if (addr >= 0x1000) {
        data = (const uint8_t *)s->log;
        offset = addr - 0x1000;
        available = s->count * RECORD_SIZE;
    } else if (addr >= 0x800 && addr < 0x880) {
        data = s->failure;
        offset = addr - 0x800;
        available = RECORD_SIZE;
    }
    if (data) {
        if (offset <= available && size <= available - offset) {
            for (unsigned i = 0; i < size; i++) {
                value |= (uint64_t)data[offset + i] << (8 * i);
            }
        }
        return value;
    }
    if ((addr & 7) || size != 8) {
        return 0;
    }
    switch (addr) {
    case 0x00: return 0x534c554741524301ULL;
    case 0x08: return s->state;
    case 0x10: return s->error;
    case 0x18: return s->epoch;
    case 0x20: return s->job_epoch;
    case 0x28: return s->job;
    case 0x30: return s->src;
    case 0x38: return s->dst;
    case 0x40: return s->words;
    case 0x48: return s->scalar;
    case 0x50: return s->release;
    case 0x58: return s->fault;
    case 0x60: return s->capacity;
    case 0x68: return s->count;
    case 0x70: return s->committed;
    case 0x78: return s->finished;
    case 0x80: return s->compute_start;
    case 0x88: return s->compute_end;
    case 0x90: return s->link_start;
    case 0x98: return s->link_end;
    case 0xa0: return s->queue_wait;
    case 0xb0: return s->rejected;
    case 0xb8: return POLICY_ID;
    case 0xc0: return d->slugarch_enforce;
    case 0xc8: return d->slugarch_record_ns;
    case 0xd0: return d->slugarch_compute_ns;
    case 0xd8: return d->slugarch_bandwidth;
    case 0xe0: return d->slugarch_link_ns;
    case 0xe8: return s->requests;
    case 0xf0: return s->completions;
    case 0xf8: return s->failures;
    case 0x100: return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    default: return 0;
    }
}

void cxl_slugarch_write(CXLType2State *d, hwaddr addr, uint64_t v, unsigned size)
{
    struct CXLSlugArchState *s = d->slugarch;
    if (size != 8 || (addr & 7) || s->state == BUSY) {
        s->rejected++;
        return;
    }
    switch (addr) {
    case 0x18:
        /* An explicit higher epoch acknowledges terminal state and drains logs.
         * Trusted software must retain the exported old epoch before doing this. */
        if (v <= s->epoch) {
            s->rejected++;
            return;
        }
        s->epoch = v;
        s->count = s->state = s->error = s->committed = 0;
        memset(s->failure, 0, sizeof(s->failure));
        break;
    case 0x20: s->job_epoch = v; break;
    case 0x28: s->job = v; break;
    case 0x30: s->src = v; break;
    case 0x38: s->dst = v; break;
    case 0x40: s->words = v; break;
    case 0x48: s->scalar = v; break;
    case 0x50: s->release = v; break;
    case 0x58: s->fault = v; break;
    case 0x60:
        if (v < s->count || v > MAX_RECORDS) {
            s->rejected++;
        } else {
            s->capacity = v;
        }
        break;
    case 0xa8:
        if (v == 1 && s->state != PREFAIL && s->state != POSTFAIL) {
            submit(s);
        } else {
            s->rejected++;
        }
        break;
    default: s->rejected++; break;
    }
}
