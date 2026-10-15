/*
 * SlugArch J-extension dynamic adapter tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/cxl/slugarch_jit.h"
#include "qemu/units.h"
#include "qapi/error.h"

static const char real_policy[] =
    "{"
    "\"version\":1,"
    "\"name\":\"qemu-adapter-validation\","
    "\"allowed_classes\":[\"cxl_mem_read\",\"cxl_mem_write\","
    "\"cxl_mem_data\",\"completion\"],"
    "\"ranges\":[{\"base\":83886080,\"length\":33554432}],"
    "\"sample_stride\":1,"
    "\"record_mode\":\"validation\","
    "\"metadata_budget\":256,"
    "\"epoch_policy\":\"phase\","
    "\"rules\":["
    "{\"op\":\"capture\",\"mode\":\"validation\"},"
    "{\"op\":\"emit\"},"
    "{\"op\":\"epoch_from_phase\"},"
    "{\"op\":\"halt\"}"
    "]"
    "}";

static char *fake_module_path(const char *name)
{
    const char *build_dir = g_getenv("G_TEST_BUILDDIR");
    g_autofree char *filename = NULL;

    g_assert_nonnull(build_dir);
    filename = g_strdup_printf("%s%s", name, CONFIG_HOST_DSOSUF);
    return g_canonicalize_filename(filename, build_dir);
}

static CXLType2JitEvent valid_event(void)
{
    CXLType2JitEvent event = {
        .client_id = 17,
        .direction = 0,
        .event_class = 2,
        .opcode = 3,
        .payload_len = 3,
        .address = 80 * MiB,
        .tag = 11,
        .phase_id = 7,
        .monotonic_ns = 900,
        .status = 0,
        .payload = { 1, 0, 2 },
    };

    return event;
}

static void assert_error_contains(Error *error, const char *needle)
{
    g_assert_nonnull(error);
    g_assert_nonnull(strstr(error_get_pretty(error), needle));
    error_free(error);
}

static void open_fake(CXLType2JitState *state, uint32_t backend)
{
    g_autofree char *module = fake_module_path("slugarch-jit-fake");
    Error *error = NULL;

    cxl_type2_jit_state_init(state, backend, true, 256);
    g_assert_true(cxl_type2_jit_open(state, module, &error));
    g_assert_null(error);
    g_assert_cmpuint(state->abi_version, ==, SLUG_JIT_ABI_VERSION);
    g_assert_cmpuint(state->requested_backend, ==, backend);
    g_assert_nonnull(state->library);
    g_assert_nonnull(state->handle);
    g_assert_cmpuint(state->status, ==, SLUG_JIT_STATUS_LOADING);
    g_assert_false(state->ready);
}

static void load_fake_policy(CXLType2JitState *state, const char *policy)
{
    Error *error = NULL;

    g_assert_true(cxl_type2_jit_load_policy(
        state, (const uint8_t *)policy, strlen(policy), &error));
    g_assert_null(error);
    g_assert_true(state->ready);
    g_assert_cmpuint(state->status, ==, SLUG_JIT_STATUS_READY);
    g_assert_cmpuint(state->selected_backend, ==, state->requested_backend);
    g_assert_cmpuint(state->policy_bytes, ==, strlen(policy));
    for (size_t i = 0; i < sizeof(state->policy_digest); i++) {
        g_assert_cmpuint(state->policy_digest[i], ==, 0xa5);
    }
}

static void test_open_load_observe_close(void)
{
    CXLType2JitState state;
    CXLType2JitEvent event = valid_event();
    SlugJitDecision decision;
    Error *error = NULL;

    open_fake(&state, SLUG_JIT_BACKEND_RUST);
    load_fake_policy(&state, "valid");
    g_assert_true(cxl_type2_jit_observe_event(
        &state, &event, &decision, &error));
    g_assert_null(error);

    g_assert_cmpuint(state.last_event.struct_size, ==,
                     sizeof(SlugJitEvent));
    g_assert_cmpuint(state.last_event.abi_version, ==,
                     SLUG_JIT_ABI_VERSION);
    g_assert_cmpuint(state.last_event.event_id, ==, 1);
    g_assert_cmpuint(state.last_event.client_id, ==, event.client_id);
    g_assert_cmpuint(state.last_event.payload_len, ==, event.payload_len);
    g_assert_cmpmem(state.last_event.payload, event.payload_len,
                    event.payload, event.payload_len);
    for (size_t i = event.payload_len; i < SLUG_JIT_PAYLOAD_BYTES; i++) {
        g_assert_cmpuint(state.last_event.payload[i], ==, 0);
    }
    g_assert_cmpuint(decision.accepted, ==, 1);
    g_assert_cmpuint(decision.emitted, ==, 1);
    g_assert_cmpuint(decision.record_id, ==, 1);
    g_assert_cmpuint(state.stats.event_count, ==, 1);
    g_assert_cmpuint(state.stats.record_count, ==, 1);
    g_assert_cmpuint(state.stats.metadata_bytes, ==, 8);
    g_assert_cmpuint(state.stats.drop_count, ==, 0);

    cxl_type2_jit_close(&state);
    cxl_type2_jit_close(&state);
    g_assert_null(state.library);
    g_assert_null(state.handle);
    g_assert_cmpuint(state.status, ==, SLUG_JIT_STATUS_OFF);
}

static void test_loader_rejections(void)
{
    g_autofree char *module = fake_module_path("slugarch-jit-fake");
    g_autofree char *missing_symbol =
        fake_module_path("slugarch-jit-fake-missing");
    CXLType2JitState state;
    Error *error = NULL;

    cxl_type2_jit_state_init(&state, SLUG_JIT_BACKEND_RUST, true, 256);
    g_assert_false(cxl_type2_jit_open(&state, "relative.so", &error));
    assert_error_contains(g_steal_pointer(&error), "absolute");

    g_assert_false(cxl_type2_jit_open(
        &state, "/definitely/missing/slugarch-jit.so", &error));
    assert_error_contains(g_steal_pointer(&error), "dlopen");

    g_setenv("SLUGARCH_JIT_FAKE_BAD_ABI", "1", true);
    g_assert_false(cxl_type2_jit_open(&state, module, &error));
    assert_error_contains(g_steal_pointer(&error), "ABI version");
    g_unsetenv("SLUGARCH_JIT_FAKE_BAD_ABI");

    g_assert_false(cxl_type2_jit_open(&state, missing_symbol, &error));
    assert_error_contains(g_steal_pointer(&error), "slugarch_jit_stats");

    cxl_type2_jit_state_init(
        &state, SLUG_JIT_BACKEND_FPGA_VERILATOR, true, 256);
    g_setenv("SLUGARCH_JIT_FAKE_NO_FPGA", "1", true);
    g_assert_false(cxl_type2_jit_open(&state, module, &error));
    assert_error_contains(g_steal_pointer(&error),
                          "lacks required capabilities");
    g_unsetenv("SLUGARCH_JIT_FAKE_NO_FPGA");

    cxl_type2_jit_state_init(&state, SLUG_JIT_BACKEND_RUST, true, 256);
    g_setenv("SLUGARCH_JIT_FAKE_MISSING_CORE_CAP", "1", true);
    g_assert_false(cxl_type2_jit_open(&state, module, &error));
    assert_error_contains(g_steal_pointer(&error),
                          "lacks required capabilities");
    g_unsetenv("SLUGARCH_JIT_FAKE_MISSING_CORE_CAP");
    cxl_type2_jit_close(&state);
}

static void test_policy_rejections_are_fail_closed(void)
{
    CXLType2JitState state;
    CXLType2JitEvent event = valid_event();
    SlugJitDecision decision;
    Error *error = NULL;

    open_fake(&state, SLUG_JIT_BACKEND_FPGA_VERILATOR);
    g_assert_false(cxl_type2_jit_load_policy(
        &state, (const uint8_t *)"invalid", 7, &error));
    g_assert_cmpuint(state.last_error, ==, SLUG_JIT_ERR_PARSE);
    g_assert_false(state.ready);
    g_assert_cmpuint(state.status, ==, SLUG_JIT_STATUS_ERROR);
    assert_error_contains(g_steal_pointer(&error), "policy");
    g_assert_false(cxl_type2_jit_observe_event(
        &state, &event, &decision, &error));
    assert_error_contains(g_steal_pointer(&error), "not ready");
    cxl_type2_jit_close(&state);

    open_fake(&state, SLUG_JIT_BACKEND_RUST);
    g_assert_false(cxl_type2_jit_load_policy(
        &state, (const uint8_t *)"bad-digest", 10, &error));
    g_assert_cmpuint(state.last_error, ==, SLUG_JIT_ERR_DIGEST_MISMATCH);
    assert_error_contains(g_steal_pointer(&error), "digest");
    cxl_type2_jit_close(&state);

    open_fake(&state, SLUG_JIT_BACKEND_RUST);
    g_assert_false(cxl_type2_jit_load_policy(
        &state, (const uint8_t *)"wrong-backend", 13, &error));
    g_assert_cmpuint(state.last_error, ==, SLUG_JIT_ERR_UNSUPPORTED);
    assert_error_contains(g_steal_pointer(&error), "backend");
    cxl_type2_jit_close(&state);
}

static void test_strict_reject_drop_and_panic(void)
{
    const struct {
        const char *policy;
        uint32_t error_code;
        uint64_t reject_count;
        uint64_t drop_count;
    } cases[] = {
        { "reject", SLUG_JIT_ERR_REJECTED, 1, 0 },
        { "drop", SLUG_JIT_ERR_DROP, 0, 1 },
        { "panic", SLUG_JIT_ERR_PANIC, 0, 0 },
    };

    for (size_t i = 0; i < G_N_ELEMENTS(cases); i++) {
        CXLType2JitState state;
        CXLType2JitEvent event = valid_event();
        SlugJitDecision decision;
        Error *error = NULL;

        open_fake(&state, SLUG_JIT_BACKEND_RUST);
        load_fake_policy(&state, cases[i].policy);
        g_assert_false(cxl_type2_jit_observe_event(
            &state, &event, &decision, &error));
        g_assert_cmpuint(state.last_error, ==, cases[i].error_code);
        g_assert_cmpuint(state.status, ==, SLUG_JIT_STATUS_ERROR);
        g_assert_false(state.ready);
        g_assert_cmpuint(state.stats.reject_count, ==,
                         cases[i].reject_count);
        g_assert_cmpuint(state.stats.drop_count, ==, cases[i].drop_count);
        assert_error_contains(g_steal_pointer(&error), "JIT");
        cxl_type2_jit_close(&state);
    }
}

static void test_event_validation_and_diagnostic(void)
{
    CXLType2JitState state;
    CXLType2JitEvent event = valid_event();
    SlugJitDecision decision;
    g_autofree uint8_t *diagnostic = NULL;
    uint32_t required = 0;
    uint32_t written = 0;
    Error *error = NULL;

    open_fake(&state, SLUG_JIT_BACKEND_RUST);
    load_fake_policy(&state, "valid");
    event.payload[event.payload_len] = 9;
    g_assert_false(cxl_type2_jit_observe_event(
        &state, &event, &decision, &error));
    g_assert_cmpuint(state.next_event_id, ==, 0);
    g_assert_cmpuint(state.last_error, ==, SLUG_JIT_ERR_UNSUPPORTED);
    g_assert_cmpuint(state.status, ==, SLUG_JIT_STATUS_ERROR);
    g_assert_false(state.ready);
    assert_error_contains(g_steal_pointer(&error), "payload");
    cxl_type2_jit_close(&state);

    open_fake(&state, SLUG_JIT_BACKEND_RUST);
    load_fake_policy(&state, "drop");
    event = valid_event();
    g_assert_false(cxl_type2_jit_observe_event(
        &state, &event, &decision, &error));
    error_free(g_steal_pointer(&error));

    g_assert_true(cxl_type2_jit_copy_diagnostic(
        &state, NULL, 0, &required, &error));
    g_assert_null(error);
    g_assert_cmpuint(required, >, 0);
    g_assert_false(cxl_type2_jit_copy_diagnostic(
        &state, NULL, 1, &written, &error));
    assert_error_contains(g_steal_pointer(&error), "null");
    diagnostic = g_malloc(required);
    g_assert_true(cxl_type2_jit_copy_diagnostic(
        &state, diagnostic, required, &written, &error));
    g_assert_null(error);
    g_assert_cmpuint(written, ==, required);
    g_assert_nonnull(g_strstr_len((const char *)diagnostic, written, "drop"));
    cxl_type2_jit_close(&state);
}

static void test_policy_file_and_jsonl(void)
{
    g_autofree char *directory = g_dir_make_tmp("slugarch-jit-test-XXXXXX",
                                                 NULL);
    g_autofree char *policy_path = NULL;
    g_autofree char *log_path = NULL;
    g_autofree char *jsonl = NULL;
    CXLType2JitState state;
    CXLType2JitEvent event = valid_event();
    SlugJitDecision decision;
    Error *error = NULL;

    g_assert_nonnull(directory);
    policy_path = g_build_filename(directory, "policy.json", NULL);
    log_path = g_build_filename(directory, "events.jsonl", NULL);
    g_assert_true(g_file_set_contents(policy_path, "valid", -1, NULL));

    open_fake(&state, SLUG_JIT_BACKEND_RUST);
    g_assert_false(cxl_type2_jit_load_policy_file(
        &state, "relative-policy", &error));
    assert_error_contains(g_steal_pointer(&error), "absolute");
    g_assert_true(cxl_type2_jit_load_policy_file(
        &state, policy_path, &error));
    g_assert_null(error);
    g_assert_cmpstr(state.policy_path, ==, policy_path);

    g_assert_false(cxl_type2_jit_open_log(
        &state, "relative-log", &error));
    assert_error_contains(g_steal_pointer(&error), "absolute");
    g_assert_true(cxl_type2_jit_open_log(&state, log_path, &error));
    g_assert_null(error);
    g_assert_true(cxl_type2_jit_observe_event(
        &state, &event, &decision, &error));
    g_assert_null(error);
    cxl_type2_jit_close(&state);

    g_assert_true(g_file_get_contents(log_path, &jsonl, NULL, NULL));
    g_assert_nonnull(strstr(jsonl, "\"event_id\":1"));
    g_assert_nonnull(strstr(jsonl, "\"client_id\":17"));
    g_assert_nonnull(strstr(jsonl, "\"policy_digest\":\"a5a5"));
    g_assert_nonnull(strstr(jsonl, "\"effective_error\":0"));
    g_assert_nonnull(strstr(jsonl, "\"record_count\":1"));

    g_remove(log_path);
    g_remove(policy_path);
    g_rmdir(directory);
}

static unsigned int fd_count(void)
{
    g_autoptr(GDir) directory = g_dir_open("/proc/self/fd", 0, NULL);
    unsigned int count = 0;

    g_assert_nonnull(directory);
    while (g_dir_read_name(directory)) {
        count++;
    }
    return count;
}

static void test_repeated_open_close_has_no_fd_growth(void)
{
    unsigned int before = fd_count();

    for (unsigned int i = 0; i < 32; i++) {
        CXLType2JitState state;

        open_fake(&state, SLUG_JIT_BACKEND_RUST);
        load_fake_policy(&state, "valid");
        cxl_type2_jit_close(&state);
    }
    g_assert_cmpuint(fd_count(), ==, before);
}

static void test_real_runtime(const char *environment, uint32_t backend)
{
    const char *library = g_getenv(environment);
    g_autofree char *skip_reason = NULL;
    CXLType2JitState state;
    CXLType2JitEvent event = valid_event();
    SlugJitDecision decision;
    Error *error = NULL;

    if (!library) {
        skip_reason = g_strdup_printf("%s is not set", environment);
        g_test_skip(skip_reason);
        return;
    }

    cxl_type2_jit_state_init(&state, backend, true, 256);
    g_assert_true(cxl_type2_jit_open(&state, library, &error));
    g_assert_null(error);
    g_assert_true(cxl_type2_jit_load_policy(
        &state, (const uint8_t *)real_policy, strlen(real_policy), &error));
    g_assert_null(error);
    g_assert_true(cxl_type2_jit_observe_event(
        &state, &event, &decision, &error));
    g_assert_null(error);
    g_assert_cmpuint(decision.accepted, ==, 1);
    g_assert_cmpuint(decision.emitted, ==, 1);
    g_assert_cmpuint(state.stats.event_count, ==, 1);
    g_assert_cmpuint(state.stats.record_count, ==, 1);
    g_assert_cmpuint(state.stats.drop_count, ==, 0);
    g_assert_cmpuint(state.stats.epoch, ==, event.phase_id);
    cxl_type2_jit_close(&state);
}

static void test_real_rust_runtime(void)
{
    test_real_runtime("SLUGARCH_JIT_REAL_LIBRARY",
                      SLUG_JIT_BACKEND_RUST);
}

static void test_real_fpga_runtime(void)
{
    test_real_runtime("SLUGARCH_JIT_REAL_FPGA_LIBRARY",
                      SLUG_JIT_BACKEND_FPGA_VERILATOR);
}

static void test_real_library_rejects_unavailable_fpga(void)
{
    const char *library =
        g_getenv("SLUGARCH_JIT_REAL_NO_FPGA_LIBRARY");
    CXLType2JitState state;
    Error *error = NULL;

    if (!library) {
        g_test_skip("SLUGARCH_JIT_REAL_NO_FPGA_LIBRARY is not set");
        return;
    }

    cxl_type2_jit_state_init(
        &state, SLUG_JIT_BACKEND_FPGA_VERILATOR, true, 256);
    g_assert_false(cxl_type2_jit_open(&state, library, &error));
    assert_error_contains(g_steal_pointer(&error),
                          "lacks required capabilities");
    g_assert_null(state.library);
    g_assert_null(state.handle);
    g_assert_cmpuint(state.status, ==, SLUG_JIT_STATUS_OFF);
    cxl_type2_jit_close(&state);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/cxl/type2/jit/open-load-observe-close",
                    test_open_load_observe_close);
    g_test_add_func("/cxl/type2/jit/loader-rejections",
                    test_loader_rejections);
    g_test_add_func("/cxl/type2/jit/policy-rejections",
                    test_policy_rejections_are_fail_closed);
    g_test_add_func("/cxl/type2/jit/strict-errors",
                    test_strict_reject_drop_and_panic);
    g_test_add_func("/cxl/type2/jit/event-diagnostic",
                    test_event_validation_and_diagnostic);
    g_test_add_func("/cxl/type2/jit/policy-file-jsonl",
                    test_policy_file_and_jsonl);
    g_test_add_func("/cxl/type2/jit/fd-stability",
                    test_repeated_open_close_has_no_fd_growth);
    g_test_add_func("/cxl/type2/jit/real-rust-runtime",
                    test_real_rust_runtime);
    g_test_add_func("/cxl/type2/jit/real-fpga-runtime",
                    test_real_fpga_runtime);
    g_test_add_func("/cxl/type2/jit/real-no-fpga-fails-closed",
                    test_real_library_rejects_unavailable_fpga);
    return g_test_run();
}
