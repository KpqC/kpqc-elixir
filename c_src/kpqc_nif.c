#include <erl_nif.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef int (*keypair_fn)(uint8_t *, uint8_t *);
typedef int (*sign_fn)(uint8_t *, uint64_t *, const uint8_t *, size_t,
                       const uint8_t *, size_t, const uint8_t *);
typedef int (*verify_fn)(const uint8_t *, size_t, const uint8_t *, size_t,
                         const uint8_t *, size_t, const uint8_t *);
typedef int (*encapsulate_fn)(uint8_t *, uint8_t *, const uint8_t *);
typedef int (*decapsulate_fn)(uint8_t *, const uint8_t *, const uint8_t *);

#if defined(KPQC_TEST_ENTROPY)
typedef int (*set_entropy_fn)(const uint8_t *, size_t);
typedef size_t (*remaining_entropy_fn)(void);
typedef void (*clear_entropy_fn)(void);
#endif

typedef enum {
    KPQC_SIGNATURE,
    KPQC_KEM
} kpqc_kind;

typedef struct {
    const char *id;
    ERL_NIF_TERM atom;
    kpqc_kind kind;
    size_t public_key_bytes;
    size_t secret_key_bytes;
    size_t output_bytes;
    size_t shared_secret_bytes;
    keypair_fn keypair;
    sign_fn sign;
    verify_fn verify;
    encapsulate_fn encapsulate;
    decapsulate_fn decapsulate;
#if defined(KPQC_TEST_ENTROPY)
    set_entropy_fn set_entropy;
    remaining_entropy_fn remaining_entropy;
    clear_entropy_fn clear_entropy;
#endif
} kpqc_algorithm;

#define DECLARE_SIGNATURE(prefix)                                             \
    int prefix##_keypair(uint8_t *, uint8_t *);                              \
    int prefix##_sign(uint8_t *, uint64_t *, const uint8_t *, size_t,         \
                      const uint8_t *, size_t, const uint8_t *);              \
    int prefix##_verify(const uint8_t *, size_t, const uint8_t *, size_t,     \
                        const uint8_t *, size_t, const uint8_t *);

#define DECLARE_KEM(prefix)                                                   \
    int prefix##_keypair(uint8_t *, uint8_t *);                              \
    int prefix##_encapsulate(uint8_t *, uint8_t *, const uint8_t *);          \
    int prefix##_decapsulate(uint8_t *, const uint8_t *, const uint8_t *);

#if defined(KPQC_TEST_ENTROPY)
#define DECLARE_ENTROPY(prefix)                                               \
    int prefix##_set_test_entropy(const uint8_t *, size_t);                  \
    size_t prefix##_test_entropy_remaining(void);                            \
    void prefix##_clear_test_entropy(void);
#else
#define DECLARE_ENTROPY(prefix)
#endif

#define DECLARE_SIG_ALGORITHM(prefix) DECLARE_SIGNATURE(prefix) DECLARE_ENTROPY(prefix)
#define DECLARE_KEM_ALGORITHM(prefix) DECLARE_KEM(prefix) DECLARE_ENTROPY(prefix)

DECLARE_SIG_ALGORITHM(kpqc_aimer128f)
DECLARE_SIG_ALGORITHM(kpqc_aimer128s)
DECLARE_SIG_ALGORITHM(kpqc_aimer192f)
DECLARE_SIG_ALGORITHM(kpqc_aimer192s)
DECLARE_SIG_ALGORITHM(kpqc_aimer256f)
DECLARE_SIG_ALGORITHM(kpqc_aimer256s)
DECLARE_SIG_ALGORITHM(kpqc_haetae2)
DECLARE_SIG_ALGORITHM(kpqc_haetae3)
DECLARE_SIG_ALGORITHM(kpqc_haetae5)
DECLARE_KEM_ALGORITHM(kpqc_ntruplus768)
DECLARE_KEM_ALGORITHM(kpqc_ntruplus864)
DECLARE_KEM_ALGORITHM(kpqc_ntruplus1152)
DECLARE_KEM_ALGORITHM(kpqc_smaugt128)
DECLARE_KEM_ALGORITHM(kpqc_smaugt192)
DECLARE_KEM_ALGORITHM(kpqc_smaugt256)
DECLARE_KEM_ALGORITHM(kpqc_timer)

#if defined(KPQC_TEST_ENTROPY)
#define ENTROPY_FIELDS(prefix)                                                \
    prefix##_set_test_entropy, prefix##_test_entropy_remaining,              \
        prefix##_clear_test_entropy
#else
#define ENTROPY_FIELDS(prefix)
#endif

#define SIG_ALGORITHM(name, prefix, pk, sk, sig)                              \
    {name, 0, KPQC_SIGNATURE, pk, sk, sig, 0, prefix##_keypair, prefix##_sign, \
     prefix##_verify, NULL, NULL, ENTROPY_FIELDS(prefix)}

#define KEM_ALGORITHM(name, prefix, pk, sk, ct, ss)                           \
    {name, 0, KPQC_KEM, pk, sk, ct, ss, prefix##_keypair, NULL, NULL,          \
     prefix##_encapsulate, prefix##_decapsulate, ENTROPY_FIELDS(prefix)}

static kpqc_algorithm algorithms[] = {
    SIG_ALGORITHM("aimer128f", kpqc_aimer128f, 32, 48, 6944),
    SIG_ALGORITHM("aimer128s", kpqc_aimer128s, 32, 48, 4704),
    SIG_ALGORITHM("aimer192f", kpqc_aimer192f, 48, 72, 15408),
    SIG_ALGORITHM("aimer192s", kpqc_aimer192s, 48, 72, 10320),
    SIG_ALGORITHM("aimer256f", kpqc_aimer256f, 64, 96, 31360),
    SIG_ALGORITHM("aimer256s", kpqc_aimer256s, 64, 96, 20224),
    SIG_ALGORITHM("haetae2", kpqc_haetae2, 992, 1408, 1474),
    SIG_ALGORITHM("haetae3", kpqc_haetae3, 1472, 2112, 2349),
    SIG_ALGORITHM("haetae5", kpqc_haetae5, 2080, 2752, 2948),
    KEM_ALGORITHM("ntruplus768", kpqc_ntruplus768, 1152, 2336, 1152, 32),
    KEM_ALGORITHM("ntruplus864", kpqc_ntruplus864, 1296, 2624, 1296, 32),
    KEM_ALGORITHM("ntruplus1152", kpqc_ntruplus1152, 1728, 3488, 1728, 32),
    KEM_ALGORITHM("smaugt128", kpqc_smaugt128, 672, 832, 672, 32),
    KEM_ALGORITHM("smaugt192", kpqc_smaugt192, 1088, 1312, 992, 32),
    KEM_ALGORITHM("smaugt256", kpqc_smaugt256, 1440, 1728, 1376, 32),
    KEM_ALGORITHM("timer", kpqc_timer, 672, 832, 608, 32),
};

static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_error;
static ERL_NIF_TERM atom_true;
static ERL_NIF_TERM atom_false;

static void secure_zero(void *pointer, size_t length) {
    volatile uint8_t *bytes = (volatile uint8_t *)pointer;
    while (length-- > 0) {
        *bytes++ = 0;
    }
}

static ERL_NIF_TERM error_atom(ErlNifEnv *env, const char *reason) {
    return enif_make_tuple2(env, atom_error, enif_make_atom(env, reason));
}

static ERL_NIF_TERM native_error(ErlNifEnv *env, const char *operation,
                                 int status) {
    ERL_NIF_TERM reason = enif_make_tuple3(
        env, enif_make_atom(env, "native_error"),
        enif_make_atom(env, operation), enif_make_int(env, status));
    return enif_make_tuple2(env, atom_error, reason);
}

static ERL_NIF_TERM invalid_size(ErlNifEnv *env, const char *field,
                                 size_t expected, size_t actual) {
    ERL_NIF_TERM reason = enif_make_tuple4(
        env, enif_make_atom(env, "invalid_size"), enif_make_atom(env, field),
        enif_make_uint64(env, (ErlNifUInt64)expected),
        enif_make_uint64(env, (ErlNifUInt64)actual));
    return enif_make_tuple2(env, atom_error, reason);
}

static kpqc_algorithm *find_algorithm(ERL_NIF_TERM term, kpqc_kind kind) {
    size_t count = sizeof(algorithms) / sizeof(algorithms[0]);
    for (size_t index = 0; index < count; index++) {
        if (algorithms[index].kind == kind &&
            enif_is_identical(term, algorithms[index].atom)) {
            return &algorithms[index];
        }
    }
    return NULL;
}

static ERL_NIF_TERM nif_keypair(ErlNifEnv *env, int argc,
                                const ERL_NIF_TERM argv[]) {
    (void)argc;
    kpqc_algorithm *algorithm = NULL;
    size_t count = sizeof(algorithms) / sizeof(algorithms[0]);
    for (size_t index = 0; index < count; index++) {
        if (enif_is_identical(argv[0], algorithms[index].atom)) {
            algorithm = &algorithms[index];
            break;
        }
    }
    if (algorithm == NULL) {
        return error_atom(env, "invalid_algorithm");
    }

    ErlNifBinary public_key;
    ErlNifBinary secret_key;
    if (!enif_alloc_binary(algorithm->public_key_bytes, &public_key)) {
        return error_atom(env, "allocation_failed");
    }
    if (!enif_alloc_binary(algorithm->secret_key_bytes, &secret_key)) {
        enif_release_binary(&public_key);
        return error_atom(env, "allocation_failed");
    }

    int status = algorithm->keypair(public_key.data, secret_key.data);
    if (status != 0) {
        secure_zero(public_key.data, public_key.size);
        secure_zero(secret_key.data, secret_key.size);
        enif_release_binary(&public_key);
        enif_release_binary(&secret_key);
        return native_error(env, "keypair", status);
    }

    ERL_NIF_TERM public_key_term = enif_make_binary(env, &public_key);
    ERL_NIF_TERM secret_key_term = enif_make_binary(env, &secret_key);
    return enif_make_tuple3(env, atom_ok, public_key_term, secret_key_term);
}

static ERL_NIF_TERM nif_sign(ErlNifEnv *env, int argc,
                             const ERL_NIF_TERM argv[]) {
    (void)argc;
    kpqc_algorithm *algorithm = find_algorithm(argv[0], KPQC_SIGNATURE);
    ErlNifBinary message;
    ErlNifBinary context;
    ErlNifBinary secret_key;
    if (algorithm == NULL) {
        return error_atom(env, "invalid_algorithm");
    }
    if (!enif_inspect_binary(env, argv[1], &message) ||
        !enif_inspect_binary(env, argv[2], &context) ||
        !enif_inspect_binary(env, argv[3], &secret_key)) {
        return enif_make_badarg(env);
    }
    if (secret_key.size != algorithm->secret_key_bytes) {
        return invalid_size(env, "secret_key", algorithm->secret_key_bytes,
                            secret_key.size);
    }
    if (context.size > 255) {
        return error_atom(env, "context_too_long");
    }

    ErlNifBinary signature;
    if (!enif_alloc_binary(algorithm->output_bytes, &signature)) {
        return error_atom(env, "allocation_failed");
    }
    uint64_t signature_len = 0;
    int status = algorithm->sign(
        signature.data, &signature_len, message.data, message.size,
        context.data, context.size, secret_key.data);
    if (status != 0 || signature_len != algorithm->output_bytes) {
        secure_zero(signature.data, signature.size);
        enif_release_binary(&signature);
        return native_error(env, "sign", status != 0 ? status : -1);
    }
    return enif_make_tuple2(env, atom_ok, enif_make_binary(env, &signature));
}

static ERL_NIF_TERM nif_verify(ErlNifEnv *env, int argc,
                               const ERL_NIF_TERM argv[]) {
    (void)argc;
    kpqc_algorithm *algorithm = find_algorithm(argv[0], KPQC_SIGNATURE);
    ErlNifBinary signature;
    ErlNifBinary message;
    ErlNifBinary context;
    ErlNifBinary public_key;
    if (algorithm == NULL) {
        return error_atom(env, "invalid_algorithm");
    }
    if (!enif_inspect_binary(env, argv[1], &signature) ||
        !enif_inspect_binary(env, argv[2], &message) ||
        !enif_inspect_binary(env, argv[3], &context) ||
        !enif_inspect_binary(env, argv[4], &public_key)) {
        return enif_make_badarg(env);
    }
    if (public_key.size != algorithm->public_key_bytes) {
        return invalid_size(env, "public_key", algorithm->public_key_bytes,
                            public_key.size);
    }
    if (context.size > 255) {
        return error_atom(env, "context_too_long");
    }
    if (signature.size != algorithm->output_bytes) {
        return enif_make_tuple2(env, atom_ok, atom_false);
    }

    int status = algorithm->verify(
        signature.data, signature.size, message.data, message.size,
        context.data, context.size, public_key.data);
    if (status == -2) {
        return native_error(env, "verify", status);
    }
    return enif_make_tuple2(env, atom_ok, status == 0 ? atom_true : atom_false);
}

static ERL_NIF_TERM nif_encapsulate(ErlNifEnv *env, int argc,
                                    const ERL_NIF_TERM argv[]) {
    (void)argc;
    kpqc_algorithm *algorithm = find_algorithm(argv[0], KPQC_KEM);
    ErlNifBinary public_key;
    if (algorithm == NULL) {
        return error_atom(env, "invalid_algorithm");
    }
    if (!enif_inspect_binary(env, argv[1], &public_key)) {
        return enif_make_badarg(env);
    }
    if (public_key.size != algorithm->public_key_bytes) {
        return invalid_size(env, "public_key", algorithm->public_key_bytes,
                            public_key.size);
    }

    ErlNifBinary ciphertext;
    ErlNifBinary shared_secret;
    if (!enif_alloc_binary(algorithm->output_bytes, &ciphertext)) {
        return error_atom(env, "allocation_failed");
    }
    if (!enif_alloc_binary(algorithm->shared_secret_bytes, &shared_secret)) {
        enif_release_binary(&ciphertext);
        return error_atom(env, "allocation_failed");
    }

    int status = algorithm->encapsulate(ciphertext.data, shared_secret.data,
                                        public_key.data);
    if (status != 0) {
        secure_zero(ciphertext.data, ciphertext.size);
        secure_zero(shared_secret.data, shared_secret.size);
        enif_release_binary(&ciphertext);
        enif_release_binary(&shared_secret);
        return native_error(env, "encapsulate", status);
    }
    return enif_make_tuple3(env, atom_ok, enif_make_binary(env, &ciphertext),
                            enif_make_binary(env, &shared_secret));
}

static ERL_NIF_TERM nif_decapsulate(ErlNifEnv *env, int argc,
                                    const ERL_NIF_TERM argv[]) {
    (void)argc;
    kpqc_algorithm *algorithm = find_algorithm(argv[0], KPQC_KEM);
    ErlNifBinary ciphertext;
    ErlNifBinary secret_key;
    if (algorithm == NULL) {
        return error_atom(env, "invalid_algorithm");
    }
    if (!enif_inspect_binary(env, argv[1], &ciphertext) ||
        !enif_inspect_binary(env, argv[2], &secret_key)) {
        return enif_make_badarg(env);
    }
    if (ciphertext.size != algorithm->output_bytes) {
        return invalid_size(env, "ciphertext", algorithm->output_bytes,
                            ciphertext.size);
    }
    if (secret_key.size != algorithm->secret_key_bytes) {
        return invalid_size(env, "secret_key", algorithm->secret_key_bytes,
                            secret_key.size);
    }

    ErlNifBinary shared_secret;
    if (!enif_alloc_binary(algorithm->shared_secret_bytes, &shared_secret)) {
        return error_atom(env, "allocation_failed");
    }
    int status = algorithm->decapsulate(shared_secret.data, ciphertext.data,
                                        secret_key.data);
    if (status != 0) {
        secure_zero(shared_secret.data, shared_secret.size);
        enif_release_binary(&shared_secret);
        return native_error(env, "decapsulate", status);
    }
    return enif_make_tuple2(env, atom_ok,
                            enif_make_binary(env, &shared_secret));
}

#if defined(KPQC_TEST_ENTROPY)
static ERL_NIF_TERM nif_kat_set_entropy(ErlNifEnv *env, int argc,
                                        const ERL_NIF_TERM argv[]) {
    (void)argc;
    ErlNifBinary entropy;
    kpqc_algorithm *algorithm = NULL;
    size_t count = sizeof(algorithms) / sizeof(algorithms[0]);
    for (size_t index = 0; index < count; index++) {
        if (enif_is_identical(argv[0], algorithms[index].atom)) {
            algorithm = &algorithms[index];
            break;
        }
    }
    if (algorithm == NULL) {
        return error_atom(env, "invalid_algorithm");
    }
    if (!enif_inspect_binary(env, argv[1], &entropy)) {
        return enif_make_badarg(env);
    }
    int status = algorithm->set_entropy(entropy.data, entropy.size);
    if (status != 0) {
        return native_error(env, "set_test_entropy", status);
    }
    return atom_ok;
}

static ERL_NIF_TERM nif_kat_clear_entropy(ErlNifEnv *env, int argc,
                                          const ERL_NIF_TERM argv[]) {
    (void)argc;
    size_t count = sizeof(algorithms) / sizeof(algorithms[0]);
    for (size_t index = 0; index < count; index++) {
        if (enif_is_identical(argv[0], algorithms[index].atom)) {
            size_t remaining = algorithms[index].remaining_entropy();
            algorithms[index].clear_entropy();
            return enif_make_tuple2(
                env, atom_ok,
                enif_make_uint64(env, (ErlNifUInt64)remaining));
        }
    }
    return error_atom(env, "invalid_algorithm");
}
#endif

static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info) {
    (void)priv_data;
    (void)load_info;
    atom_ok = enif_make_atom(env, "ok");
    atom_error = enif_make_atom(env, "error");
    atom_true = enif_make_atom(env, "true");
    atom_false = enif_make_atom(env, "false");

    size_t count = sizeof(algorithms) / sizeof(algorithms[0]);
    for (size_t index = 0; index < count; index++) {
        algorithms[index].atom = enif_make_atom(env, algorithms[index].id);
    }
    return 0;
}

static ErlNifFunc nif_functions[] = {
    {"keypair", 1, nif_keypair, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sign", 4, nif_sign, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"verify", 5, nif_verify, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"encapsulate", 2, nif_encapsulate, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"decapsulate", 3, nif_decapsulate, ERL_NIF_DIRTY_JOB_CPU_BOUND},
#if defined(KPQC_TEST_ENTROPY)
    {"kat_set_entropy", 2, nif_kat_set_entropy, 0},
    {"kat_clear_entropy", 1, nif_kat_clear_entropy, 0},
#endif
};

ERL_NIF_INIT(Elixir.KpqC.Native, nif_functions, load, NULL, NULL, NULL)
