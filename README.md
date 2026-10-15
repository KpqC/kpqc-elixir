# KpqC

KpqC provides synchronous Elixir APIs for the AIMer and HAETAE signature
schemes and the NTRU+ and SMAUG-T key encapsulation mechanisms (KEMs). Native
operations run on BEAM dirty CPU schedulers.

## Runtime support

- Elixir 1.14 or newer and Erlang/OTP 25 or newer
- `make` and a C11 compiler
- macOS or Linux

## Install

Add `kpqc` to the dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:kpqc, "~> 0.1.0"}
  ]
end
```

The package bundles its native algorithm sources and builds them locally. It
does not download native libraries during compilation.

## Available schemes

| Algorithm | Type | Accessors |
| --- | --- | --- |
| **AIMer** | Signature | `aimer128f/0`, `aimer128s/0`, `aimer192f/0`, `aimer192s/0`, `aimer256f/0`, `aimer256s/0` |
| **HAETAE** | Signature | `haetae2/0`, `haetae3/0`, `haetae5/0` |
| **NTRU+** | KEM | `ntruplus768/0`, `ntruplus864/0`, `ntruplus1152/0` |
| **SMAUG&#8209;T** | KEM | `smaugt128/0`, `smaugt192/0`, `smaugt256/0`, `timer/0` |

### Signatures

```elixir
algorithm = KpqC.aimer128f()
{:ok, keys} = KpqC.generate_key_pair(algorithm)

message = "release-manifest:v3"
{:ok, signature} = KpqC.sign(algorithm, message, keys.secret_key)
{:ok, true} = KpqC.verify(algorithm, message, signature, keys.public_key)
```

`sign/4` and `verify/5` accept an optional application context of at most 255
bytes. Verification fails if the supplied context differs from the signing
context.

### KEM

A KEM creates a shared secret for a sender and a recipient. The public key may
be distributed; the secret key and resulting shared secret must remain private.

```elixir
algorithm = KpqC.smaugt192()
{:ok, recipient} = KpqC.generate_key_pair(algorithm)
{:ok, outbound} = KpqC.encapsulate(algorithm, recipient.public_key)
{:ok, inbound_secret} =
  KpqC.decapsulate(algorithm, outbound.ciphertext, recipient.secret_key)

true = inbound_secret == outbound.shared_secret
```

## Data and failures

Keys, signatures, ciphertexts, messages, contexts, and shared secrets are
binaries. Successful operations return `{:ok, value}`; failures return
`{:error, reason}`. Invalid signatures return `{:ok, false}`.

NTRU+ rejects non-canonical public keys and invalid ciphertexts. SMAUG-T uses
implicit rejection and returns a replacement secret for an invalid
ciphertext; it will not equal the sender's shared secret.

### Parameter sizes

All sizes are in bytes.

#### Signatures

| Accessor | Public key | Secret key | Signature |
| --- | ---: | ---: | ---: |
| `aimer128f/0` | 32 | 48 | 6,944 |
| `aimer128s/0` | 32 | 48 | 4,704 |
| `aimer192f/0` | 48 | 72 | 15,408 |
| `aimer192s/0` | 48 | 72 | 10,320 |
| `aimer256f/0` | 64 | 96 | 31,360 |
| `aimer256s/0` | 64 | 96 | 20,224 |
| `haetae2/0` | 992 | 1,408 | 1,474 |
| `haetae3/0` | 1,472 | 2,112 | 2,349 |
| `haetae5/0` | 2,080 | 2,752 | 2,948 |

#### KEMs

| Accessor | Public key | Secret key | Ciphertext | Shared secret |
| --- | ---: | ---: | ---: | ---: |
| `ntruplus768/0` | 1,152 | 2,336 | 1,152 | 32 |
| `ntruplus864/0` | 1,296 | 2,624 | 1,296 | 32 |
| `ntruplus1152/0` | 1,728 | 3,488 | 1,728 | 32 |
| `smaugt128/0` | 672 | 832 | 672 | 32 |
| `smaugt192/0` | 1,088 | 1,312 | 992 | 32 |
| `smaugt256/0` | 1,440 | 1,728 | 1,376 | 32 |
| `timer/0` | 672 | 832 | 608 | 32 |

## Tests

```sh
mix test
```

The optional known-answer suite validates all 1,600 records from the pinned
[KpqC/kpqc-test-vectors at commit d75490bf824f](https://github.com/KpqC/kpqc-test-vectors/tree/d75490bf824faa4b148cd0b901a2eb13198fe0da).
Its deterministic entropy hooks are only compiled into this explicit test
build:

```sh
MIX_ENV=test \
KPQC_TEST_ENTROPY=1 \
KPQC_TEST_VECTORS=../kpqc-test-vectors \
mix do clean + test
```

Run `MIX_ENV=test mix do clean + test` without `KPQC_TEST_ENTROPY` afterward
to restore the normal NIF.

## Security

The native cores are compiled from the upstream reference implementations.
This package has not received an independent security audit and does not
guarantee constant-time execution. Assess those constraints before using it
with sensitive production keys.

Third-party licenses and attributions are listed in
[THIRD_PARTY_NOTICES.md](https://github.com/KpqC/kpqc-elixir/blob/main/THIRD_PARTY_NOTICES.md).
