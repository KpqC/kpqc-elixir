defmodule KpqC do
  @moduledoc """
  Synchronous Elixir APIs for the KpqC post-quantum signature and
  key encapsulation mechanisms (KEMs).

  Cryptographic work runs on BEAM dirty CPU schedulers through a bundled NIF.
  """

  alias KpqC.{Algorithm, EncapsulatedSecret, KeyPair, Native}

  @signature_algorithms [
    %Algorithm{
      id: :aimer128f,
      name: "AIMer-128f",
      kind: :signature,
      public_key_bytes: 32,
      secret_key_bytes: 48,
      signature_bytes: 6944
    },
    %Algorithm{
      id: :aimer128s,
      name: "AIMer-128s",
      kind: :signature,
      public_key_bytes: 32,
      secret_key_bytes: 48,
      signature_bytes: 4704
    },
    %Algorithm{
      id: :aimer192f,
      name: "AIMer-192f",
      kind: :signature,
      public_key_bytes: 48,
      secret_key_bytes: 72,
      signature_bytes: 15408
    },
    %Algorithm{
      id: :aimer192s,
      name: "AIMer-192s",
      kind: :signature,
      public_key_bytes: 48,
      secret_key_bytes: 72,
      signature_bytes: 10320
    },
    %Algorithm{
      id: :aimer256f,
      name: "AIMer-256f",
      kind: :signature,
      public_key_bytes: 64,
      secret_key_bytes: 96,
      signature_bytes: 31360
    },
    %Algorithm{
      id: :aimer256s,
      name: "AIMer-256s",
      kind: :signature,
      public_key_bytes: 64,
      secret_key_bytes: 96,
      signature_bytes: 20224
    },
    %Algorithm{
      id: :haetae2,
      name: "HAETAE-2",
      kind: :signature,
      public_key_bytes: 992,
      secret_key_bytes: 1408,
      signature_bytes: 1474
    },
    %Algorithm{
      id: :haetae3,
      name: "HAETAE-3",
      kind: :signature,
      public_key_bytes: 1472,
      secret_key_bytes: 2112,
      signature_bytes: 2349
    },
    %Algorithm{
      id: :haetae5,
      name: "HAETAE-5",
      kind: :signature,
      public_key_bytes: 2080,
      secret_key_bytes: 2752,
      signature_bytes: 2948
    }
  ]

  @kem_algorithms [
    %Algorithm{
      id: :ntruplus768,
      name: "NTRU+-768",
      kind: :kem,
      public_key_bytes: 1152,
      secret_key_bytes: 2336,
      ciphertext_bytes: 1152,
      shared_secret_bytes: 32
    },
    %Algorithm{
      id: :ntruplus864,
      name: "NTRU+-864",
      kind: :kem,
      public_key_bytes: 1296,
      secret_key_bytes: 2624,
      ciphertext_bytes: 1296,
      shared_secret_bytes: 32
    },
    %Algorithm{
      id: :ntruplus1152,
      name: "NTRU+-1152",
      kind: :kem,
      public_key_bytes: 1728,
      secret_key_bytes: 3488,
      ciphertext_bytes: 1728,
      shared_secret_bytes: 32
    },
    %Algorithm{
      id: :smaugt128,
      name: "SMAUG-T-128",
      kind: :kem,
      public_key_bytes: 672,
      secret_key_bytes: 832,
      ciphertext_bytes: 672,
      shared_secret_bytes: 32
    },
    %Algorithm{
      id: :smaugt192,
      name: "SMAUG-T-192",
      kind: :kem,
      public_key_bytes: 1088,
      secret_key_bytes: 1312,
      ciphertext_bytes: 992,
      shared_secret_bytes: 32
    },
    %Algorithm{
      id: :smaugt256,
      name: "SMAUG-T-256",
      kind: :kem,
      public_key_bytes: 1440,
      secret_key_bytes: 1728,
      ciphertext_bytes: 1376,
      shared_secret_bytes: 32
    },
    %Algorithm{
      id: :timer,
      name: "TiMER",
      kind: :kem,
      public_key_bytes: 672,
      secret_key_bytes: 832,
      ciphertext_bytes: 608,
      shared_secret_bytes: 32
    }
  ]

  @algorithms @signature_algorithms ++ @kem_algorithms
  @algorithms_by_id Map.new(@algorithms, &{&1.id, &1})

  @type error_reason ::
          :invalid_algorithm
          | :wrong_algorithm_type
          | :context_too_long
          | :allocation_failed
          | {:invalid_type, atom(), :binary}
          | {:invalid_size, atom(), non_neg_integer(), non_neg_integer()}
          | {:native_error, atom(), integer()}

  @type result(value) :: {:ok, value} | {:error, error_reason()}

  for algorithm <- @algorithms do
    @doc "Returns metadata for #{algorithm.name}."
    @spec unquote(algorithm.id)() :: Algorithm.t()
    def unquote(algorithm.id)(), do: unquote(Macro.escape(algorithm))
  end

  @doc "Returns all supported signature algorithms."
  @spec signature_algorithms() :: [Algorithm.t()]
  def signature_algorithms, do: @signature_algorithms

  @doc "Returns all supported KEM algorithms."
  @spec kem_algorithms() :: [Algorithm.t()]
  def kem_algorithms, do: @kem_algorithms

  @doc "Returns all supported algorithms."
  @spec algorithms() :: [Algorithm.t()]
  def algorithms, do: @algorithms

  @doc "Generates a key pair for a signature or KEM algorithm."
  @spec generate_key_pair(Algorithm.t()) :: result(KeyPair.t())
  def generate_key_pair(algorithm) do
    with {:ok, canonical} <- lookup_algorithm(algorithm) do
      case Native.keypair(canonical.id) do
        {:ok, public_key, secret_key} ->
          {:ok, %KeyPair{public_key: public_key, secret_key: secret_key}}

        {:error, _reason} = error ->
          error
      end
    end
  end

  @doc "Signs a message with an optional domain-separation context."
  @spec sign(Algorithm.t(), binary(), binary(), binary()) :: result(binary())
  def sign(algorithm, message, secret_key, context \\ <<>>) do
    with {:ok, canonical} <- lookup_algorithm(algorithm, :signature),
         :ok <- validate_binary(:message, message),
         :ok <- validate_binary(:secret_key, secret_key),
         :ok <- validate_binary(:context, context),
         :ok <- validate_size(:secret_key, secret_key, canonical.secret_key_bytes),
         :ok <- validate_context(context) do
      Native.sign(canonical.id, message, context, secret_key)
    end
  end

  @doc "Verifies a signature and returns `{:ok, true}` or `{:ok, false}`."
  @spec verify(Algorithm.t(), binary(), binary(), binary(), binary()) :: result(boolean())
  def verify(algorithm, message, signature, public_key, context \\ <<>>) do
    with {:ok, canonical} <- lookup_algorithm(algorithm, :signature),
         :ok <- validate_binary(:message, message),
         :ok <- validate_binary(:signature, signature),
         :ok <- validate_binary(:public_key, public_key),
         :ok <- validate_binary(:context, context),
         :ok <- validate_size(:public_key, public_key, canonical.public_key_bytes),
         :ok <- validate_context(context) do
      if byte_size(signature) == canonical.signature_bytes do
        Native.verify(canonical.id, signature, message, context, public_key)
      else
        {:ok, false}
      end
    end
  end

  @doc "Encapsulates a new shared secret to a public key."
  @spec encapsulate(Algorithm.t(), binary()) :: result(EncapsulatedSecret.t())
  def encapsulate(algorithm, public_key) do
    with {:ok, canonical} <- lookup_algorithm(algorithm, :kem),
         :ok <- validate_binary(:public_key, public_key),
         :ok <- validate_size(:public_key, public_key, canonical.public_key_bytes) do
      case Native.encapsulate(canonical.id, public_key) do
        {:ok, ciphertext, shared_secret} ->
          {:ok, %EncapsulatedSecret{ciphertext: ciphertext, shared_secret: shared_secret}}

        {:error, _reason} = error ->
          error
      end
    end
  end

  @doc "Decapsulates a shared secret from a ciphertext."
  @spec decapsulate(Algorithm.t(), binary(), binary()) :: result(binary())
  def decapsulate(algorithm, ciphertext, secret_key) do
    with {:ok, canonical} <- lookup_algorithm(algorithm, :kem),
         :ok <- validate_binary(:ciphertext, ciphertext),
         :ok <- validate_binary(:secret_key, secret_key),
         :ok <- validate_size(:ciphertext, ciphertext, canonical.ciphertext_bytes),
         :ok <- validate_size(:secret_key, secret_key, canonical.secret_key_bytes) do
      Native.decapsulate(canonical.id, ciphertext, secret_key)
    end
  end

  defp lookup_algorithm(%Algorithm{id: id}), do: lookup_id(id, nil)
  defp lookup_algorithm(_algorithm), do: {:error, :invalid_algorithm}

  defp lookup_algorithm(%Algorithm{id: id}, kind), do: lookup_id(id, kind)
  defp lookup_algorithm(_algorithm, _kind), do: {:error, :invalid_algorithm}

  defp lookup_id(id, kind) do
    case @algorithms_by_id do
      %{^id => %Algorithm{kind: ^kind} = algorithm} -> {:ok, algorithm}
      %{^id => %Algorithm{}} when not is_nil(kind) -> {:error, :wrong_algorithm_type}
      %{^id => %Algorithm{} = algorithm} -> {:ok, algorithm}
      _ -> {:error, :invalid_algorithm}
    end
  end

  defp validate_binary(_field, value) when is_binary(value), do: :ok
  defp validate_binary(field, _value), do: {:error, {:invalid_type, field, :binary}}

  defp validate_size(field, value, expected) do
    actual = byte_size(value)

    if actual == expected,
      do: :ok,
      else: {:error, {:invalid_size, field, expected, actual}}
  end

  defp validate_context(context) when byte_size(context) <= 255, do: :ok
  defp validate_context(_context), do: {:error, :context_too_long}
end
