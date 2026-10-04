defmodule KpqCKATTest do
  use ExUnit.Case, async: false

  alias KpqC.Native
  alias __MODULE__.CTRDRBG

  @moduletag timeout: :infinity
  @vector_root System.get_env("KPQC_TEST_VECTORS") || "../kpqc-test-vectors"

  @signature_configs [
    {KpqC.aimer128f(), "aimer/128f", false, 16},
    {KpqC.aimer128s(), "aimer/128s", false, 16},
    {KpqC.aimer192f(), "aimer/192f", false, 24},
    {KpqC.aimer192s(), "aimer/192s", false, 24},
    {KpqC.aimer256f(), "aimer/256f", false, 32},
    {KpqC.aimer256s(), "aimer/256s", false, 32},
    {KpqC.haetae2(), "haetae/mode2", true, 32},
    {KpqC.haetae3(), "haetae/mode3", true, 32},
    {KpqC.haetae5(), "haetae/mode5", true, 32}
  ]

  @kem_configs [
    {KpqC.ntruplus768(), "ntruplus/768", 0, 96},
    {KpqC.ntruplus864(), "ntruplus/864", 0, 108},
    {KpqC.ntruplus1152(), "ntruplus/1152", 0, 144},
    {KpqC.smaugt128(), "smaugt/mode1", 2, 32},
    {KpqC.smaugt192(), "smaugt/mode3", 2, 32},
    {KpqC.smaugt256(), "smaugt/mode5", 2, 32},
    {KpqC.timer(), "smaugt/modet", 2, 16}
  ]

  def kat_configs, do: {@signature_configs, @kem_configs}

  if System.get_env("KPQC_TEST_ENTROPY") == "1" do
    test "all 1,600 known-answer vectors match exactly" do
      assert File.dir?(@vector_root),
             "KPQC_TEST_VECTORS does not point to the kpqc-test-vectors repository"

      {signature_configs, kem_configs} = kat_configs()

      signature_count =
        Enum.reduce(signature_configs, 0, fn config, total ->
          total + check_signature_vectors(config)
        end)

      kem_count =
        Enum.reduce(kem_configs, 0, fn config, total ->
          total + check_kem_vectors(config)
        end)

      assert signature_count + kem_count == 1600
    end

    test "deterministic entropy exhaustion is reported" do
      algorithm = KpqC.aimer128f()
      assert :ok = Native.kat_set_entropy(algorithm.id, <<>>)
      assert {:error, {:native_error, :keypair, _status}} = KpqC.generate_key_pair(algorithm)
      assert {:ok, 0} = Native.kat_clear_entropy(algorithm.id)
    end
  else
    @tag skip: "set KPQC_TEST_ENTROPY=1 and rebuild to run known-answer tests"
    test "known-answer vectors" do
      :ok
    end
  end

  def check_signature_vectors({algorithm, relative_path, haetae?, seed_bytes}) do
    vectors = read_vectors(Path.join([@vector_root, relative_path, "kat.rsp"]))
    assert length(vectors) == 100, "#{algorithm.name} must contain 100 vectors"

    Enum.each(vectors, fn vector ->
      drbg = CTRDRBG.new!(field!(vector, "seed"))

      {key_result, drbg} =
        if haetae? do
          {entropy, drbg} = CTRDRBG.generate(drbg, seed_bytes)

          {with_exact_entropy(algorithm, entropy, fn -> KpqC.generate_key_pair(algorithm) end),
           drbg}
        else
          with_repeated_entropy(
            algorithm,
            drbg,
            seed_bytes,
            128,
            fn -> KpqC.generate_key_pair(algorithm) end
          )
        end

      assert {:ok, keys} = key_result
      assert_field!(algorithm, vector, "pk", keys.public_key)
      assert_field!(algorithm, vector, "sk", keys.secret_key)

      message = field!(vector, "msg")

      expected_signature =
        case Map.fetch(vector, "sig") do
          {:ok, signature} ->
            decode_hex!(signature)

          :error ->
            binary_part(field!(vector, "sm"), byte_size(message), algorithm.signature_bytes)
        end

      {signing_entropy, drbg} = CTRDRBG.generate(drbg, seed_bytes)

      {context, _drbg} =
        if haetae? do
          {length_byte, drbg} = CTRDRBG.generate(drbg, 1)
          <<context_length>> = length_byte
          CTRDRBG.generate(drbg, context_length)
        else
          {<<>>, drbg}
        end

      assert {:ok, signature} =
               with_exact_entropy(algorithm, signing_entropy, fn ->
                 KpqC.sign(algorithm, message, keys.secret_key, context)
               end)

      assert signature == expected_signature,
             "#{algorithm.name} vector #{vector["count"]} produced the wrong signature"

      assert {:ok, true} =
               KpqC.verify(algorithm, message, expected_signature, field!(vector, "pk"), context)
    end)

    length(vectors)
  end

  def check_kem_vectors({algorithm, relative_path, key_calls, encapsulation_bytes}) do
    vectors = read_vectors(Path.join([@vector_root, relative_path, "kat.rsp"]))
    assert length(vectors) == 100, "#{algorithm.name} must contain 100 vectors"

    Enum.each(vectors, fn vector ->
      drbg = CTRDRBG.new!(field!(vector, "seed"))

      {key_result, drbg} =
        if key_calls == 0 do
          with_repeated_entropy(algorithm, drbg, 32, 128, fn ->
            KpqC.generate_key_pair(algorithm)
          end)
        else
          {chunks, drbg} = CTRDRBG.generate_many(drbg, key_calls, 32)
          entropy = IO.iodata_to_binary(chunks)

          {with_exact_entropy(algorithm, entropy, fn -> KpqC.generate_key_pair(algorithm) end),
           drbg}
        end

      assert {:ok, keys} = key_result
      assert_field!(algorithm, vector, "pk", keys.public_key)
      assert_field!(algorithm, vector, "sk", keys.secret_key)

      {entropy, _drbg} = CTRDRBG.generate(drbg, encapsulation_bytes)

      assert {:ok, encapsulated} =
               with_exact_entropy(algorithm, entropy, fn ->
                 KpqC.encapsulate(algorithm, keys.public_key)
               end)

      assert_field!(algorithm, vector, "ct", encapsulated.ciphertext)
      assert_field!(algorithm, vector, "ss", encapsulated.shared_secret)

      assert {:ok, secret} =
               KpqC.decapsulate(algorithm, encapsulated.ciphertext, keys.secret_key)

      assert secret == field!(vector, "ss"),
             "#{algorithm.name} vector #{vector["count"]} produced the wrong shared secret"
    end)

    length(vectors)
  end

  def with_exact_entropy(algorithm, entropy, operation) do
    assert :ok = Native.kat_set_entropy(algorithm.id, entropy)
    result = operation.()
    assert {:ok, 0} = Native.kat_clear_entropy(algorithm.id)
    result
  end

  def with_repeated_entropy(algorithm, drbg, call_bytes, max_calls, operation) do
    {chunks, _probe} = CTRDRBG.generate_many(drbg, max_calls, call_bytes)
    entropy = IO.iodata_to_binary(chunks)
    assert :ok = Native.kat_set_entropy(algorithm.id, entropy)
    result = operation.()
    assert {:ok, remaining} = Native.kat_clear_entropy(algorithm.id)
    consumed = byte_size(entropy) - remaining
    assert consumed > 0
    assert rem(consumed, call_bytes) == 0
    {_discarded, drbg} = CTRDRBG.generate_many(drbg, div(consumed, call_bytes), call_bytes)
    {result, drbg}
  end

  def assert_field!(algorithm, vector, name, actual) do
    assert actual == field!(vector, name),
           "#{algorithm.name} vector #{vector["count"]} produced the wrong #{name}"
  end

  def read_vectors(path) do
    path
    |> File.stream!()
    |> Enum.reduce({[], %{}}, fn line, {vectors, current} ->
      case String.split(String.trim(line), " = ", parts: 2) do
        ["count", value] when map_size(current) > 0 ->
          {[current | vectors], %{"count" => value}}

        [name, value] ->
          {vectors, Map.put(current, name, value)}

        _ ->
          {vectors, current}
      end
    end)
    |> then(fn {vectors, current} -> Enum.reverse([current | vectors]) end)
  end

  def field!(vector, name), do: vector |> Map.fetch!(name) |> decode_hex!()
  def decode_hex!(value), do: Base.decode16!(value, case: :mixed)

  defmodule CTRDRBG do
    import Bitwise

    defstruct key: <<0::256>>, counter: <<0::128>>

    def new!(entropy) when byte_size(entropy) == 48 do
      update(%__MODULE__{}, entropy)
    end

    def generate(state, length) do
      blocks = div(length + 15, 16)

      {output, state} =
        Enum.reduce(1..blocks//1, {[], state}, fn _, {output, state} ->
          state = increment(state)
          encrypted = :crypto.crypto_one_time(:aes_256_ecb, state.key, state.counter, true)
          {[encrypted | output], state}
        end)

      result = output |> Enum.reverse() |> IO.iodata_to_binary() |> binary_part(0, length)
      {result, update(state, <<>>)}
    end

    def generate_many(state, count, bytes) do
      Enum.reduce(1..count//1, {[], state}, fn _, {chunks, state} ->
        {chunk, state} = generate(state, bytes)
        {[chunk | chunks], state}
      end)
      |> then(fn {chunks, state} -> {Enum.reverse(chunks), state} end)
    end

    defp update(state, provided) do
      {material, state} =
        Enum.reduce(1..3, {[], state}, fn _, {blocks, state} ->
          state = increment(state)
          encrypted = :crypto.crypto_one_time(:aes_256_ecb, state.key, state.counter, true)
          {[encrypted | blocks], state}
        end)

      material = material |> Enum.reverse() |> IO.iodata_to_binary()
      padded = provided <> :binary.copy(<<0>>, 48 - byte_size(provided))
      <<key::binary-size(32), counter::binary-size(16)>> = :crypto.exor(material, padded)
      %{state | key: key, counter: counter}
    end

    defp increment(state) do
      value = rem(:binary.decode_unsigned(state.counter) + 1, 1 <<< 128)
      %{state | counter: <<value::unsigned-big-size(128)>>}
    end
  end
end
