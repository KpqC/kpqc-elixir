defmodule KpqCTest do
  use ExUnit.Case, async: false
  @moduletag timeout: :infinity

  alias KpqC.{Algorithm, EncapsulatedSecret, KeyPair}

  test "the complete algorithm registry is exposed" do
    assert length(KpqC.signature_algorithms()) == 9
    assert length(KpqC.kem_algorithms()) == 7
    assert length(KpqC.algorithms()) == 16
    assert Enum.uniq_by(KpqC.algorithms(), & &1.id) == KpqC.algorithms()
    assert KpqC.aimer128f().signature_bytes == 6944
    assert KpqC.ntruplus1152().ciphertext_bytes == 1728
    assert KpqC.timer().name == "TiMER"
  end

  test "all signature algorithms generate, sign, and verify" do
    message = "KpqC Elixir"
    context = "release"

    for algorithm <- KpqC.signature_algorithms() do
      assert {:ok, %KeyPair{} = keys} = KpqC.generate_key_pair(algorithm)
      assert byte_size(keys.public_key) == algorithm.public_key_bytes
      assert byte_size(keys.secret_key) == algorithm.secret_key_bytes

      assert {:ok, signature} = KpqC.sign(algorithm, message, keys.secret_key, context)
      assert byte_size(signature) == algorithm.signature_bytes

      assert {:ok, true} =
               KpqC.verify(algorithm, message, signature, keys.public_key, context)

      assert {:ok, false} =
               KpqC.verify(
                 algorithm,
                 message,
                 flip_first(signature),
                 keys.public_key,
                 context
               )

      assert {:ok, false} =
               KpqC.verify(algorithm, message <> "!", signature, keys.public_key, context)

      assert {:ok, false} =
               KpqC.verify(algorithm, message, signature, keys.public_key, "wrong")

      assert {:ok, false} = KpqC.verify(algorithm, message, <<0>>, keys.public_key)
    end
  end

  test "all KEM algorithms encapsulate and decapsulate" do
    for algorithm <- KpqC.kem_algorithms() do
      assert {:ok, %KeyPair{} = keys} = KpqC.generate_key_pair(algorithm)
      assert byte_size(keys.public_key) == algorithm.public_key_bytes
      assert byte_size(keys.secret_key) == algorithm.secret_key_bytes

      assert {:ok, %EncapsulatedSecret{} = outbound} =
               KpqC.encapsulate(algorithm, keys.public_key)

      assert byte_size(outbound.ciphertext) == algorithm.ciphertext_bytes
      assert byte_size(outbound.shared_secret) == algorithm.shared_secret_bytes

      assert {:ok, inbound} =
               KpqC.decapsulate(algorithm, outbound.ciphertext, keys.secret_key)

      assert inbound == outbound.shared_secret

      case KpqC.decapsulate(algorithm, flip_first(outbound.ciphertext), keys.secret_key) do
        {:error, {:native_error, :decapsulate, _status}}
        when algorithm.id in [:ntruplus768, :ntruplus864, :ntruplus1152] ->
          :ok

        {:ok, replacement} when algorithm.id in [:smaugt128, :smaugt192, :smaugt256, :timer] ->
          assert byte_size(replacement) == algorithm.shared_secret_bytes
          refute replacement == outbound.shared_secret

        result ->
          flunk("unexpected rejection result for #{algorithm.name}: #{inspect(result)}")
      end
    end
  end

  test "public APIs reject the wrong algorithm kind" do
    assert {:error, :wrong_algorithm_type} = KpqC.sign(KpqC.timer(), <<>>, <<>>)
    assert {:error, :wrong_algorithm_type} = KpqC.encapsulate(KpqC.haetae2(), <<>>)
  end

  test "public APIs validate types and sizes" do
    algorithm = KpqC.aimer128f()
    assert {:ok, keys} = KpqC.generate_key_pair(algorithm)

    assert {:error, {:invalid_type, :message, :binary}} =
             KpqC.sign(algorithm, [:not, :binary], keys.secret_key)

    assert {:error, {:invalid_type, :message, :binary}} =
             KpqC.verify(algorithm, [:not, :binary], [:not, :binary], keys.public_key)

    assert {:error, {:invalid_size, :secret_key, 48, 1}} =
             KpqC.sign(algorithm, <<>>, <<0>>)

    assert {:error, :context_too_long} =
             KpqC.sign(algorithm, <<>>, keys.secret_key, :binary.copy(<<0>>, 256))

    assert {:error, {:invalid_size, :public_key, 32, 1}} =
             KpqC.verify(algorithm, <<>>, <<>>, <<0>>)

    assert {:error, {:invalid_size, :public_key, 1152, 1}} =
             KpqC.encapsulate(KpqC.ntruplus768(), <<0>>)

    assert {:error, {:invalid_size, :ciphertext, 1152, 1}} =
             KpqC.decapsulate(KpqC.ntruplus768(), <<0>>, :binary.copy(<<0>>, 2336))

    assert {:error, :invalid_algorithm} =
             KpqC.generate_key_pair(%Algorithm{
               id: :unknown,
               name: "unknown",
               kind: :kem,
               public_key_bytes: 1,
               secret_key_bytes: 1
             })
  end

  test "NTRU+ rejects non-canonical public keys and ciphertexts" do
    algorithm = KpqC.ntruplus768()

    assert {:error, {:native_error, :encapsulate, _status}} =
             KpqC.encapsulate(algorithm, :binary.copy(<<255>>, algorithm.public_key_bytes))

    assert {:ok, keys} = KpqC.generate_key_pair(algorithm)

    assert {:error, {:native_error, :decapsulate, _status}} =
             KpqC.decapsulate(
               algorithm,
               :binary.copy(<<255>>, algorithm.ciphertext_bytes),
               keys.secret_key
             )
  end

  defp flip_first(<<first, rest::binary>>), do: <<Bitwise.bxor(first, 1), rest::binary>>
end
