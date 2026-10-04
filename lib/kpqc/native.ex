defmodule KpqC.Native do
  @moduledoc false

  @on_load :load_nif

  def load_nif do
    path = :kpqc |> :code.priv_dir() |> Path.join("kpqc_nif")
    :erlang.load_nif(String.to_charlist(path), 0)
  end

  def keypair(_algorithm), do: :erlang.nif_error(:nif_not_loaded)

  def sign(_algorithm, _message, _context, _secret_key),
    do: :erlang.nif_error(:nif_not_loaded)

  def verify(_algorithm, _signature, _message, _context, _public_key),
    do: :erlang.nif_error(:nif_not_loaded)

  def encapsulate(_algorithm, _public_key), do: :erlang.nif_error(:nif_not_loaded)

  def decapsulate(_algorithm, _ciphertext, _secret_key),
    do: :erlang.nif_error(:nif_not_loaded)

  def kat_set_entropy(_algorithm, _entropy), do: :erlang.nif_error(:nif_not_loaded)
  def kat_clear_entropy(_algorithm), do: :erlang.nif_error(:nif_not_loaded)
end
