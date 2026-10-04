defmodule KpqC.EncapsulatedSecret do
  @moduledoc "A KEM ciphertext and its shared secret."

  @enforce_keys [:ciphertext, :shared_secret]
  defstruct [:ciphertext, :shared_secret]

  @type t :: %__MODULE__{ciphertext: binary(), shared_secret: binary()}
end
