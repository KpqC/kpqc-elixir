defmodule KpqC.KeyPair do
  @moduledoc "A generated public and secret key pair."

  @enforce_keys [:public_key, :secret_key]
  defstruct [:public_key, :secret_key]

  @type t :: %__MODULE__{public_key: binary(), secret_key: binary()}
end
