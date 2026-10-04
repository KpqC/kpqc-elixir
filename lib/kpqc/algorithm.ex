defmodule KpqC.Algorithm do
  @moduledoc "Metadata for a supported KpqC algorithm."

  @enforce_keys [:id, :name, :kind, :public_key_bytes, :secret_key_bytes]
  defstruct [
    :id,
    :name,
    :kind,
    :public_key_bytes,
    :secret_key_bytes,
    :signature_bytes,
    :ciphertext_bytes,
    :shared_secret_bytes
  ]

  @type kind :: :signature | :kem

  @type t :: %__MODULE__{
          id: atom(),
          name: String.t(),
          kind: kind(),
          public_key_bytes: pos_integer(),
          secret_key_bytes: pos_integer(),
          signature_bytes: pos_integer() | nil,
          ciphertext_bytes: pos_integer() | nil,
          shared_secret_bytes: pos_integer() | nil
        }
end
