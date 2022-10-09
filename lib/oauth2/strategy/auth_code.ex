defmodule OAuth2.Strategy.AuthCode do
  @moduledoc """
  The Authorization Code Strategy.

  http://tools.ietf.org/html/rfc6749#section-1.3.1

  The authorization code is obtained by using an authorization server
  as an intermediary between the client and resource owner.  Instead of
  requesting authorization directly from the resource owner, the client
  directs the resource owner to an authorization server (via its
  user-agent as defined in [RFC2616]), which in turn directs the
  resource owner back to the client with the authorization code.

  Before directing the resource owner back to the client with the
  authorization code, the authorization server authenticates the
  resource owner and obtains authorization.  Because the resource owner
  only authenticates with the authorization server, the resource
  owner's credentials are never shared with the client.

  The authorization code provides a few important security benefits,
  such as the ability to authenticate the client, as well as the
  transmission of the access token directly to the client without
  passing it through the resource owner's user-agent and potentially
  exposing it to others, including the resource owner.
  """

  use OAuth2.Strategy

  @pkce_code_bytes 32
  @pkce_code_length 43

  @doc """
  The authorization URL endpoint of the provider.
  params additional query parameters for the URL
  """
  @impl true
  def authorize_url(client, params) do
    client
    |> put_param(:response_type, "code")
    |> put_param(:client_id, client.client_id)
    |> put_param(:redirect_uri, client.redirect_uri)
    |> handle_authorization_pkce()
    |> merge_params(params)
  end

  @doc """
  Retrieve an access token given the specified validation code.
  """
  @impl true
  def get_token(client, params, headers) do
    {code, params} = Keyword.pop(params, :code, client.params["code"])

    unless code do
      raise OAuth2.Error, reason: "Missing required key `code` for `#{inspect(__MODULE__)}`"
    end

    client
    |> put_param(:code, code)
    |> put_param(:grant_type, "authorization_code")
    |> put_param(:client_id, client.client_id)
    |> put_param(:redirect_uri, client.redirect_uri)
    |> handle_token_pkce()
    |> merge_params(params)
    |> basic_auth()
    |> put_headers(headers)
  end

  defp handle_authorization_pkce(client) do
    if client.pkce do
      verifier = pkce_code_verifier()

      client
      |> put_private(:code_verifier, verifier)
      |> put_param(:code_challenge, pkce_challenge_from_verifier(verifier))
      |> put_param(:code_challenge_method, "S256")
    else
      client
    end
  end

  defp handle_token_pkce(client) do
    if client.pkce do
      client
      |> delete_param(:code_challenge)
      |> delete_param(:code_challenge_method)
      |> put_param_from_private(:code_verifier)
    else
      client
    end
  end

  defp pkce_code_verifier() do
    @pkce_code_bytes
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64()
    |> binary_part(0, @pkce_code_length)
  end

  defp pkce_challenge_from_verifier(verifier) do
    verifier
    |> then(& :crypto.hash(:sha256, &1))
    |> Base.url_encode64()
  end
end
