defmodule SSLTester.Server do
  @moduledoc """
  Simple TLS server taken from `X509.Test.Server`
  """
  use GenServer

  @doc """
  Starts a test server for the given test suite.
  ## Options:
  * `:port` - the TCP port to listen on; defaults to 0, meaning an ephemeral
    port is selected by the operating system, which may be retrieved using
    `get_port/1`
  * `:response` - the data to send back to clients when a successful connection
    is established (default: "OK")
  """
  @spec start_link(Keyword.t()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Returns the TCP port number on which the specified X509.Test.Server instance
  is listening.
  """
  @spec get_port(pid()) :: :inet.port_number()
  def get_port(pid) do
    GenServer.call(pid, :get_port)
  end

  # Callbacks

  defmodule State do
    @moduledoc false
    defstruct [:listen_socket, :port, :ssl_opts, :response]
  end

  @impl true
  def init(opts) do
    port = Keyword.get(opts, :port, 0)
    response = Keyword.get(opts, :response, "OK")
    ssl_opts = Keyword.fetch!(opts, :ssl_opts)

    with {:ok, listen_socket} <- :gen_tcp.listen(port, reuseaddr: true),
         {:ok, {_, port}} <- :inet.sockname(listen_socket),
         {:ok, _} <- :prim_inet.async_accept(listen_socket, -1) do
      {:ok,
       %State{listen_socket: listen_socket, port: port, ssl_opts: ssl_opts, response: response}}
    else
      error ->
        {:stop, error}
    end
  end

  @impl true
  def handle_call(:get_port, _from, %State{port: port} = state) do
    {:reply, port, state}
  end

  @impl true
  def handle_info({:inet_async, listen_socket, _ref, {:ok, socket}}, state) do
    :inet_db.register_socket(socket, :inet_tcp)

    pid =
      spawn_link(fn ->
        receive do
          :start -> worker(socket, state.ssl_opts, state.response)
        after
          250 -> :gen_tcp.close(socket)
        end
      end)

    _ = :gen_tcp.controlling_process(socket, pid)
    send(pid, :start)
    {:ok, _} = :prim_inet.async_accept(listen_socket, -1)
    {:noreply, state}
  end

  defp worker(socket, ssl_opts, response) do
    case :ssl.ssl_accept(
           socket,
           [
             active: false,
             reuse_sessions: false
           ] ++ ssl_opts ++ log_opts(),
           1278
         ) do
      {:ok, ssl_socket} ->
        flush(ssl_socket)
        _ = :ssl.send(ssl_socket, response)
        :ssl.close(ssl_socket)

      {:error, reason} ->
        IO.puts("Closed socket: #{inspect(reason)}")
        :gen_tcp.close(socket)
    end
  end

  defp flush(ssl_socket) do
    case :ssl.recv(ssl_socket, 0, 100) do
      {:ok, _data} ->
        flush(ssl_socket)

      _done ->
        :done
    end
  end

  def log_opts do
    if version(:ssl) >= [9, 3] do
      [log_level: :emergency]
    else
      [log_alert: false]
    end
  end

  defp version(application) do
    application
    |> Application.spec()
    |> Keyword.get(:vsn)
    |> to_string()
    |> String.split(".")
    |> Enum.map(&String.to_integer/1)
  end
end
