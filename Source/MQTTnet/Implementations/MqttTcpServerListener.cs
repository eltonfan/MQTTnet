#if !WINDOWS_UWP
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using MQTTnet.Adapter;
using MQTTnet.Diagnostics;
using MQTTnet.Serializer;
using MQTTnet.Server;

namespace MQTTnet.Implementations
{
    public class MqttTcpServerListener : IDisposable
    {
        private readonly IMqttNetChildLogger _logger;
        private readonly CancellationToken _cancellationToken;
        private readonly AddressFamily _addressFamily;
        private readonly TimeSpan _communicationTimeout;
        private readonly MqttServerTcpEndpointBaseOptions _options;
        private readonly MqttServerTlsTcpEndpointOptions _tlsOptions;
        private readonly X509Certificate2 _tlsCertificate;
        private Socket _socket;

        public MqttTcpServerListener(
            AddressFamily addressFamily,
            MqttServerTcpEndpointBaseOptions options,
            X509Certificate2 tlsCertificate,
            TimeSpan communicationTimeout,
            CancellationToken cancellationToken,
            IMqttNetChildLogger logger)
        {
            _addressFamily = addressFamily;
            _options = options;
            _tlsCertificate = tlsCertificate;
            _communicationTimeout = communicationTimeout;
            _cancellationToken = cancellationToken;
            _logger = logger.CreateChildLogger(nameof(MqttTcpServerListener));
            
            if (_options is MqttServerTlsTcpEndpointOptions tlsOptions)
            {
                _tlsOptions = tlsOptions;
            }
        }

        public event EventHandler<MqttServerAdapterClientAcceptedEventArgs> ClientAccepted;

        public void Start()
        {
            var boundIp = _options.BoundInterNetworkAddress;
            if (_addressFamily == AddressFamily.InterNetworkV6)
            {
                boundIp = _options.BoundInterNetworkV6Address;
            }

            _socket = new Socket(_addressFamily, SocketType.Stream, ProtocolType.Tcp);
            _socket.Bind(new IPEndPoint(boundIp, _options.Port));

            _logger.Info($"Starting TCP listener for {_socket.LocalEndPoint} TLS={_tlsCertificate != null}.");

            _socket.Listen(_options.ConnectionBacklog);
            Task.Run(AcceptClientConnectionsAsync, _cancellationToken);
        }

        long latestSocketIndex = 0;

        private async Task AcceptClientConnectionsAsync()
        {
            while (!_cancellationToken.IsCancellationRequested)
            {
                try
                {
#if NET452 || NET461
                    var clientSocket = await Task.Factory.FromAsync(_socket.BeginAccept, _socket.EndAccept, null).ConfigureAwait(false);
#else
                    var clientSocket = await _socket.AcceptAsync().ConfigureAwait(false);
#endif
#pragma warning disable 4014
                    Task.Run(() => TryHandleClientConnectionAsync(clientSocket), _cancellationToken);
#pragma warning restore 4014
                }
                catch (Exception exception)
                {
                    _logger.Error(exception, $"Error while accepting connection at TCP listener {_socket.LocalEndPoint} TLS={_tlsCertificate != null}.");
                    await Task.Delay(TimeSpan.FromSeconds(1), _cancellationToken).ConfigureAwait(false);
                }
            }
        }

        private async Task TryHandleClientConnectionAsync(Socket clientSocket)
        {
            var socketIndex = Interlocked.Increment(ref latestSocketIndex);

            string remoteEndPoint = null;
            string localEndPoint = null;
            SslStream sslStream = null;
            var stopwatch = new Stopwatch();
            try
            {
                stopwatch.Start();

                remoteEndPoint = clientSocket.RemoteEndPoint.ToString();
                localEndPoint = clientSocket.LocalEndPoint.ToString();

                _logger.Verbose("Client '{0}' accepted by TCP listener '{1}, {2}',  Socket[{3}]:{4}ms",
                    remoteEndPoint,
                    _socket.LocalEndPoint,
                    _addressFamily == AddressFamily.InterNetwork ? "ipv4" : "ipv6",
                    socketIndex, stopwatch.Elapsed.TotalMilliseconds);

                clientSocket.NoDelay = true;

                if (_tlsCertificate != null)
                {//如果不设置超时，AuthenticateAsServerAsync 可能会一直阻塞下去
                    clientSocket.ReceiveTimeout = (int)_communicationTimeout.TotalMilliseconds;
                    clientSocket.SendTimeout = (int)_communicationTimeout.TotalMilliseconds;

                    var stream = new NetworkStream(clientSocket, true);
                    sslStream = new SslStream(stream, false);

                    var cancellationTokenDisposeSslStream = new CancellationTokenSource();
                    var taskDisposeSslStream = Task.Delay(2000, cancellationTokenDisposeSslStream.Token)
                        .ContinueWith((task) =>
                        {
                            if (task.IsCanceled)
                                return;
                            if (cancellationTokenDisposeSslStream.IsCancellationRequested)
                                return;

                            //超时，则清理掉
                            Cleanup(clientSocket, sslStream);
                        });

                    await sslStream.AuthenticateAsServerAsync(_tlsCertificate, false, _tlsOptions.SslProtocol, false).ConfigureAwait(false);

                    cancellationTokenDisposeSslStream.Cancel();

                    _logger.Verbose("Client '{0}' SslStream created. Socket[{1}]:{2}ms",
                        clientSocket.RemoteEndPoint,
                        socketIndex, stopwatch.Elapsed.TotalMilliseconds);
                }

                if (ClientAccepted != null)
                {
                    using (var clientAdapter = new MqttChannelAdapter(new MqttTcpChannel(clientSocket, sslStream), new MqttPacketSerializer(), _logger))
                    {
                        var args = new MqttServerAdapterClientAcceptedEventArgs(clientAdapter);
                        ClientAccepted.Invoke(this, args);
                        await args.SessionTask.ConfigureAwait(false);
                    }
                }

                _logger.Verbose("Client '{0}' processed. Socket[{1}]:{2}ms",
                    clientSocket.RemoteEndPoint,
                    socketIndex, stopwatch.Elapsed.TotalMilliseconds);
            }
            catch (ObjectDisposedException exception)
            {
                // It can happen that the listener socket is accessed after the cancellation token is already set and the listener socket is disposed.
                _logger.Error(exception, $"Error while handling client connection. Client[{socketIndex}]:'{localEndPoint}, {remoteEndPoint}, {_socket.LocalEndPoint}' TLS:{_tlsCertificate != null} Time:{stopwatch.Elapsed.TotalMilliseconds}ms Disposed");
            }
            catch (Exception exception)
            {
                Cleanup(clientSocket, sslStream);

                if (exception is SocketException s && s.SocketErrorCode == SocketError.OperationAborted)
                {
                    _logger.Warning(exception, $"Error while handling client connection. Client[{socketIndex}]:'{localEndPoint}, {remoteEndPoint}, {_socket.LocalEndPoint}' TLS:{_tlsCertificate != null} Time:{stopwatch.Elapsed.TotalMilliseconds}ms OperationAborted");
                    return;
                }
                if (exception is System.IO.IOException ioException)
                {
                    _logger.Error(exception, $"Error while accepting connection at TCP listener '{localEndPoint}, {remoteEndPoint}, {_socket.LocalEndPoint}' TLS={_tlsCertificate != null}, Socket[{socketIndex}]:{stopwatch.Elapsed.TotalMilliseconds}ms IOException");
                    return;
                }

                _logger.Error(exception, $"Error while handling client connection. Client[{socketIndex}]:'{localEndPoint}, {remoteEndPoint}, {_socket.LocalEndPoint}' TLS:{_tlsCertificate != null} Time:{stopwatch.Elapsed.TotalMilliseconds}ms Unknown");
            }
            finally
            {
                try
                {
                    Cleanup(clientSocket, sslStream);

                    _logger.Verbose("Client '{0}' disconnected at TCP listener '{1}, {2}'.",
                        remoteEndPoint,
                        _socket.LocalEndPoint,
                        _addressFamily == AddressFamily.InterNetwork ? "ipv4" : "ipv6");
                }
                catch (Exception disposeException)
                {
                    _logger.Error(disposeException, "Error while cleaning up client connection");
                }

                stopwatch.Stop();
            }
        }

        void Cleanup(Socket socket, SslStream stream)
        {
            Cleanup(ref stream, s => s.Dispose());
            Cleanup(ref socket, s =>
            {
                if (s.Connected)
                {
                    s.Shutdown(SocketShutdown.Both);
                }
                s.Dispose();
            });
        }

        private static void Cleanup<T>(ref T item, Action<T> handler) where T : class
        {
            var temp = item;
            item = null;
            try
            {
                if (temp != null)
                {
                    handler(temp);
                }
            }
            catch (ObjectDisposedException)
            {
            }
            catch (NullReferenceException)
            {
            }
        }

        public void Dispose()
        {
            _socket?.Dispose();

#if NETSTANDARD1_3 || NETSTANDARD2_0 || NET461 || NET472
            _tlsCertificate?.Dispose();
#endif
        }
    }
}
#endif