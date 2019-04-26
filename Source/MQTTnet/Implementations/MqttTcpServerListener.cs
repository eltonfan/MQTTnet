#if !WINDOWS_UWP
using System;
using System.Diagnostics;
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

        long totelSockets = 0;

        private async Task AcceptClientConnectionsAsync()
        {
            while (!_cancellationToken.IsCancellationRequested)
            {
                Interlocked.Increment(ref totelSockets);

                Socket clientSocket = null;
                SslStream sslStream = null;
                var stopwatch = new Stopwatch();
                try
                {
#if NET452 || NET461
                    clientSocket = await Task.Factory.FromAsync(_socket.BeginAccept, _socket.EndAccept, null).ConfigureAwait(false);
#else
                    clientSocket = await _socket.AcceptAsync().ConfigureAwait(false);
#endif
                    stopwatch.Start();
                    clientSocket.NoDelay = true;

                    _logger.Verbose("Client '{0}' accepted by TCP listener '{1}, {2}',  Socket[{3}]:{4}ms",
                        clientSocket.RemoteEndPoint,
                        _socket.LocalEndPoint,
                        _addressFamily == AddressFamily.InterNetwork ? "ipv4" : "ipv6",
                        totelSockets, stopwatch.Elapsed.TotalMilliseconds);

                    if (_tlsCertificate != null)
                    {//如果不设置超时，AuthenticateAsServerAsync 可能会一直阻塞下去
                        clientSocket.ReceiveTimeout = (int)_communicationTimeout.TotalMilliseconds;
                        clientSocket.SendTimeout = (int)_communicationTimeout.TotalMilliseconds;

                        sslStream = new SslStream(new NetworkStream(clientSocket), false);

                        var cancellationTokenDisposeSslStream = new CancellationTokenSource();
                        var taskDisposeSslStream = Task.Delay(2000, cancellationTokenDisposeSslStream.Token)
                            .ContinueWith((task) =>
                            {
                                if (task.IsCanceled)
                                    return;
                                if (cancellationTokenDisposeSslStream.IsCancellationRequested)
                                    return;

                                //超时，则清理掉
                                sslStream.Dispose();
                            });

                        await sslStream.AuthenticateAsServerAsync(_tlsCertificate, false, _tlsOptions.SslProtocol, false).ConfigureAwait(false);

                        cancellationTokenDisposeSslStream.Cancel();

                        _logger.Verbose("Client '{0}' SslStream created. Socket[{1}]:{2}ms",
                            clientSocket.RemoteEndPoint,
                            totelSockets, stopwatch.Elapsed.TotalMilliseconds);
                    }

                    var clientAdapter = new MqttChannelAdapter(new MqttTcpChannel(clientSocket, sslStream), new MqttPacketSerializer(), _logger);
                    ClientAccepted?.Invoke(this, new MqttServerAdapterClientAcceptedEventArgs(clientAdapter));

                    _logger.Verbose("Client '{0}' processed. Socket[{1}]:{2}ms",
                        clientSocket.RemoteEndPoint,
                        totelSockets, stopwatch.Elapsed.TotalMilliseconds);
                }
                catch (ObjectDisposedException exception)
                {
                    var localEndPoint = clientSocket?.LocalEndPoint?.ToString();
                    var remoteEndPoint = clientSocket?.RemoteEndPoint?.ToString();
                    Cleanup(clientSocket, sslStream);
                    _logger.Error(exception, $"Error while accepting connection at TCP listener '{localEndPoint}, {remoteEndPoint}, {_socket.LocalEndPoint}' TLS={_tlsCertificate != null}, Socket[{totelSockets}]:{stopwatch.Elapsed.TotalMilliseconds}ms, Skip.");
                    // It can happen that the listener socket is accessed after the cancellation token is already set and the listener socket is disposed.
                }
                catch (Exception exception)
                {
                    var localEndPoint = clientSocket?.LocalEndPoint?.ToString();
                    var remoteEndPoint = clientSocket?.RemoteEndPoint?.ToString();
                    Cleanup(clientSocket, sslStream);

                    if (exception is SocketException s && s.SocketErrorCode == SocketError.OperationAborted)
                    {
                        _logger.Warning(exception, $"Error while accepting connection at TCP listener '{localEndPoint}, {remoteEndPoint}, {_socket.LocalEndPoint}' TLS={_tlsCertificate != null}, Socket[{totelSockets}]:{stopwatch.Elapsed.TotalMilliseconds}ms, OperationAborted.");
                        return;
                    }
                    if(exception is System.IO.IOException ioException)
                    {
                        _logger.Error(exception, $"Error while accepting connection at TCP listener '{localEndPoint}, {remoteEndPoint}, {_socket.LocalEndPoint}' TLS={_tlsCertificate != null}, Socket[{totelSockets}]:{stopwatch.Elapsed.TotalMilliseconds}ms, Wait for 0.1s.");
                        await Task.Delay(TimeSpan.FromSeconds(0.1), _cancellationToken).ConfigureAwait(false);
                        continue;
                    }

                    _logger.Error(exception, $"Error while accepting connection at TCP listener '{localEndPoint}, {remoteEndPoint}, {_socket.LocalEndPoint}' TLS={_tlsCertificate != null}, Socket[{totelSockets}]:{stopwatch.Elapsed.TotalMilliseconds}ms, Wait for 1s.");
                    await Task.Delay(TimeSpan.FromSeconds(1), _cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    stopwatch.Stop();
                }
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