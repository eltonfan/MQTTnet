#if !WINDOWS_UWP
using System;
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
        private readonly MqttServerTcpEndpointBaseOptions _options;
        private readonly MqttServerTlsTcpEndpointOptions _tlsOptions;
        private readonly X509Certificate2 _tlsCertificate;
        private Socket _socket;

        public MqttTcpServerListener(
            AddressFamily addressFamily,
            MqttServerTcpEndpointBaseOptions options,
            X509Certificate2 tlsCertificate,
            CancellationToken cancellationToken,
            IMqttNetChildLogger logger)
        {
            _addressFamily = addressFamily;
            _options = options;
            _tlsCertificate = tlsCertificate;
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

        private async Task AcceptClientConnectionsAsync()
        {
            while (!_cancellationToken.IsCancellationRequested)
            {
                Socket clientSocket = null;
                SslStream sslStream = null;
                try
                {
#if NET452 || NET461
                    clientSocket = await Task.Factory.FromAsync(_socket.BeginAccept, _socket.EndAccept, null).ConfigureAwait(false);
#else
                    clientSocket = await _socket.AcceptAsync().ConfigureAwait(false);
#endif
                    clientSocket.NoDelay = true;

                    if (_tlsCertificate != null)
                    {
                        sslStream = new SslStream(new NetworkStream(clientSocket), false);
                        await sslStream.AuthenticateAsServerAsync(_tlsCertificate, false, _tlsOptions.SslProtocol, false).ConfigureAwait(false);
                    }

                    _logger.Verbose("Client '{0}' accepted by TCP listener '{1}, {2}'.",
                        clientSocket.RemoteEndPoint,
                        _socket.LocalEndPoint,
                        _addressFamily == AddressFamily.InterNetwork ? "ipv4" : "ipv6");

                    var clientAdapter = new MqttChannelAdapter(new MqttTcpChannel(clientSocket, sslStream), new MqttPacketSerializer(), _logger);
                    ClientAccepted?.Invoke(this, new MqttServerAdapterClientAcceptedEventArgs(clientAdapter));
                }
                catch (ObjectDisposedException exception)
                {
                    var localEndPoint = clientSocket?.LocalEndPoint?.ToString();
                    var remoteEndPoint = clientSocket?.RemoteEndPoint?.ToString();
                    Cleanup(clientSocket, sslStream);
                    _logger.Warning(exception, $"Error while accepting connection at TCP listener '{localEndPoint}, {remoteEndPoint}, {_socket.LocalEndPoint}' TLS={_tlsCertificate != null}, Skip.");
                    // It can happen that the listener socket is accessed after the cancellation token is already set and the listener socket is disposed.
                }
                catch (Exception exception)
                {
                    var localEndPoint = clientSocket?.LocalEndPoint?.ToString();
                    var remoteEndPoint = clientSocket?.RemoteEndPoint?.ToString();
                    Cleanup(clientSocket, sslStream);

                    if (exception is SocketException s && s.SocketErrorCode == SocketError.OperationAborted)
                    {
                        _logger.Warning(exception, $"Error while accepting connection at TCP listener '{localEndPoint}, {remoteEndPoint}, {_socket.LocalEndPoint}' TLS={_tlsCertificate != null}, OperationAborted.");
                        return;
                    }
                    if(exception is System.IO.IOException ioException)
                    {
                        _logger.Error(exception, $"Error while accepting connection at TCP listener '{localEndPoint}, {remoteEndPoint}, {_socket.LocalEndPoint}' TLS={_tlsCertificate != null}, Wait for 0.1s.");
                        await Task.Delay(TimeSpan.FromSeconds(0.1), _cancellationToken).ConfigureAwait(false);
                        continue;
                    }

                    _logger.Error(exception, $"Error while accepting connection at TCP listener '{localEndPoint}, {remoteEndPoint}, {_socket.LocalEndPoint}' TLS={_tlsCertificate != null}, Wait for 1s.");
                    await Task.Delay(TimeSpan.FromSeconds(1), _cancellationToken).ConfigureAwait(false);
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