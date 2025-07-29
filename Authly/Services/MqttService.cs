using MQTTnet;
using MQTTnet.Protocol;
using System.Text;
using System.Text.Json;

namespace Authly.Services
{
    public static class MqttServiceExtensions
    {
        public static IServiceCollection AddMqttService(this IServiceCollection services)
        {
            services.AddSingleton<IMqttService, MqttService>();
            return services;
        }
    }
    
    public interface IMqttService
    {
        Task ConnectAsync(CancellationToken cancellationToken = default);
        Task DisconnectAsync(CancellationToken cancellationToken = default);
        void Publish(string topic,
            object payload);
        void Publish(string topic,
            object payload,
            bool retain,
            MqttQualityOfServiceLevel qos = MqttQualityOfServiceLevel.AtLeastOnce);
        Task PublishAsync(string topic,
            object payload,
            CancellationToken cancellationToken = default);
        Task PublishAsync(string topic,
            object payload,
            bool retain,
            MqttQualityOfServiceLevel qos = MqttQualityOfServiceLevel.AtLeastOnce,
            CancellationToken cancellationToken = default);
        Task SubscribeAsync(string topic, Func<string, string, Task> messageHandler, CancellationToken cancellationToken = default);
        bool IsConnected { get; }
        event EventHandler<string> ConnectionStatusChanged;
    }

    public class MqttService : IMqttService, IDisposable
    {
        private readonly IMqttClient _mqttClient;
        private readonly MqttClientOptions _options;
        private readonly Dictionary<string, Func<string, string, Task>> _subscriptions = [];
        private readonly IApplicationLogger _logger;
        private readonly JsonSerializerOptions _jsonSerializerOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };

        public bool IsEnabled { get; private set; } = false;
        public bool IsConnected => IsEnabled && (_mqttClient?.IsConnected ?? false);
        public event EventHandler<string> ConnectionStatusChanged;

        public MqttService(IApplicationLogger logger, IConfiguration configuration)
        {
            _logger = logger;

            var mqttConfig = configuration.GetSection("Mqtt");

            IsEnabled = mqttConfig.GetValue<bool>("Enabled", false);

            var clientOptionsBuilder = new MqttClientOptionsBuilder()
                .WithClientId(mqttConfig["ClientId"] ?? nameof(Authly))
                .WithCredentials(mqttConfig["Username"], mqttConfig["Password"])
                .WithCleanSession()
                .WithKeepAlivePeriod(TimeSpan.FromSeconds(mqttConfig.GetValue<int>("KeepAliveSeconds", 30)));

            if (!string.IsNullOrEmpty(mqttConfig["WebSocketUri"]))
            {
                _logger.LogInfo(nameof(MqttService), $"Using WebSocket connection to MQTT broker. URI: {mqttConfig["WebSocketUri"]}");

                clientOptionsBuilder.WithWebSocketServer(x =>
                {
                    x.WithUri(mqttConfig["WebSocketUri"]);
                });
            }
            else if (!string.IsNullOrEmpty(mqttConfig["Server"]))
            {
                var server = mqttConfig["Server"];
                var port = mqttConfig.GetValue<int>("Port", 1883);
                var useTls = mqttConfig.GetValue<bool>("UseTls", false);

                _logger.LogInfo(nameof(MqttService), $"Using TCP connection to MQTT broker. Server: {server}, Port: {port}");

                clientOptionsBuilder.WithTcpServer(server, port);

                if (useTls)
                {
                    clientOptionsBuilder.WithTlsOptions(tls =>
                    {
                        tls.UseTls(true);
                        tls.WithIgnoreCertificateChainErrors(true);
                        tls.WithIgnoreCertificateRevocationErrors(true);
                        tls.WithAllowUntrustedCertificates(true);
                    });
                }
            }
            else if (IsEnabled)
            {
                _logger.LogWarning(nameof(MqttService), "MQTT broker configuration is missing. MQTT service will not be enabled.");
                IsEnabled = false;
            }
            else
            {
                _logger.LogInfo(nameof(MqttService), "MQTT broker configuration is disabled.");
            }

            if (!IsEnabled)
                return;

            _options = clientOptionsBuilder.Build();

            var factory = new MqttClientFactory();
            _mqttClient = factory.CreateMqttClient();

            _mqttClient.ConnectedAsync += OnConnectedAsync;
            _mqttClient.DisconnectedAsync += OnDisconnectedAsync;
            _mqttClient.ApplicationMessageReceivedAsync += OnMessageReceivedAsync;
        }

        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                if (!IsEnabled || IsConnected)
                    return;
                _logger.LogInfo(nameof(MqttService), "Connecting to MQTT broker...");
                ArgumentNullException.ThrowIfNull(_mqttClient);
                var res = await _mqttClient.ConnectAsync(_options, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(nameof(MqttService), "Connection to MQTT broker exception", ex);
                throw;
            }
        }

        public async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                if (!IsConnected)
                    return;
                var disconnectOptions = new MqttClientDisconnectOptionsBuilder()
                    .WithReason(MqttClientDisconnectOptionsReason.NormalDisconnection)
                    .Build();
                _logger.LogInfo(nameof(MqttService), "Disconnecting from MQTT broker...");
                await _mqttClient.DisconnectAsync(disconnectOptions, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(nameof(MqttService), "Disconnecting from MQTT broker exception", ex);
                throw;
            }
        }



        public void Publish(string topic, object payload)
            => Publish(topic, payload, retain: false, qos: MqttQualityOfServiceLevel.AtLeastOnce);

        public void Publish(string topic, object payload, bool retain, MqttQualityOfServiceLevel qos = MqttQualityOfServiceLevel.AtLeastOnce)
            => _ = PublishAsync(topic, payload, retain, qos);
        public Task PublishAsync(
            string topic,
            object payload,
            CancellationToken cancellationToken = default)
            => PublishAsync(topic, payload, retain: false, qos: MqttQualityOfServiceLevel.AtLeastOnce, cancellationToken: cancellationToken);
        public async Task PublishAsync(
            string topic, 
            object payload, 
            bool retain, 
            MqttQualityOfServiceLevel qos = MqttQualityOfServiceLevel.AtLeastOnce, 
            CancellationToken cancellationToken = default)
        {
            try
            {
                if (!IsEnabled)
                    return;

                await ConnectAsync(cancellationToken);

                var json = JsonSerializer.Serialize(payload, _jsonSerializerOptions);
                var message = new MqttApplicationMessageBuilder()
                    .WithTopic(topic)
                    .WithPayload(json)
                    .WithQualityOfServiceLevel(qos)
                    .WithRetainFlag(retain)
                    .Build();

                await _mqttClient.PublishAsync(message, cancellationToken);
                _logger.LogDebug(nameof(MqttService), $"Message published to topic {topic}:{Environment.NewLine}{json}");
            }
            catch (Exception ex)
            {
                _logger.LogError(nameof(MqttService), $"Error occurred when publishing to topic {topic}", ex);
                throw;
            }
        }

        public async Task SubscribeAsync(string topic, Func<string, string, Task> messageHandler, CancellationToken cancellationToken = default)
        {
            try
            {
                if (!IsEnabled)
                    return;

                await ConnectAsync(cancellationToken);
                _subscriptions[topic] = messageHandler;

                var subscribeOptions = new MqttClientSubscribeOptionsBuilder()
                    .WithTopicFilter(topic, MqttQualityOfServiceLevel.AtLeastOnce)
                    .Build();

                await _mqttClient.SubscribeAsync(subscribeOptions, cancellationToken);
                _logger.LogInfo(nameof(MqttService), $"Successfully subscribed to topic: {topic}");
            }
            catch (Exception ex)
            {
                _logger.LogError(nameof(MqttService), $"Error occurred when subscribing to topic {topic}", ex);
                throw;
            }
        }

        private Task OnConnectedAsync(MqttClientConnectedEventArgs args)
        {
            _logger.LogInfo(nameof(MqttService), "Successfully connected to MQTT broker");
            ConnectionStatusChanged?.Invoke(this, "Connected");
            return Task.CompletedTask;
        }

        private Task OnDisconnectedAsync(MqttClientDisconnectedEventArgs args)
        {
            if (args.Reason == MqttClientDisconnectReason.NormalDisconnection)
            {
                _logger.LogInfo(nameof(MqttService), $"MQTT broker disconnected ({args.Reason.ToString()})");
            }
            else if(args.Exception != null)
            {
                _logger.LogError(nameof(MqttService), $"MQTT broker disconnected with exception: {args.Reason.ToString()}", args.Exception);
            }
            else
            {
                _logger.LogWarning(nameof(MqttService), $"MQTT broker disconnected unexpectedly ({args.Reason.ToString()})");
            }
            ConnectionStatusChanged?.Invoke(this, "Disconnected");
            return Task.CompletedTask;
        }

        private async Task OnMessageReceivedAsync(MqttApplicationMessageReceivedEventArgs args)
        {
            try
            {
                var topic = args.ApplicationMessage.Topic;
                var payload = Encoding.UTF8.GetString(args.ApplicationMessage.Payload);

                _logger.LogDebug(nameof(MqttService), $"Received message from {topic}:{Environment.NewLine}{payload}");

                var handler = _subscriptions.FirstOrDefault(s =>
                    MqttTopicFilterComparer.Compare(topic, s.Key) == MqttTopicFilterCompareResult.IsMatch).Value;

                if (handler != null)
                {
                    await handler(topic, payload);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(nameof(MqttService), "Error occurred when processing received message", ex);
            }
        }

        public void Dispose()
        {
            if (!IsEnabled)
                return;
            _mqttClient?.DisconnectAsync().Wait(5000);
            _mqttClient?.Dispose();
        }
    }
}
