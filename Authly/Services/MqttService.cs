using MQTTnet;
using MQTTnet.Protocol;
using System.Text;
using System.Text.Json;

namespace Authly.Services
{
    /// <summary>
    /// Extension methods for registering MQTT service in dependency injection container
    /// </summary>
    public static class MqttServiceExtensions
    {
        /// <summary>
        /// Adds MQTT service as singleton to the service collection
        /// </summary>
        /// <param name="services">The service collection</param>
        /// <returns>The service collection for method chaining</returns>
        public static IServiceCollection AddMqttService(this IServiceCollection services)
        {
            services.AddSingleton<IMqttService, MqttService>();
            return services;
        }
    }

    /// <summary>
    /// Interface for MQTT service providing publish/subscribe functionality
    /// </summary>
    public interface IMqttService
    {
        /// <summary>
        /// Connects to the MQTT broker asynchronously
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task representing the connection operation</returns>
        Task ConnectAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Disconnects from the MQTT broker asynchronously
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task representing the disconnection operation</returns>
        Task DisconnectAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Publishes a message to the specified topic (fire and forget)
        /// </summary>
        /// <param name="topic">MQTT topic</param>
        /// <param name="payload">Message payload object (will be JSON serialized)</param>
        void Publish(string topic, object payload);

        /// <summary>
        /// Publishes a message to the specified topic with retain and QoS options (fire and forget)
        /// </summary>
        /// <param name="topic">MQTT topic</param>
        /// <param name="payload">Message payload object (will be JSON serialized)</param>
        /// <param name="retain">Whether to retain the message on the broker</param>
        /// <param name="qos">Quality of Service level</param>
        void Publish(string topic, object payload, bool retain, MqttQualityOfServiceLevel qos = MqttQualityOfServiceLevel.AtLeastOnce);

        /// <summary>
        /// Publishes a message to the specified topic asynchronously
        /// </summary>
        /// <param name="topic">MQTT topic</param>
        /// <param name="payload">Message payload object (will be JSON serialized)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task representing the publish operation</returns>
        Task PublishAsync(string topic, object payload, CancellationToken cancellationToken = default);

        /// <summary>
        /// Publishes a message to the specified topic asynchronously with retain and QoS options
        /// </summary>
        /// <param name="topic">MQTT topic</param>
        /// <param name="payload">Message payload object (will be JSON serialized)</param>
        /// <param name="retain">Whether to retain the message on the broker</param>
        /// <param name="qos">Quality of Service level</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task representing the publish operation</returns>
        Task PublishAsync(string topic, object payload, bool retain, MqttQualityOfServiceLevel qos = MqttQualityOfServiceLevel.AtLeastOnce, CancellationToken cancellationToken = default);

        /// <summary>
        /// Subscribes to a topic and registers a message handler
        /// </summary>
        /// <param name="topic">MQTT topic or topic filter</param>
        /// <param name="messageHandler">Handler function called when messages are received</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task representing the subscribe operation</returns>
        Task SubscribeAsync(string topic, Func<string, string, Task> messageHandler, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets whether the MQTT client is currently connected to the broker
        /// </summary>
        bool IsConnected { get; }

        /// <summary>
        /// Event fired when connection status changes
        /// </summary>
        event EventHandler<string> ConnectionStatusChanged;
    }

    /// <summary>
    /// MQTT service implementation providing publish/subscribe functionality with automatic reconnection
    /// </summary>
    public class MqttService : IMqttService, IDisposable
    {
        private readonly IMqttClient _mqttClient;
        private readonly MqttClientOptions _options;
        private readonly Dictionary<string, Func<string, string, Task>> _subscriptions = [];
        private readonly IApplicationLogger _logger;

        /// <summary>
        /// JSON serializer options for message payloads
        /// </summary>
        private readonly JsonSerializerOptions _jsonSerializerOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };

        /// <summary>
        /// Gets whether MQTT service is enabled in configuration
        /// </summary>
        public bool IsEnabled { get; private set; } = false;

        /// <summary>
        /// Gets whether the MQTT client is enabled and connected to the broker
        /// </summary>
        public bool IsConnected => IsEnabled && (_mqttClient?.IsConnected ?? false);

        /// <summary>
        /// Event fired when connection status changes
        /// </summary>
        public event EventHandler<string> ConnectionStatusChanged;

        /// <summary>
        /// Initializes a new instance of the MQTT service
        /// </summary>
        /// <param name="logger">Application logger</param>
        /// <param name="configuration">Configuration containing MQTT settings</param>
        public MqttService(IApplicationLogger logger, IConfiguration configuration)
        {
            _logger = logger;

            var mqttConfig = configuration.GetSection("Mqtt");

            // Check if MQTT is enabled in configuration
            IsEnabled = mqttConfig.GetValue<bool>("Enabled", false);

            if (!IsEnabled)
            {
                _logger.LogInfo(nameof(MqttService), "MQTT broker configuration is disabled.");
                return;
            }

            // Build client options with basic settings
            var clientOptionsBuilder = new MqttClientOptionsBuilder()
                .WithClientId(mqttConfig["ClientId"] ?? nameof(Authly))
                .WithCredentials(mqttConfig["Username"], mqttConfig["Password"])
                .WithCleanSession(mqttConfig.GetValue<bool>("CleanSession", true))
                .WithKeepAlivePeriod(TimeSpan.FromSeconds(mqttConfig.GetValue<int>("KeepAliveSeconds", 30)));

            // Configure WebSocket connection if URI is provided
            if (!string.IsNullOrEmpty(mqttConfig["WebSocketUri"]))
            {
                _logger.LogInfo(nameof(MqttService), $"Using WebSocket connection to MQTT broker. URI: {mqttConfig["WebSocketUri"]}");

                clientOptionsBuilder.WithWebSocketServer(x =>
                {
                    x.WithUri(mqttConfig["WebSocketUri"]);
                });
            }
            // Configure TCP connection if server is provided
            else if (!string.IsNullOrEmpty(mqttConfig["Server"]))
            {
                var server = mqttConfig["Server"];
                var port = mqttConfig.GetValue<int>("Port", 1883);
                var useTls = mqttConfig.GetValue<bool>("UseTls", false);

                _logger.LogInfo(nameof(MqttService), $"Using TCP connection to MQTT broker. Server: {server}, Port: {port}");

                clientOptionsBuilder.WithTcpServer(server, port);

                // Configure TLS if enabled
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
            // Handle missing configuration
            else if (IsEnabled)
            {
                _logger.LogWarning(nameof(MqttService), "MQTT broker configuration is missing. MQTT service will not be enabled.");
                IsEnabled = false;
            }
            else
            {
                _logger.LogInfo(nameof(MqttService), "MQTT broker configuration is disabled.");
            }

            // Exit early if service is not enabled
            if (!IsEnabled)
                return;

            // Build final options and create client
            _options = clientOptionsBuilder.Build();

            var factory = new MqttClientFactory();
            _mqttClient = factory.CreateMqttClient();

            // Register event handlers
            _mqttClient.ConnectedAsync += OnConnectedAsync;
            _mqttClient.DisconnectedAsync += OnDisconnectedAsync;
            _mqttClient.ApplicationMessageReceivedAsync += OnMessageReceivedAsync;
        }

        /// <summary>
        /// Connects to the MQTT broker if not already connected
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task representing the connection operation</returns>
        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // Skip if service is disabled or already connected
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

        /// <summary>
        /// Disconnects from the MQTT broker gracefully
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task representing the disconnection operation</returns>
        public async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // Skip if not connected
                if (!IsConnected)
                    return;

                // Build disconnect options for graceful disconnection
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

        /// <summary>
        /// Publishes a message with default settings (fire and forget)
        /// </summary>
        /// <param name="topic">MQTT topic</param>
        /// <param name="payload">Message payload object</param>
        public void Publish(string topic, object payload)
            => Publish(topic, payload, retain: false, qos: MqttQualityOfServiceLevel.AtLeastOnce);

        /// <summary>
        /// Publishes a message with specified retain and QoS settings (fire and forget)
        /// </summary>
        /// <param name="topic">MQTT topic</param>
        /// <param name="payload">Message payload object</param>
        /// <param name="retain">Whether to retain the message</param>
        /// <param name="qos">Quality of Service level</param>
        public void Publish(string topic, object payload, bool retain, MqttQualityOfServiceLevel qos = MqttQualityOfServiceLevel.AtLeastOnce)
            => _ = PublishAsync(topic, payload, retain, qos);

        /// <summary>
        /// Publishes a message asynchronously with default settings
        /// </summary>
        /// <param name="topic">MQTT topic</param>
        /// <param name="payload">Message payload object</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task representing the publish operation</returns>
        public Task PublishAsync(string topic, object payload, CancellationToken cancellationToken = default)
            => PublishAsync(topic, payload, retain: false, qos: MqttQualityOfServiceLevel.AtLeastOnce, cancellationToken: cancellationToken);

        /// <summary>
        /// Publishes a message asynchronously with all options
        /// </summary>
        /// <param name="topic">MQTT topic</param>
        /// <param name="payload">Message payload object (will be JSON serialized)</param>
        /// <param name="retain">Whether to retain the message on the broker</param>
        /// <param name="qos">Quality of Service level</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task representing the publish operation</returns>
        public async Task PublishAsync(string topic, object payload, bool retain, MqttQualityOfServiceLevel qos = MqttQualityOfServiceLevel.AtLeastOnce, CancellationToken cancellationToken = default)
        {
            try
            {
                // Skip if service is disabled
                if (!IsEnabled)
                    return;

                // Ensure connection before publishing
                await ConnectAsync(cancellationToken);

                // Serialize payload to JSON
                var json = JsonSerializer.Serialize(payload, _jsonSerializerOptions);

                // Build MQTT message
                var message = new MqttApplicationMessageBuilder()
                    .WithTopic(topic)
                    .WithPayload(json)
                    .WithQualityOfServiceLevel(qos)
                    .WithRetainFlag(retain)
                    .Build();

                // Publish the message
                await _mqttClient.PublishAsync(message, cancellationToken);
                _logger.LogDebug(nameof(MqttService), $"Message published to topic {topic}:{Environment.NewLine}{json}");
            }
            catch (Exception ex)
            {
                _logger.LogError(nameof(MqttService), $"Error occurred when publishing to topic {topic}", ex);
                throw;
            }
        }

        /// <summary>
        /// Subscribes to a topic and registers a message handler
        /// </summary>
        /// <param name="topic">MQTT topic or topic filter (supports wildcards)</param>
        /// <param name="messageHandler">Handler function called when messages are received</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task representing the subscribe operation</returns>
        public async Task SubscribeAsync(string topic, Func<string, string, Task> messageHandler, CancellationToken cancellationToken = default)
        {
            try
            {
                // Skip if service is disabled
                if (!IsEnabled)
                    return;

                // Ensure connection before subscribing
                await ConnectAsync(cancellationToken);

                // Register the message handler
                _subscriptions[topic] = messageHandler;

                // Build subscription options
                var subscribeOptions = new MqttClientSubscribeOptionsBuilder()
                    .WithTopicFilter(topic, MqttQualityOfServiceLevel.AtLeastOnce)
                    .Build();

                // Subscribe to the topic
                await _mqttClient.SubscribeAsync(subscribeOptions, cancellationToken);
                _logger.LogInfo(nameof(MqttService), $"Successfully subscribed to topic: {topic}");
            }
            catch (Exception ex)
            {
                _logger.LogError(nameof(MqttService), $"Error occurred when subscribing to topic {topic}", ex);
                throw;
            }
        }

        /// <summary>
        /// Event handler for successful connection to MQTT broker
        /// </summary>
        /// <param name="args">Connection event arguments</param>
        /// <returns>Completed task</returns>
        private Task OnConnectedAsync(MqttClientConnectedEventArgs args)
        {
            _logger.LogInfo(nameof(MqttService), "Successfully connected to MQTT broker");
            ConnectionStatusChanged?.Invoke(this, "Connected");
            return Task.CompletedTask;
        }

        /// <summary>
        /// Event handler for disconnection from MQTT broker
        /// </summary>
        /// <param name="args">Disconnection event arguments</param>
        /// <returns>Completed task</returns>
        private Task OnDisconnectedAsync(MqttClientDisconnectedEventArgs args)
        {
            // Handle different disconnection scenarios
            if (args.Reason == MqttClientDisconnectReason.NormalDisconnection)
            {
                _logger.LogInfo(nameof(MqttService), $"MQTT broker disconnected ({args.Reason.ToString()})");
            }
            else if (args.Exception != null)
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

        /// <summary>
        /// Event handler for received MQTT messages
        /// </summary>
        /// <param name="args">Message received event arguments</param>
        /// <returns>Task representing the message processing</returns>
        private async Task OnMessageReceivedAsync(MqttApplicationMessageReceivedEventArgs args)
        {
            try
            {
                var topic = args.ApplicationMessage.Topic;
                var payload = Encoding.UTF8.GetString(args.ApplicationMessage.Payload);

                _logger.LogDebug(nameof(MqttService), $"Received message from {topic}:{Environment.NewLine}{payload}");

                // Find matching subscription handler using topic filter comparison
                var handler = _subscriptions.FirstOrDefault(s =>
                    MqttTopicFilterComparer.Compare(topic, s.Key) == MqttTopicFilterCompareResult.IsMatch).Value;

                // Execute handler if found
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

        /// <summary>
        /// Disposes the MQTT client and disconnects gracefully
        /// </summary>
        public void Dispose()
        {
            if (!IsEnabled)
                return;

            // Attempt graceful disconnection with timeout
            _mqttClient?.DisconnectAsync().Wait(5000);
            _mqttClient?.Dispose();
        }
    }
}