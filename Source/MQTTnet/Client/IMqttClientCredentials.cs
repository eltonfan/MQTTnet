namespace MQTTnet.Client
{
    public interface IMqttClientCredentials
    {
        void Create(out string userName, out string password);
    }
}