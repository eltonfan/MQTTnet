namespace MQTTnet.Client
{
    public class MqttClientCredentials : IMqttClientCredentials
    {
        public string UserName { get; set; }

        public string Password { get; set; }

        public void Create(out string userName, out string password)
        {
            userName = this.UserName;
            password = this.Password;
        }
    }
}
