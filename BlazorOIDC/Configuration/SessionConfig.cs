namespace BlazorOIDC.Configuration;

public class SessionConfig
{
    public int SlidingExpirationMinutes { get; set; } = 30;
    public int AbsoluteExpirationHours { get; set; } = 24;
}
