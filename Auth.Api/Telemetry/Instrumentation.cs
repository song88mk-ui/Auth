using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Auth.Api.Telemetry
{

  public class Instrumentation: IDisposable
  {

    internal const string ActivitySourceName = "Auth.API";
    internal const string MeterName = "Auth.API";

    private readonly Meter meter;

    public Instrumentation()
    {
      string? version = "latest"; //typeof(Instrumentation).Assembly.GetName().Version?.ToString();
      this.ActivitySource = new ActivitySource(ActivitySourceName, version);
      this.meter = new Meter(MeterName, version);
      this.LoginSuccessCounter = this.meter.CreateCounter<long>("login.success", "count", "Number of success logins.");
      this.LoginFailureCounter = this.meter.CreateCounter<long>("login.failure", "count", "Number of failed logins.");
    }

    public ActivitySource ActivitySource { get; }
    public Counter<long> LoginSuccessCounter { get; }
    public Counter<long> LoginFailureCounter { get; }

    public void Dispose()
    {
      this.ActivitySource.Dispose();
      this.meter.Dispose();
    }

  }

}
