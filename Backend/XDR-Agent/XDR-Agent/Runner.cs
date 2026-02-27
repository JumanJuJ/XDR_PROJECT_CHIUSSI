
using XDR_Agent.Network;
using XDR_Agent.Local;

Host.CreateDefaultBuilder(args)
    .ConfigureServices(services =>
    {
        services.AddHostedService<NetworkAgentWorker>();
        services.AddHostedService<LocalAgentWorker>();
    })
    .Build()
    .Run();
