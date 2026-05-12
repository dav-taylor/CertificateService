// Copyright(c) 2026 David Taylor
using Certes;
using Certes.Acme;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
namespace CertificateService;

/// <summary>
/// Extension methods to integrate CertificateService with asp.net.
/// </summary>
public static class CertificateExtensionMethods
{
    /// <summary>
    /// Add the required CertificateService as singleton.  This service handles certificate registration, renewal
    /// and provides the certificates to the reverse proxy's certificate selector.
    /// </summary>
    public static void AddCertificateService(this IServiceCollection services)
    {
        services.AddSingleton<CertificateService>();
        services.AddOptions<ReverseProxyConfig>().BindConfiguration("ReverseProxy");
    }

    /// <summary>
    /// Configure the Kestrel certificate selector to use the CertificateService to select certificates.
    /// </summary>
    public static void UseCertificateServiceSniSelector(this ConfigureWebHostBuilder webHost)
    {
        webHost.ConfigureKestrel(options => options.ConfigureHttpsDefaults(https =>
        {
            var certs = options.ApplicationServices.GetRequiredService<CertificateService>();
            https.ServerCertificateSelector = (context, name) => certs.GetCertificateByDomain(name);
        }));
    }

    /// <summary>
    /// Map endpoint LetsEncrypt uses for ACME challenges during certificate provisioning to prove 
    /// ownership of a domain. Must be called *before* UseHttpsRedirection (to allow HTTP request)
    /// </summary>
    public static void UseCertificateServiceAcmeHttp01(this WebApplication app)
    {
        // app.MapGet("/.well-known/acme-challenge/{token}", (string token, CertificateService certs) => certs.AcmeHttpChallenge(token));
        // Short-circuit ACME HTTP-01 *before* any https redirection (replaces above line):
        app.Use(async (ctx, next) =>
        {
            if ((HttpMethods.IsGet(ctx.Request.Method) || HttpMethods.IsHead(ctx.Request.Method))
                && ctx.Request.Path.StartsWithSegments("/.well-known/acme-challenge", out var rest))
            {
                var token = rest.Value?.TrimStart('/'); // rest is like "/{token}"
                if (!string.IsNullOrWhiteSpace(token))
                {
                    var certs = ctx.RequestServices.GetRequiredService<CertificateService>();
                    var result = certs.AcmeHttpChallenge(token);
                    await result.ExecuteAsync(ctx);
                    return;
                }
            }
            await next();
        });
    }

    /// <summary>
    /// Optionally map the certificate status endpoint /.well-known/status
    /// The returns the registered certificate information as json
    /// </summary>
    public static void MapCertificateServiceStatus(this WebApplication app)
    {
        app.MapGet("/.well-known/status", (CertificateService certs) => certs.CertificateStatus);
    }
}

internal class CertificateService : IDisposable
{
    private readonly IConfiguration _config;
    private readonly ILogger<CertificateService> _logger;
    private readonly ConcurrentDictionary<string, X509Certificate2> _certificates = new(); // Host to Cert map
    private readonly Dictionary<string, string> _challengeMap = []; // LetsEncrypt ACME challenge map
    private readonly Timer _renewalTimer;
    private readonly CertificateServiceConfig _certificateServiceConfig;
    private readonly Uri _letsEncryptUri = WellKnownServers.LetsEncryptV2;
    private readonly string _certPath;
    private bool _processingCertificates = false; // True while processing new certificates


    public CertificateService(ILogger<CertificateService> logger, IConfiguration config, IHostApplicationLifetime lifetime, IWebHostEnvironment env, IOptionsMonitor<ReverseProxyConfig> optionsMonitor)
    {
        _logger = logger;
        _config = config;
        _certificateServiceConfig = GetCertificateServiceConfig();
        _certPath = Path.IsPathFullyQualified(_certificateServiceConfig.CertPath)
                ? _certificateServiceConfig.CertPath // Used for absolute paths
                : Path.Combine(env.ContentRootPath, _certificateServiceConfig.CertPath); // Paths relative to content root

        // Make sure we can access certificate directory
        VerifyFileAccess();
        LoadAllCertificates(); // Load existing certificates immediately (no delay)

        // Process certificate *after* http pipeline has started (so LetsEncrypt inbound challenges resolve)
        lifetime.ApplicationStarted.Register(() => ProcessCertificatesAndHandleExceptions());

        // Provision any newly required certificates if YARP proxy configuration changes
        if (_config.GetSection("ReverseProxy").Exists())
        {
            optionsMonitor.OnChange(newConfig => ProcessCertificatesAndHandleExceptions("Detected configuration change, re-checking certificates"));
        }

        // Every day we check if certificates need to be renewed and reload as required
        _renewalTimer = new Timer(_ => ProcessCertificatesAndHandleExceptions("Checking certificate renewal status"), null, TimeSpan.FromDays(1), TimeSpan.FromDays(1) + TimeSpan.FromMinutes(Random.Shared.Next(0, 60)));

        _logger.LogInformation("CertificateService initialized");
    }

    public X509Certificate2? GetCertificateByDomain(string? domainName)
    {
        // Do not log warnings if people are just hitting the ip address without a hostname
        if (string.IsNullOrEmpty(domainName)) return null;

        if (_certificates.TryGetValue(domainName, out var certificate))
        {
            _logger.LogDebug("Selected certificate for domain: {domain}", domainName);
            return certificate;
        }

        // Log warning if domain not found
        _logger.LogWarning("Certificate not found for domain: {domain}", domainName);
        return null;
    }

    //ACME HTTP Challenge (http-01)
    public IResult AcmeHttpChallenge(string token)
    {
        return _challengeMap.TryGetValue(token, out var KeyAuthz)
            ? Results.Text(KeyAuthz) : Results.NotFound();
    }

    public IResult CertificateStatus => Results.Json(_certificates.Select(kvp =>
    {
        var (domain, cert) = kvp;
        var expired = cert.NotAfter < DateTime.UtcNow;
        return new { domain, expired, cert.NotBefore, cert.NotAfter, cert.Subject, cert.Issuer };
    }));

    private void VerifyFileAccess()
    {
        try
        {
            _logger.LogInformation("Verifying access to certificate path {path}", _certPath);
            if (!Directory.Exists(_certPath))
            {
                _logger.LogInformation("Creating certificate directory {path}", _certPath);
                Directory.CreateDirectory(_certPath);
            }

            var filePath = Path.Combine(_certPath, "probe.txt");
            _logger.LogDebug("Testing write access by writing {path}", filePath);
            File.WriteAllText(filePath, "test");
            _logger.LogDebug("Testing read access by reading {path}", filePath);
            if (File.ReadAllText(filePath) != "test")
            {
                throw new Exception("Cannot write and read test file " + filePath);
            }
            File.Delete(filePath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "VerifyFileAccess Failed. {message}", ex.Message);
            throw new IOException("VerifyFileAccess Failed", ex);
        }
    }

    private void LoadAllCertificates(string[] domains = default!)
    {
        // By default we use the domains in the configuration (Configuration:Domains or Yarp host config) unless supplied.
        domains ??= GetDomains();
        _logger.LogInformation("Loading certificates for all domains");

        foreach (var domain in domains)
        {
            try
            {
                var certPath = Path.Combine(_certPath, domain + ".pfx");
                if (!File.Exists(certPath))
                {
                    _logger.LogWarning("Certificate not found for {domain} at {certPath}", domain, certPath);
                    continue;
                }

                var cert = X509CertificateLoader.LoadPkcs12FromFile(certPath, _certificateServiceConfig.Password);
                _logger.LogInformation("Certificate loaded for {domain}, expires: {expiryDate}", domain, cert.NotAfter);

                // Update the certificate in the cache
                _certificates.AddOrUpdate(domain, cert, (key, oldCert) =>
                {
                    oldCert?.Dispose(); // Dispose any old certificate
                    return cert;
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading certificate for domain: {domain}", domain);
            }
        }
    }

    private void ProcessCertificatesAndHandleExceptions(string? logMessage = null)
    {
        Task.Run(async () =>
        {
            try
            {
                if (_processingCertificates)
                {
                    _logger.LogInformation("Skipping certificate processing because another run is in progress.");
                    return;
                }
                _processingCertificates = true;
                if (logMessage is not null) _logger.LogInformation(logMessage);
                await ProcessCertificates();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Critical error processing certificates. {message}", ex.Message);
            }
            finally
            {
                _processingCertificates = false;
            }
        });
    }

    private async Task ProcessCertificates()
    {
        if (DateTime.Now.Year < 2000) // Protect against bad RTC or NTP unavailability.
        {
            _logger.LogWarning("Certificate processing skipped due to invalid date {dateTime}", DateTime.UtcNow);
            return;
        }

        // Build list of valid certificates on disk (not including lapsed or needing renewal)
        List<string> certificateDomainList = [];
        foreach (var pfxFile in Directory.GetFiles(_certPath, "*.pfx"))
        {
            var domain = Path.GetFileNameWithoutExtension(pfxFile);
            var cert = X509CertificateLoader.LoadPkcs12FromFile(pfxFile, _certificateServiceConfig.Password);
            // Note: Assume one LetsEncrypt certificate per domain (1-to-1 mapping)
            if (!cert.MatchesHostname(domain))
            {
                _logger.LogWarning("Certificate {pfxFile} for {domain} does not match filename, skipping.", pfxFile, domain);
                continue;
            }
            if (cert.NotAfter <= DateTime.UtcNow.AddDays(30))
            {
                _logger.LogInformation("Certificate {pfxFile} for {domain} stale or expired with expiry {expiryDate}", pfxFile, domain, cert.NotAfter);
                continue;
            }

            // Add to list of certificates that we consider "active" (not stale or expired)
            certificateDomainList.Add(domain);
        }

        // List of domains used as Host in configuration (CertificateService:Domains or YARP Proxy hosts)
        var ConfigurationDomainList = GetDomains();
        // Create list of certificates we need to provision with LetsEncrypt API
        var renewalList = ConfigurationDomainList.Except(certificateDomainList).ToArray();

        // Use LetsEncrypt to provision and load these certificates.
        if (renewalList.Length > 0)
        {
            var context = await GetAcmeContext();
            foreach (var domain in renewalList)
            {
                try
                {
                    await AcmeOrder(context, domain);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error processing LetsEncrypt AcmeOrder for domain {domain}", domain);
                }
            }
            // Reload these certificates into the dictionary.
            LoadAllCertificates(renewalList);
        }
    }

    private string[] GetDomains()
    {
        // Look for explicit domains entry (for non-YARP mode)
        var configuredDomains = _certificateServiceConfig.Domains?
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray() ?? [];

        if (configuredDomains.Length > 0)
        {
            _logger.LogInformation("Domains sourced from CertificateService:Domains: {count}", configuredDomains.Length);
            return configuredDomains;
        }

        // Get Hosts from Yarp Configuration
        var hosts =
            (from route in _config.GetSection("ReverseProxy:Routes").GetChildren()
             from host in route.GetSection("Match:Hosts").Get<string[]>() ?? []
             select host).Distinct().ToArray();

        if (hosts.Length > 0)
        {
            _logger.LogInformation("Domains sourced from ReverseProxy route hosts");
            return hosts;
        }

        _logger.LogWarning("No domains found. Configure either ReverseProxy route hosts or CertificateService:Domains.");
        return [];
    }

    private CertificateServiceConfig GetCertificateServiceConfig()
        => _config.GetSection("CertificateService").Get<CertificateServiceConfig>() ?? throw new Exception("Configuration must include CertificateService section (see docs)");

    private CsrInfo GetCsrTemplate()
        => _config.GetSection("CertificateService:CsrInfo").Get<CsrInfo>() ?? throw new Exception("Configuration must include CsrInfo in CertificateService section (see docs)");

    private async Task<AcmeContext> GetAcmeContext()
    {
        var pemPath = Path.Combine(_certPath, "accountKey.pem");
        if (File.Exists(pemPath))
        {
            // Create AcmeContext from previously saved account key
            _logger.LogInformation("LetsEncrypt using existing account {pemPath}", pemPath);
            var pemKey = File.ReadAllText(pemPath);
            var accountKey = KeyFactory.FromPem(pemKey);
            var acme = new AcmeContext(_letsEncryptUri, accountKey);
            return acme;
        }
        else
        {
            // Create AcmeContext from newly created account and saving account key
            _logger.LogInformation("LetsEncrypt creating new account {pemPath}", pemPath);
            var acme = new AcmeContext(_letsEncryptUri);
            _ = await acme.NewAccount(_certificateServiceConfig.Email, _certificateServiceConfig.AcceptTermsOfService);
            var pemKey = acme.AccountKey.ToPem();
            File.WriteAllText(pemPath, pemKey);
            return acme;
        }
    }

    private async Task AcmeOrder(AcmeContext acme, string domain)
    {
        _logger.LogInformation("LetsEncrypt starting certificate order: {domain}", domain);
        var order = await acme.NewOrder([domain]);
        var authz = await order.Authorizations();
        var httpChallenge = await authz.First().Http();
        _challengeMap[httpChallenge.Token] = httpChallenge.KeyAuthz;
        _logger.LogInformation("LetsEncrypt confirming ownership with http challenge for {domain}", domain);
        await WaitForChallenge(httpChallenge);
        _challengeMap.Remove(httpChallenge.Token);
        _logger.LogInformation("LetsEncrypt creating certificate for {domain}", domain);
        var privateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
        var csrInfo = GetCsrTemplate();
        csrInfo.CommonName = domain;
        var cert = await order.Generate(csrInfo, privateKey);
        var pfxPath = Path.Combine(_certPath, $"{domain}.pfx");
        _logger.LogInformation("LetsEncrypt certificate saving to {pfxPath}", pfxPath);
        var pfxBuilder = cert.ToPfx(privateKey);
        var pfxBytes = pfxBuilder.Build(domain, _certificateServiceConfig.Password);
        File.WriteAllBytes(pfxPath, pfxBytes);
    }


    private async Task WaitForChallenge(IChallengeContext httpChallenge, int maxSeconds = 30)
    {
        await httpChallenge.Validate();
        var timeout = DateTime.UtcNow.AddSeconds(maxSeconds);

        while (DateTime.UtcNow < timeout)
        {
            var status = await httpChallenge.Resource();
            if (status.Status is Certes.Acme.Resource.ChallengeStatus.Valid) return;
            if (status.Status is Certes.Acme.Resource.ChallengeStatus.Invalid)
                throw new AcmeException($"LetsEncrypt ACME challenge failed: {status.Error?.Detail}");
            await Task.Delay(2000);
        }

        throw new TimeoutException("LetsEncrypt ACME challenge did not complete in time");
    }

    public void Dispose()
    {
        _renewalTimer?.Dispose();
        foreach (var cert in _certificates.Values)
        {
            cert?.Dispose();
        }
        _certificates.Clear();
    }
}

// Record used to deserialize settings from IConfiguration
// *Domains* should be null or empty array if using Yarp.  For non-YARP use supply the domain(s) for the certificates
internal record CertificateServiceConfig(bool AcceptTermsOfService, string CertPath, string Email, string Password, CsrInfo CsrInfo, string[]? Domains = null);

// Empty record used to watch for changes in YARP ReverseProxy section from IConfiguration
internal record ReverseProxyConfig;