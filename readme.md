CertificateService is available as a nuget package.

CertificateService supports either direct usage or usage as part of a YARP reverse proxy configuration.  Here is an example appsettings.json configuration file for direct usage:

```json
{
  "AllowedHosts": "*",
  "Urls": "http://*:80;https://*:443",
  "CertificateService": {
    "AcceptTermsOfService": true,
    "CertPath": ".certs",
    "Email": "email@user.com",
    "Password": "some-password",
    "CsrInfo": {
      "CountryName": "AU",
      "State": "NSW",
      "Locality": "Sydney",
      "Organization": "MyCompany Limited",
      "OrganizationUnit": "IT"
    },
    "Domains": [ "example.com", "www.example.com" ]
  }
}
```

Note: The `CertificateService:Password` value protects the generated `.pfx`
certificate files and should not be stored directly in `appsettings.json`
for production use. Use an environment variable, user secrets, Azure Key Vault,
AWS Secrets Manager, Docker/Kubernetes secrets, or another secure secret store.

The `.certs` directory contains generated certificates and ACME account material.
Do not commit it to source control.

Here is an example asp.net Program.cs using CertificateService:

```cs
using CertificateService;

var builder = WebApplication.CreateBuilder(args);

// Only enable Let's Encrypt certificate provisioning outside development.
// In development, use the normal ASP.NET Core developer certificate.
if (!builder.Environment.IsDevelopment())
{
    builder.Services.AddCertificateService();

    // Configure Kestrel SNI certificate selection using CertificateService.
    builder.WebHost.UseCertificateServiceSniSelector();
}

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    // Let's Encrypt needs to reach:
    // http://your-domain/.well-known/acme-challenge/{token}
    app.UseCertificateServiceAcmeHttp01();

    // Optional: expose certificate status as JSON at /.well-known/status
    app.MapCertificateServiceStatus();

    // Redirect normal HTTP traffic to HTTPS after ACME challenge handling.
    app.UseHttpsRedirection();
}

app.MapGet("/", () => "Hello from CertificateService demo.");

app.Run();
```
