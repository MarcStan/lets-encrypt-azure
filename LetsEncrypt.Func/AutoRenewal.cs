using LetsEncrypt.Logic;
using LetsEncrypt.Logic.Acme;
using LetsEncrypt.Logic.Authentication;
using LetsEncrypt.Logic.Config;
using LetsEncrypt.Logic.Storage;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace LetsEncrypt.Func
{
    public static class AutoRenewal
    {
        /// <summary>
        /// Wrapper function that allows manual execution via http with optional override parameters.
        /// </summary>
        /// <param name="req"></param>
        /// <param name="log"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        [FunctionName("execute")]
        public static async Task<IActionResult> ExecuteManuallyAsync(
            [HttpTrigger(AuthorizationLevel.Function, "POST", Route = "")] HttpRequestMessage req,
            ILogger log,
            CancellationToken cancellationToken,
            Microsoft.Azure.WebJobs.ExecutionContext executionContext)
        {
            var q = req.RequestUri.ParseQueryString();
            var overrides = new Overrides
            {
                NewCertificate = "true".Equals(q.GetValues(nameof(Overrides.NewCertificate))?.FirstOrDefault(), StringComparison.OrdinalIgnoreCase),
                UpdateResource = "true".Equals(q.GetValues(nameof(Overrides.UpdateResource))?.FirstOrDefault(), StringComparison.OrdinalIgnoreCase)
            };
            try
            {
                await RenewAsync(overrides, log, cancellationToken, executionContext);
                return new AcceptedResult();
            }
            catch (Exception)
            {
                return new BadRequestObjectResult(new
                {
                    message = "Certificate renewal failed, check appinsights for details"
                });
            }
        }

        /// <summary>
        /// Time triggered function that reads config files from storage
        /// and renews certificates accordingly if needed.
        /// </summary>
        /// <param name="timer"></param>
        /// <param name="log"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        [FunctionName("renew")]
        public static Task RenewAsync(
          [TimerTrigger(Schedule.Daily)] TimerInfo timer,
          ILogger log,
          CancellationToken cancellationToken,
          Microsoft.Azure.WebJobs.ExecutionContext executionContext)
            => RenewAsync((Overrides)null, log, cancellationToken, executionContext);

        private static async Task RenewAsync(Overrides overrides, ILogger log, CancellationToken cancellationToken,
          Microsoft.Azure.WebJobs.ExecutionContext executionContext)
        {
            // internal storage (used for letsencrypt account metadata)
            IStorageProvider storageProvider = new AzureBlobStorageProvider(Environment.GetEnvironmentVariable("AzureWebJobsStorage"), "letsencrypt");

            IConfigurationProcessor processor = new ConfigurationProcessor();
            var configurations = await LoadConfigFilesAsync(storageProvider, processor, log, cancellationToken, executionContext);
            IAuthenticationService authenticationService = new AuthenticationService(storageProvider);
            var az = new AzureHelper();

            var tokenProvider = new AzureServiceTokenProvider();
            var keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(tokenProvider.KeyVaultTokenCallback));
            var storageFactory = new StorageFactory(az);

            var renewalOptionsParser = new RenewalOptionParser(az, keyVaultClient, storageFactory, log);
            var certificateBuilder = new CertificateBuilder();

            IRenewalService renewalService = new RenewalService(authenticationService, renewalOptionsParser, certificateBuilder, log);
            var stopwatch = new Stopwatch();
            // TODO: with lots of certificate renewals this could run into function timeout (10mins)
            // with 30 days to expiry (default setting) this isn't a big problem as next day all finished certs are skipped
            // user will only get email <= 14 days before expiry so acceptable for now
            var errors = new List<Exception>();
            foreach ((var name, var config) in configurations)
            {
                using (log.BeginScope($"Working on certificates from {name}"))
                {
                    foreach (var cert in config.Certificates)
                    {
                        stopwatch.Restart();
                        var hostNames = string.Join(";", cert.HostNames);
                        cert.Overrides = overrides ?? Overrides.None;
                        try
                        {
                            var result = await renewalService.RenewCertificateAsync(config.Acme, cert, cancellationToken);
                            switch (result)
                            {
                                case RenewalResult.NoChange:
                                    log.LogInformation($"Certificate renewal skipped for: {hostNames} (no change required yet)");
                                    break;
                                case RenewalResult.Success:
                                    log.LogInformation($"Certificate renewal succeeded for: {hostNames}");
                                    break;
                                default:
                                    throw new ArgumentOutOfRangeException(result.ToString());
                            }
                        }
                        catch (Exception e)
                        {
                            log.LogError(e, $"Certificate renewal failed for: {hostNames}!");
                            errors.Add(e);
                        }
                        log.LogInformation($"Renewing certificates for {hostNames} took: {stopwatch.Elapsed}");
                    }
                }
            }
            if (!configurations.Any())
            {
                log.LogWarning("No configurations where processed, refere to the sample on how to set up configs!");
            }
            if (errors.Any())
                throw new AggregateException("Failed to process all certificates", errors);
        }

        internal static async Task<IEnumerable<(string configName, Configuration)>> LoadConfigFilesAsync(
            IStorageProvider storageProvider,
            IConfigurationProcessor processor,
            ILogger log,
            CancellationToken cancellationToken,
            Microsoft.Azure.WebJobs.ExecutionContext executionContext)

        {
            var configs = new List<(string, Configuration)>();
            var paths = await storageProvider.ListAsync("config/", cancellationToken);
            foreach (var path in paths)
            {
                if ("config/sample.json".Equals(path, StringComparison.OrdinalIgnoreCase))
                    continue; // ignore

                var content = await storageProvider.GetAsync(path, cancellationToken);
                try
                {
                    configs.Add((path, processor.ValidateAndLoad(content)));
                }
                catch (Exception e)
                {
                    log.LogError(e, "Failed to process configuration file " + path);
                }
            }
            if (!paths.Any())
            {
                log.LogWarning("No config files found. Placing config/sample.json in storage!");
                string sampleJsonPath = Path.Combine(executionContext.FunctionAppDirectory, "sample.json");
                var content = await File.ReadAllTextAsync(sampleJsonPath, cancellationToken);
                await storageProvider.SetAsync("config/sample.json", content, cancellationToken);
            }
            return configs.ToArray();
        }
    }
}
