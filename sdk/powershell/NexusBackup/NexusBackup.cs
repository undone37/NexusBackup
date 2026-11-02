// Types of the NexusBackup PowerShell module, compiled by Add-Type on import (NexusBackup.psm1).
//
// Certificate checks: Invoke-RestMethod in PowerShell 7 can only use the system store or skip all checks, so the
// module sends with an HttpClient whose handler calls CertificateValidator: the system store, a private CA (or
// the appliance's self-signed certificate) as the only trust anchor, or a pinned SHA-256 fingerprint (no name
// or chain check: for the self-signed certificate reached by an address it does not name).

using System;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace NexusBackup
{
    public class NexusBackupException : Exception
    {
        public NexusBackupException(string message) : base(message) { }
        public NexusBackupException(string message, Exception inner) : base(message, inner) { }
    }

    /// The API answered with an error status; ApiError is its {"error": "..."} text.
    public class ApiException : NexusBackupException
    {
        public int StatusCode { get; }
        public string ApiError { get; }
        public string Method { get; }
        public string Path { get; }
        public object Body { get; }

        public ApiException(int statusCode, string apiError, string method, string path, object body)
            : base(method + " " + path + ": HTTP " + statusCode + ": " + apiError)
        {
            StatusCode = statusCode;
            ApiError = apiError;
            Method = method;
            Path = path;
            Body = body;
        }
    }

    /// The operation is not reachable with an API token: connect with -Credential (a person's session).
    public class SessionRequiredException : NexusBackupException
    {
        public SessionRequiredException(string message) : base(message) { }
    }

    /// The certificate was refused (untrusted, wrong name, fingerprint mismatch).
    public class TlsException : NexusBackupException
    {
        public TlsException(string message, Exception inner) : base(message, inner) { }
    }

    /// A job ended failed or cancelled; Reason is its result's error or the last line of its log.
    public class JobFailedException : NexusBackupException
    {
        public long JobId { get; }
        public string Kind { get; }
        public string State { get; }
        public string Reason { get; }
        public object Job { get; }

        public JobFailedException(long jobId, string kind, string state, string reason, object job)
            : base("job " + jobId + " (" + kind + ") " + state + ": "
                   + (string.IsNullOrEmpty(reason) ? "no reason given" : reason))
        {
            JobId = jobId;
            Kind = kind;
            State = state;
            Reason = string.IsNullOrEmpty(reason) ? "no reason given" : reason;
            Job = job;
        }
    }

    /// A job was still queued or running when the wait timed out; it goes on running on the appliance.
    public class WaitTimeoutException : NexusBackupException
    {
        public long JobId { get; }
        public object Job { get; }

        public WaitTimeoutException(long jobId, string state, double timeoutSec, object job)
            : base("job " + jobId + ": still " + state + " after " + timeoutSec + " s")
        {
            JobId = jobId;
            Job = job;
        }
    }

    public sealed class CertificateValidator
    {
        private readonly string _fingerprint;
        private readonly X509Certificate2Collection _roots;
        private readonly bool _skip;

        /// Why the last certificate was refused (null: accepted, or none checked since Reset).
        public string LastError { get; private set; }

        public void Reset() { LastError = null; }

        /// fingerprint: SHA-256, hex with or without colons; roots: the only trust anchors; skip: check nothing.
        public CertificateValidator(string fingerprint, X509Certificate2Collection roots, bool skip)
        {
            _fingerprint = string.IsNullOrEmpty(fingerprint) ? null : NormalizeFingerprint(fingerprint);
            _roots = roots != null && roots.Count > 0 ? roots : null;
            _skip = skip;
        }

        public static string NormalizeFingerprint(string fingerprint)
        {
            var hex = fingerprint.Replace(":", "").Replace(" ", "").ToLowerInvariant();
            if (hex.Length != 64)
                throw new ArgumentException("fingerprint: the SHA-256 of the certificate, 64 hex digits (colons allowed)");
            foreach (var c in hex)
                if (!Uri.IsHexDigit(c))
                    throw new ArgumentException("fingerprint: the SHA-256 of the certificate, 64 hex digits (colons allowed)");
            return hex;
        }

        /// SHA-256 of the certificate as upper-case hex with colons (as the appliance and browsers show it).
        public static string Fingerprint(X509Certificate cert)
        {
            var hex = Convert.ToHexString(SHA256.HashData(cert.GetRawCertData()));
            var parts = new string[32];
            for (var i = 0; i < 32; i++) parts[i] = hex.Substring(i * 2, 2);
            return string.Join(":", parts);
        }

        public bool Validate(X509Certificate2 cert, X509Chain chain, SslPolicyErrors errors)
        {
            LastError = null;
            if (_skip) return true;
            if (cert == null)
            {
                LastError = "the server sent no certificate";
                return false;
            }
            if (_fingerprint != null)
            {
                if (Convert.ToHexString(SHA256.HashData(cert.RawData)).ToLowerInvariant() == _fingerprint) return true;
                LastError = "certificate fingerprint " + Fingerprint(cert) + " does not match the pinned one";
                return false;
            }
            if (_roots != null)
            {
                if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
                {
                    LastError = "the certificate does not name this host (" + cert.Subject + ")";
                    return false;
                }
                using (var own = new X509Chain())
                {
                    own.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    own.ChainPolicy.CustomTrustStore.AddRange(_roots);
                    own.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    if (chain != null)
                        foreach (var e in chain.ChainElements) own.ChainPolicy.ExtraStore.Add(e.Certificate);
                    if (own.Build(cert)) return true;
                    var why = own.ChainStatus.Length > 0 ? own.ChainStatus[0].StatusInformation.Trim() : "untrusted";
                    LastError = "certificate not trusted by the given CA: " + why;
                    return false;
                }
            }
            if (errors == SslPolicyErrors.None) return true;
            LastError = "certificate not trusted (" + errors + "); pass -CaCertificatePath with the appliance's CA "
                        + "or certificate, or -CertificateFingerprint with its SHA-256 (Settings -> Certificate)";
            return false;
        }

        public HttpClientHandler CreateHandler()
        {
            var h = new HttpClientHandler
            {
                UseCookies = false,
                AllowAutoRedirect = false,
            };
            h.ServerCertificateCustomValidationCallback = (request, cert, chain, errors) => Validate(cert, chain, errors);
            return h;
        }

        /// The fingerprint of the certificate a server presents, unchecked (trust on first use: compare it with
        /// the one shown on the appliance before pinning it).
        public static string GetServerFingerprint(string host, int port, int timeoutMs)
        {
            using (var tcp = new TcpClient())
            {
                if (!tcp.ConnectAsync(host, port).Wait(timeoutMs)) throw new TimeoutException(host + ":" + port);
                X509Certificate seen = null;
                RemoteCertificateValidationCallback keep = (sender, cert, chain, errors) =>
                {
                    seen = cert;
                    return true;
                };
                using (var ssl = new SslStream(tcp.GetStream(), false, keep))
                {
                    ssl.AuthenticateAsClient(host);
                    return Fingerprint(seen ?? ssl.RemoteCertificate);
                }
            }
        }
    }
}
