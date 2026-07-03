using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.IO;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;

public static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            var config = CollectorConfig.Parse(args);
            if (config.ShowHelp)
            {
                Help.Print();
                return 0;
            }

            var log = new Logger(config.Verbosity);
            var collector = new AuthorizationStateCollector(config, log);
            collector.Run();
            return 0;
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine("collect-adauth: invalid arguments: " + ex.Message);
            Console.Error.WriteLine("Use --help for usage.");
            return 2;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("collect-adauth: collection failed: " + ex.Message);
            Console.Error.WriteLine(ex);
            return 1;
        }
    }

    #region Configuration

    private sealed class CollectorConfig
    {
        public string? Host { get; private set; }
        public int Port { get; private set; } = 389;
        public string? BaseDn { get; set; }
        public string OutputPath { get; private set; } = "ad_authorization_state.json";
        public string? Domain { get; private set; } = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
        public bool IncludeBuiltIn { get; private set; } = true;
        public int PageSize { get; private set; } = 1000;
        public int Threads { get; private set; } = Math.Max(1, Environment.ProcessorCount / 2);
        public int Verbosity { get; private set; } = 2;
        public bool Resume { get; private set; }
        public bool CheckpointEnabled { get; private set; } = true;
        public string CheckpointDir { get; private set; } = ".adcollect-checkpoints";
        public TimeSpan Timeout { get; private set; } = TimeSpan.FromSeconds(30);
        public int RetryCount { get; private set; } = 3;
        public int DelayMs { get; private set; }
        public bool IncludeInheritedAces { get; private set; }
        public bool ShowHelp { get; private set; }

        public static CollectorConfig Parse(string[] args)
        {
            var config = new CollectorConfig();

            for (var i = 0; i < args.Length; i++)
            {
                var raw = args[i];
                if (raw is "-h" or "/?" || raw.Equals("--help", StringComparison.OrdinalIgnoreCase))
                {
                    config.ShowHelp = true;
                    continue;
                }

                if (!raw.StartsWith("-", StringComparison.Ordinal))
                {
                    throw new ArgumentException("unexpected positional argument '" + raw + "'");
                }

                var token = raw.TrimStart('-');
                string? value = null;
                var equals = token.IndexOf('=');
                if (equals >= 0)
                {
                    value = token[(equals + 1)..];
                    token = token[..equals];
                }

                var key = NormalizeKey(token);
                value ??= OptionalValue(args, ref i);

                switch (key)
                {
                    case "host":
                    case "targethost":
                        config.Host = RequireValue(raw, value);
                        break;
                    case "port":
                    case "targetport":
                        config.Port = ParseInt(raw, value, 1, 65535);
                        break;
                    case "basedn":
                        config.BaseDn = RequireValue(raw, value);
                        break;
                    case "output":
                    case "outputpath":
                    case "outputfile":
                        config.OutputPath = RequireValue(raw, value);
                        break;
                    case "domain":
                        config.Domain = RequireValue(raw, value);
                        break;
                    case "includebuiltin":
                    case "includebuiltingroups":
                        config.IncludeBuiltIn = ParseBool(value, true);
                        break;
                    case "pagesize":
                        config.PageSize = ParseInt(raw, value, 1, 100000);
                        break;
                    case "threads":
                        config.Threads = ParseInt(raw, value, 1, 1024);
                        break;
                    case "verbosity":
                        config.Verbosity = ParseInt(raw, value, 0, 3);
                        break;
                    case "resume":
                    case "resumefromcheckpoint":
                        config.Resume = ParseBool(value, true);
                        break;
                    case "checkpointdir":
                        config.CheckpointDir = RequireValue(raw, value);
                        break;
                    case "checkpointenabled":
                        config.CheckpointEnabled = ParseBool(value, true);
                        break;
                    case "timeout":
                        config.Timeout = TimeSpan.FromSeconds(ParseInt(raw, value, 1, 86400));
                        break;
                    case "timeoutseconds":
                        config.Timeout = TimeSpan.FromSeconds(ParseInt(raw, value, 1, 86400));
                        break;
                    case "retrycount":
                    case "maxretries":
                        config.RetryCount = ParseInt(raw, value, 0, 100);
                        break;
                    case "delayms":
                    case "querydelayms":
                        config.DelayMs = ParseInt(raw, value, 0, 600000);
                        break;
                    case "includeinheritedaces":
                        config.IncludeInheritedAces = ParseBool(value, true);
                        break;
                    default:
                        throw new ArgumentException("unknown option '" + raw + "'");
                }
            }

            config.OutputPath = Path.GetFullPath(config.OutputPath);
            config.CheckpointDir = Path.GetFullPath(config.CheckpointDir);
            return config;
        }

        private static string NormalizeKey(string value)
        {
            return value.Replace("-", string.Empty, StringComparison.Ordinal)
                .Replace("_", string.Empty, StringComparison.Ordinal)
                .ToLowerInvariant();
        }

        private static string? OptionalValue(string[] args, ref int index)
        {
            if (index + 1 >= args.Length)
            {
                return null;
            }

            if (args[index + 1].StartsWith("-", StringComparison.Ordinal))
            {
                return null;
            }

            index++;
            return args[index];
        }

        private static string RequireValue(string option, string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException(option + " requires a value");
            }

            return value;
        }

        private static int ParseInt(string option, string? value, int min, int max)
        {
            value = RequireValue(option, value);
            if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) || parsed < min || parsed > max)
            {
                throw new ArgumentException(option + " must be an integer between " + min + " and " + max);
            }

            return parsed;
        }

        private static bool ParseBool(string? value, bool whenMissing)
        {
            if (value is null)
            {
                return whenMissing;
            }

            return value.Equals("1", StringComparison.OrdinalIgnoreCase) ||
                   value.Equals("true", StringComparison.OrdinalIgnoreCase) ||
                   value.Equals("yes", StringComparison.OrdinalIgnoreCase) ||
                   value.Equals("on", StringComparison.OrdinalIgnoreCase);
        }
    }

    private static class Help
    {
        public static void Print()
        {
            Console.WriteLine("collect-adauth-csharp - Active Directory authorization state collector");
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("  dotnet run -- [options]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --host HOST                 Domain controller host or DNS domain.");
            Console.WriteLine("  --port PORT                 LDAP port. Default: 389.");
            Console.WriteLine("  --base-dn DN                Search base DN. Default: RootDSE defaultNamingContext.");
            Console.WriteLine("  --output PATH               Output JSON path. Default: ad_authorization_state.json.");
            Console.WriteLine("  --domain DOMAIN             Metadata domain. Default: USERDNSDOMAIN or base DN.");
            Console.WriteLine("  --include-built-in BOOL     Include Builtin/CN=Users groups. Default: true.");
            Console.WriteLine("  --page-size N               LDAP page size. Default: 1000.");
            Console.WriteLine("  --threads N                 Accepted for pipeline compatibility. Current collector keeps LDAP writes serialized.");
            Console.WriteLine("  --verbosity 0..3            0 quiet, 1 summary, 2 progress, 3 debug. Default: 2.");
            Console.WriteLine("  --resume BOOL               Reuse completed section checkpoints. Default: false.");
            Console.WriteLine("  --checkpoint-dir DIR        Checkpoint/fragment directory. Default: .adcollect-checkpoints.");
            Console.WriteLine("  --checkpoint-enabled BOOL   Write per-section checkpoints. Default: true.");
            Console.WriteLine("  --timeout SECONDS           LDAP operation timeout. Default: 30.");
            Console.WriteLine("  --retry-count N             LDAP retry count. Default: 3.");
            Console.WriteLine("  --delay-ms N                Delay between LDAP operations. Default: 0.");
            Console.WriteLine("  --include-inherited-aces    Include inherited ACEs. Default: false to match the PowerShell collector.");
            Console.WriteLine();
            Console.WriteLine("Authentication is Windows Integrated Authentication (Negotiate) only.");
        }
    }

    #endregion

    #region Orchestration

    private sealed class AuthorizationStateCollector
    {
        private readonly CollectorConfig _config;
        private readonly Logger _log;

        public AuthorizationStateCollector(CollectorConfig config, Logger log)
        {
            _config = config;
            _log = log;
        }

        public void Run()
        {
            _log.Info("=== Active Directory Authorization State Collection ===");
            _log.Info("Output: " + _config.OutputPath);

            using var ldap = new LdapClient(_config, _log);
            ldap.Connect();

            var root = ldap.ReadRootDse();
            _config.BaseDn ??= root.DefaultNamingContext;
            if (string.IsNullOrWhiteSpace(_config.BaseDn))
            {
                throw new InvalidOperationException("RootDSE did not return defaultNamingContext; provide --base-dn.");
            }

            var metadata = new MetadataRecord
            {
                CollectorVersion = "1.1",
                Domain = ResolveMetadataDomain(_config.Domain, _config.BaseDn),
                Description = "Active Directory authorization state snapshot",
                CollectionDate = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
            };

            _log.Info("Domain: " + metadata.Domain);
            _log.Info("Base DN: " + _config.BaseDn);

            var schema = new SchemaResolver(ldap, root.ConfigurationNamingContext, _log);
            schema.Load();

            var sidResolver = new SidResolver(ldap, _config.BaseDn, _log);
            var dnResolver = new DistinguishedNameResolver(ldap, _log);
            var collectors = new SectionCollectors(_config, ldap, schema, sidResolver, dnResolver, _log);
            var spool = new SectionSpool(_config, _log);
            var stats = new CollectionStats();

            stats.AclCount = spool.WriteSection("acl_permissions", writer => collectors.CollectAcls(writer));
            stats.GroupCount = spool.WriteSection("groups", writer => collectors.CollectGroups(writer));
            spool.WriteMetadataCheckpoint(metadata);
            stats.MembershipCount = spool.WriteSection("group_memberships", writer => collectors.CollectGroupMemberships(writer));
            stats.UserCount = spool.WriteSection("users", writer => collectors.CollectUsers(writer));
            stats.DelegationCount = spool.WriteSection("delegation", writer => collectors.CollectDelegation(writer));
            stats.SpnCount = spool.WriteSection("spns", writer => collectors.CollectSpns(writer));
            stats.ComputerCount = spool.WriteSection("computers", writer => collectors.CollectComputers(writer));

            spool.ComposeFinalOutput(stats, metadata);

            _log.Info("");
            _log.Info("=== Collection Summary ===");
            _log.Info("Users:             " + stats.UserCount);
            _log.Info("Groups:            " + stats.GroupCount);
            _log.Info("Computers:         " + stats.ComputerCount);
            _log.Info("Group Memberships: " + stats.MembershipCount);
            _log.Info("SPNs:              " + stats.SpnCount);
            _log.Info("Delegations:       " + stats.DelegationCount);
            _log.Info("ACL Permissions:   " + stats.AclCount);
            _log.Info("[+] Collection complete: " + _config.OutputPath);
        }

        private static string ResolveMetadataDomain(string? configuredDomain, string baseDn)
        {
            if (!string.IsNullOrWhiteSpace(configuredDomain))
            {
                return configuredDomain.Trim().ToUpperInvariant();
            }

            var parts = new List<string>();
            foreach (var component in baseDn.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (component.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                {
                    parts.Add(component[3..]);
                }
            }

            return parts.Count == 0 ? "UNKNOWN" : string.Join(".", parts).ToUpperInvariant();
        }
    }

    private sealed class Logger
    {
        private readonly int _verbosity;

        public Logger(int verbosity)
        {
            _verbosity = verbosity;
        }

        public void Info(string message)
        {
            if (_verbosity >= 1)
            {
                Console.WriteLine(message);
            }
        }

        public void Progress(string message)
        {
            if (_verbosity >= 2)
            {
                Console.WriteLine(message);
            }
        }

        public void Debug(string message)
        {
            if (_verbosity >= 3)
            {
                Console.WriteLine("[debug] " + message);
            }
        }

        public void Warn(string message)
        {
            if (_verbosity >= 1)
            {
                Console.Error.WriteLine("[warning] " + message);
            }
        }
    }

    #endregion

    #region LDAP

    private sealed class LdapClient : IDisposable
    {
        private readonly CollectorConfig _config;
        private readonly Logger _log;
        private LdapConnection? _connection;

        public LdapClient(CollectorConfig config, Logger log)
        {
            _config = config;
            _log = log;
        }

        public void Connect()
        {
            var host = _config.Host;
            if (string.IsNullOrWhiteSpace(host))
            {
                host = _config.Domain;
            }

            if (string.IsNullOrWhiteSpace(host))
            {
                host = Environment.UserDomainName;
            }

            var identifier = new LdapDirectoryIdentifier(host, _config.Port, fullyQualifiedDnsHostName: false, connectionless: false);
            _connection = new LdapConnection(identifier)
            {
                AuthType = AuthType.Negotiate,
                Credential = CredentialCache.DefaultNetworkCredentials,
                Timeout = _config.Timeout
            };

            _connection.SessionOptions.ProtocolVersion = 3;
            _connection.SessionOptions.ReferralChasing = ReferralChasingOptions.All;
            _connection.Bind();
            _log.Info("[+] LDAP bind successful using Negotiate");
        }

        public RootDseInfo ReadRootDse()
        {
            var entry = SearchOne(string.Empty, "(objectClass=*)", SearchScope.Base, new[]
            {
                "defaultNamingContext",
                "configurationNamingContext",
                "schemaNamingContext",
                "dnsHostName"
            });

            if (entry is null)
            {
                throw new InvalidOperationException("RootDSE query returned no result.");
            }

            return new RootDseInfo
            {
                DefaultNamingContext = LdapValues.GetString(entry, "defaultNamingContext"),
                ConfigurationNamingContext = LdapValues.GetString(entry, "configurationNamingContext"),
                SchemaNamingContext = LdapValues.GetString(entry, "schemaNamingContext"),
                DnsHostName = LdapValues.GetString(entry, "dnsHostName")
            };
        }

        public IEnumerable<SearchResultEntry> SearchPaged(
            string baseDn,
            string filter,
            SearchScope scope,
            string[] attributes,
            Func<IReadOnlyList<DirectoryControl>>? extraControls = null)
        {
            byte[] cookie = Array.Empty<byte>();
            do
            {
                var request = new SearchRequest(baseDn, filter, scope, attributes)
                {
                    TimeLimit = _config.Timeout
                };
                request.Controls.Add(new PageResultRequestControl(_config.PageSize) { Cookie = cookie });

                if (extraControls is not null)
                {
                    foreach (var control in extraControls())
                    {
                        request.Controls.Add(control);
                    }
                }

                var response = (SearchResponse)Send(request);
                foreach (SearchResultEntry entry in response.Entries)
                {
                    yield return entry;
                }

                cookie = Array.Empty<byte>();
                foreach (DirectoryControl control in response.Controls)
                {
                    if (control is PageResultResponseControl page)
                    {
                        cookie = page.Cookie;
                        break;
                    }
                }
            } while (cookie.Length > 0);
        }

        public SearchResultEntry? SearchOne(string baseDn, string filter, SearchScope scope, string[] attributes)
        {
            var request = new SearchRequest(baseDn, filter, scope, attributes)
            {
                SizeLimit = 1,
                TimeLimit = _config.Timeout
            };
            var response = (SearchResponse)Send(request);
            return response.Entries.Count == 0 ? null : response.Entries[0];
        }

        public SearchResultEntry? ReadObject(string distinguishedName, params string[] attributes)
        {
            return SearchOne(distinguishedName, "(objectClass=*)", SearchScope.Base, attributes);
        }

        public List<string> GetStringValues(SearchResultEntry entry, string attributeName)
        {
            return GetStringValues(entry.DistinguishedName, entry, attributeName);
        }

        public List<string> GetStringValues(string distinguishedName, string attributeName)
        {
            var entry = ReadObject(distinguishedName, attributeName);
            return entry is null ? new List<string>() : GetStringValues(distinguishedName, entry, attributeName);
        }

        private List<string> GetStringValues(string distinguishedName, SearchResultEntry entry, string attributeName)
        {
            if (LdapValues.TryGetAttribute(entry, attributeName, out var direct))
            {
                return LdapValues.GetStrings(direct);
            }

            var values = new List<string>();
            var range = LdapValues.FindRangeAttribute(entry, attributeName);
            if (range is null)
            {
                return values;
            }

            values.AddRange(LdapValues.GetStrings(range.Attribute));
            if (range.IsTerminal)
            {
                return values;
            }

            var nextStart = range.End + 1;
            while (true)
            {
                var rangedName = attributeName + ";range=" + nextStart.ToString(CultureInfo.InvariantCulture) + "-*";
                var page = ReadObject(distinguishedName, rangedName);
                if (page is null)
                {
                    return values;
                }

                var next = LdapValues.FindRangeAttribute(page, attributeName);
                if (next is null)
                {
                    return values;
                }

                values.AddRange(LdapValues.GetStrings(next.Attribute));
                if (next.IsTerminal)
                {
                    return values;
                }

                nextStart = next.End + 1;
            }
        }

        public DirectoryResponse Send(DirectoryRequest request)
        {
            if (_connection is null)
            {
                throw new InvalidOperationException("LDAP connection is not open.");
            }

            Exception? last = null;
            for (var attempt = 0; attempt <= _config.RetryCount; attempt++)
            {
                if (_config.DelayMs > 0)
                {
                    Thread.Sleep(_config.DelayMs);
                }

                try
                {
                    return _connection.SendRequest(request, _config.Timeout);
                }
                catch (LdapException ex) when (attempt < _config.RetryCount && IsTransient(ex))
                {
                    last = ex;
                    var sleep = Math.Min(5000, 250 * (attempt + 1));
                    _log.Warn("transient LDAP failure; retrying in " + sleep + " ms: " + ex.Message);
                    Thread.Sleep(sleep);
                }
            }

            throw last ?? new InvalidOperationException("LDAP request failed.");
        }

        private static bool IsTransient(LdapException ex)
        {
            return ex.ErrorCode is 51 or 52 or 81 or 82 or 85 or 88 or 91;
        }

        public void Dispose()
        {
            _connection?.Dispose();
        }
    }

    private sealed class RootDseInfo
    {
        public string? DefaultNamingContext { get; init; }
        public string? ConfigurationNamingContext { get; init; }
        public string? SchemaNamingContext { get; init; }
        public string? DnsHostName { get; init; }
    }

    private static class LdapValues
    {
        public static string? GetString(SearchResultEntry entry, string attributeName)
        {
            if (!TryGetAttribute(entry, attributeName, out var attribute) || attribute.Count == 0)
            {
                return null;
            }

            return ConvertValueToString(attribute[0]);
        }

        public static byte[]? GetBytes(SearchResultEntry entry, string attributeName)
        {
            if (!TryGetAttribute(entry, attributeName, out var attribute) || attribute.Count == 0)
            {
                return null;
            }

            return attribute[0] as byte[];
        }

        public static List<string> GetStrings(SearchResultEntry entry, string attributeName)
        {
            return TryGetAttribute(entry, attributeName, out var attribute) ? GetStrings(attribute) : new List<string>();
        }

        public static List<string> GetStrings(DirectoryAttribute attribute)
        {
            var values = new List<string>(attribute.Count);
            for (var i = 0; i < attribute.Count; i++)
            {
                var text = ConvertValueToString(attribute[i]);
                if (text is not null)
                {
                    values.Add(text);
                }
            }

            return values;
        }

        public static string? GetObjectSid(SearchResultEntry entry)
        {
            var bytes = GetBytes(entry, "objectSid");
            if (bytes is null || bytes.Length == 0)
            {
                return null;
            }

            try
            {
                return new SecurityIdentifier(bytes, 0).Value;
            }
            catch
            {
                return null;
            }
        }

        public static bool TryGetAttribute(SearchResultEntry entry, string attributeName, out DirectoryAttribute attribute)
        {
            if (entry.Attributes.Contains(attributeName))
            {
                attribute = entry.Attributes[attributeName];
                return true;
            }

            foreach (string name in entry.Attributes.AttributeNames)
            {
                if (name.Equals(attributeName, StringComparison.OrdinalIgnoreCase))
                {
                    attribute = entry.Attributes[name];
                    return true;
                }
            }

            attribute = null!;
            return false;
        }

        public static RangeAttribute? FindRangeAttribute(SearchResultEntry entry, string attributeName)
        {
            var prefix = attributeName + ";range=";
            foreach (string name in entry.Attributes.AttributeNames)
            {
                if (!name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var range = name[prefix.Length..];
                var dash = range.IndexOf('-');
                if (dash < 0)
                {
                    continue;
                }

                var endText = range[(dash + 1)..];
                var terminal = endText == "*";
                if (!int.TryParse(range[..dash], NumberStyles.Integer, CultureInfo.InvariantCulture, out var start))
                {
                    continue;
                }

                var end = terminal
                    ? start
                    : int.TryParse(endText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedEnd)
                        ? parsedEnd
                        : start;

                return new RangeAttribute(entry.Attributes[name], start, end, terminal);
            }

            return null;
        }

        public static string GetLeafObjectClass(SearchResultEntry entry)
        {
            var values = GetStrings(entry, "objectClass");
            return values.Count == 0 ? string.Empty : values[^1];
        }

        public static long GetInt64(SearchResultEntry entry, string attributeName)
        {
            var text = GetString(entry, attributeName);
            return long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) ? parsed : 0;
        }

        private static string? ConvertValueToString(object? value)
        {
            if (value is null)
            {
                return null;
            }

            if (value is string text)
            {
                return text;
            }

            if (value is byte[] bytes)
            {
                return Encoding.UTF8.GetString(bytes);
            }

            return Convert.ToString(value, CultureInfo.InvariantCulture);
        }
    }

    private sealed class RangeAttribute
    {
        public RangeAttribute(DirectoryAttribute attribute, int start, int end, bool isTerminal)
        {
            Attribute = attribute;
            Start = start;
            End = end;
            IsTerminal = isTerminal;
        }

        public DirectoryAttribute Attribute { get; }
        public int Start { get; }
        public int End { get; }
        public bool IsTerminal { get; }
    }

    #endregion

    #region Schema And Resolvers

    private sealed class SchemaResolver
    {
        private readonly LdapClient _ldap;
        private readonly string? _configurationNamingContext;
        private readonly Logger _log;
        private readonly ConcurrentDictionary<string, string> _extendedRights = new(StringComparer.OrdinalIgnoreCase);

        public SchemaResolver(LdapClient ldap, string? configurationNamingContext, Logger log)
        {
            _ldap = ldap;
            _configurationNamingContext = configurationNamingContext;
            _log = log;
        }

        public void Load()
        {
            if (string.IsNullOrWhiteSpace(_configurationNamingContext))
            {
                _log.Warn("configurationNamingContext unavailable; extended right GUIDs may remain unresolved.");
                return;
            }

            var baseDn = "CN=Extended-Rights," + _configurationNamingContext;
            var count = 0;
            try
            {
                foreach (var entry in _ldap.SearchPaged(baseDn, "(rightsGuid=*)", SearchScope.Subtree, new[] { "rightsGuid", "displayName" }))
                {
                    var guid = LdapValues.GetString(entry, "rightsGuid");
                    var displayName = LdapValues.GetString(entry, "displayName");
                    if (!string.IsNullOrWhiteSpace(guid) && !string.IsNullOrWhiteSpace(displayName))
                    {
                        _extendedRights[guid] = displayName;
                        count++;
                    }
                }
            }
            catch (Exception ex)
            {
                _log.Warn("failed to build extended-right cache: " + ex.Message);
            }

            _log.Debug("Loaded " + count + " extended-right GUIDs.");
        }

        public string? ResolveExtendedRight(Guid guid)
        {
            if (guid == Guid.Empty)
            {
                return null;
            }

            var key = guid.ToString();
            if (_extendedRights.TryGetValue(key, out var name))
            {
                return name;
            }

            return "Unknown-Right:" + key;
        }
    }

    private sealed class SidResolver
    {
        private readonly LdapClient _ldap;
        private readonly string _baseDn;
        private readonly Logger _log;
        private readonly ConcurrentDictionary<string, string> _cache = new(StringComparer.OrdinalIgnoreCase);

        public SidResolver(LdapClient ldap, string baseDn, Logger log)
        {
            _ldap = ldap;
            _baseDn = baseDn;
            _log = log;
        }

        public string ResolvePowerShellIdentity(string sidOrAccount)
        {
            if (!sidOrAccount.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase))
            {
                return sidOrAccount;
            }

            return _cache.GetOrAdd(sidOrAccount, ResolveSidCore);
        }

        private string ResolveSidCore(string sid)
        {
            try
            {
                var securityIdentifier = new SecurityIdentifier(sid);
                var bytes = new byte[securityIdentifier.BinaryLength];
                securityIdentifier.GetBinaryForm(bytes, 0);
                var filter = "(objectSid=" + LdapFilter.EscapeBinary(bytes) + ")";
                var entry = _ldap.SearchOne(_baseDn, filter, SearchScope.Subtree, new[] { "sAMAccountName", "objectClass" });
                if (entry is not null)
                {
                    var objectClass = LdapValues.GetLeafObjectClass(entry);
                    var sam = LdapValues.GetString(entry, "sAMAccountName");
                    if (!string.IsNullOrWhiteSpace(objectClass) && !string.IsNullOrWhiteSpace(sam))
                    {
                        return objectClass + ":" + sam;
                    }
                }
            }
            catch (Exception ex)
            {
                _log.Debug("SID resolution failed for " + sid + ": " + ex.Message);
            }

            return "Unknown:" + sid;
        }
    }

    private sealed class DistinguishedNameResolver
    {
        private readonly LdapClient _ldap;
        private readonly Logger _log;
        private readonly ConcurrentDictionary<string, DirectoryObjectSummary?> _cache = new(StringComparer.OrdinalIgnoreCase);

        public DistinguishedNameResolver(LdapClient ldap, Logger log)
        {
            _ldap = ldap;
            _log = log;
        }

        public DirectoryObjectSummary? Resolve(string distinguishedName)
        {
            return _cache.GetOrAdd(distinguishedName, ResolveCore);
        }

        private DirectoryObjectSummary? ResolveCore(string distinguishedName)
        {
            try
            {
                var entry = _ldap.ReadObject(distinguishedName, "sAMAccountName", "objectClass");
                if (entry is null)
                {
                    return null;
                }

                return new DirectoryObjectSummary
                {
                    DistinguishedName = entry.DistinguishedName,
                    SamAccountName = LdapValues.GetString(entry, "sAMAccountName"),
                    ObjectClass = LdapValues.GetLeafObjectClass(entry)
                };
            }
            catch (Exception ex)
            {
                _log.Warn("failed to resolve member DN '" + distinguishedName + "': " + ex.Message);
                return null;
            }
        }
    }

    private sealed class DirectoryObjectSummary
    {
        public string? SamAccountName { get; init; }
        public string DistinguishedName { get; init; } = string.Empty;
        public string ObjectClass { get; init; } = string.Empty;
    }

    private static class LdapFilter
    {
        public static string EscapeBinary(byte[] bytes)
        {
            var builder = new StringBuilder(bytes.Length * 3);
            foreach (var b in bytes)
            {
                builder.Append('\\');
                builder.Append(b.ToString("x2", CultureInfo.InvariantCulture));
            }

            return builder.ToString();
        }
    }

    #endregion

    #region Section Collectors

    private sealed class SectionCollectors
    {
        private const long UacAccountDisable = 0x00000002;
        private const long UacTrustedForDelegation = 0x00080000;
        private const long UacTrustedToAuthForDelegation = 0x01000000;
        private const long GroupTypeSecurityEnabled = unchecked((int)0x80000000);
        private const long GroupTypeGlobal = 0x00000002;
        private const long GroupTypeDomainLocal = 0x00000004;
        private const long GroupTypeUniversal = 0x00000008;

        private readonly CollectorConfig _config;
        private readonly LdapClient _ldap;
        private readonly SchemaResolver _schema;
        private readonly SidResolver _sidResolver;
        private readonly DistinguishedNameResolver _dnResolver;
        private readonly Logger _log;

        public SectionCollectors(
            CollectorConfig config,
            LdapClient ldap,
            SchemaResolver schema,
            SidResolver sidResolver,
            DistinguishedNameResolver dnResolver,
            Logger log)
        {
            _config = config;
            _ldap = ldap;
            _schema = schema;
            _sidResolver = sidResolver;
            _dnResolver = dnResolver;
            _log = log;
        }

        public long CollectUsers(Utf8JsonWriter writer)
        {
            _log.Progress("[*] Collecting users...");
            var count = 0L;
            foreach (var entry in SearchUsers(UserAttributes))
            {
                try
                {
                    WriteUser(writer, entry);
                    count++;
                    ProgressEvery("Users", count, 5000);
                }
                catch (Exception ex)
                {
                    _log.Warn("failed to write user '" + entry.DistinguishedName + "': " + ex.Message);
                }
            }

            _log.Info("    [+] Collected " + count + " users");
            return count;
        }

        public long CollectGroups(Utf8JsonWriter writer)
        {
            _log.Progress("[*] Collecting groups...");
            var count = 0L;
            foreach (var entry in SearchGroups(GroupAttributes))
            {
                try
                {
                    WriteGroup(writer, entry);
                    count++;
                    ProgressEvery("Groups", count, 5000);
                }
                catch (Exception ex)
                {
                    _log.Warn("failed to write group '" + entry.DistinguishedName + "': " + ex.Message);
                }
            }

            _log.Info("    [+] Collected " + count + " groups");
            return count;
        }

        public long CollectComputers(Utf8JsonWriter writer)
        {
            _log.Progress("[*] Collecting computers...");
            var count = 0L;
            foreach (var entry in SearchComputers(ComputerAttributes))
            {
                try
                {
                    WriteComputer(writer, entry);
                    count++;
                    ProgressEvery("Computers", count, 5000);
                }
                catch (Exception ex)
                {
                    _log.Warn("failed to write computer '" + entry.DistinguishedName + "': " + ex.Message);
                }
            }

            _log.Info("    [+] Collected " + count + " computers");
            return count;
        }

        public long CollectGroupMemberships(Utf8JsonWriter writer)
        {
            _log.Progress("[*] Collecting group memberships (including nested)...");
            var count = 0L;
            foreach (var group in SearchGroups(new[] { "sAMAccountName", "member" }))
            {
                var groupDn = group.DistinguishedName;
                var groupSam = LdapValues.GetString(group, "sAMAccountName");
                try
                {
                    var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    EmitNestedGroupMembers(writer, groupDn, groupSam, groupDn, true, visited, ref count);
                    ProgressEvery("Group memberships", count, 10000);
                }
                catch (Exception ex)
                {
                    _log.Warn("failed to collect members of group '" + groupDn + "': " + ex.Message);
                }
            }

            _log.Info("    [+] Collected " + count + " group memberships");
            return count;
        }

        public long CollectSpns(Utf8JsonWriter writer)
        {
            _log.Progress("[*] Collecting Service Principal Names (SPNs)...");
            var count = 0L;

            foreach (var user in SearchUsers(new[] { "sAMAccountName", "servicePrincipalName", "userAccountControl" }))
            {
                var sam = LdapValues.GetString(user, "sAMAccountName");
                var enabled = IsEnabled(user);
                foreach (var spn in _ldap.GetStringValues(user, "servicePrincipalName"))
                {
                    Json.WriteSpn(writer, sam, "user", user.DistinguishedName, spn, enabled);
                    count++;
                }
            }

            foreach (var computer in SearchComputers(new[] { "sAMAccountName", "servicePrincipalName", "userAccountControl" }))
            {
                var sam = LdapValues.GetString(computer, "sAMAccountName");
                var enabled = IsEnabled(computer);
                foreach (var spn in _ldap.GetStringValues(computer, "servicePrincipalName"))
                {
                    if (IsDefaultComputerSpn(spn))
                    {
                        continue;
                    }

                    Json.WriteSpn(writer, sam, "computer", computer.DistinguishedName, spn, enabled);
                    count++;
                }
            }

            _log.Info("    [+] Collected " + count + " SPNs");
            return count;
        }

        public long CollectDelegation(Utf8JsonWriter writer)
        {
            _log.Progress("[*] Collecting delegation configurations...");
            var count = 0L;

            foreach (var user in SearchUsers(DelegationAttributes))
            {
                if (TryWriteDelegation(writer, user, "user"))
                {
                    count++;
                }
            }

            foreach (var computer in SearchComputers(DelegationAttributes))
            {
                if (TryWriteDelegation(writer, computer, "computer"))
                {
                    count++;
                }
            }

            _log.Info("    [+] Collected " + count + " delegation configurations");
            return count;
        }

        public long CollectAcls(Utf8JsonWriter writer)
        {
            _log.Progress("[*] Collecting ACL permissions...");
            var count = 0L;
            count += CollectAclsForTargets(writer, "user", UserAclFilter);
            count += CollectAclsForTargets(writer, "group", GroupFilter);
            _log.Info("    [+] Collected " + count + " ACL permissions");
            return count;
        }

        private long CollectAclsForTargets(Utf8JsonWriter writer, string targetType, string filter)
        {
            var count = 0L;
            var processed = 0L;
            var attrs = new[] { "sAMAccountName", "nTSecurityDescriptor" };
            foreach (var entry in _ldap.SearchPaged(_config.BaseDn!, filter, SearchScope.Subtree, attrs, CreateSecurityDescriptorControls))
            {
                processed++;
                try
                {
                    var sd = LdapValues.GetBytes(entry, "nTSecurityDescriptor");
                    if (sd is null || sd.Length == 0)
                    {
                        continue;
                    }

                    var targetSam = LdapValues.GetString(entry, "sAMAccountName");
                    var parser = new AclParser(_schema, _sidResolver, _config.IncludeInheritedAces);
                    count += parser.WriteInterestingAces(writer, sd, targetSam, targetType, entry.DistinguishedName);
                }
                catch (Exception ex)
                {
                    _log.Warn("failed to parse ACL for " + targetType + " '" + entry.DistinguishedName + "': " + ex.Message);
                }

                if (processed % 1000 == 0)
                {
                    _log.Progress("    [*] Processed ACLs for " + processed + " " + targetType + " objects...");
                }
            }

            return count;
        }

        private void WriteUser(Utf8JsonWriter writer, SearchResultEntry user)
        {
            var spns = _ldap.GetStringValues(user, "servicePrincipalName");
            var memberOf = _ldap.GetStringValues(user, "memberOf");
            var allowedToDelegateTo = _ldap.GetStringValues(user, "msDS-AllowedToDelegateTo");
            var trustedForDelegation = HasUacFlag(user, UacTrustedForDelegation);
            var trustedToAuth = HasUacFlag(user, UacTrustedToAuthForDelegation);

            writer.WriteStartObject();
            writer.WriteBoolean("has_delegation", trustedForDelegation || trustedToAuth || allowedToDelegateTo.Count > 0);
            Json.WriteNullableString(writer, "sid", LdapValues.GetObjectSid(user));
            Json.WriteNullableString(writer, "description", LdapValues.GetString(user, "description"));
            Json.WriteNullableString(writer, "distinguished_name", user.DistinguishedName);
            writer.WriteNumber("member_of_count", memberOf.Count);
            writer.WriteBoolean("enabled", IsEnabled(user));
            Json.WriteNullableString(writer, "sam_account_name", LdapValues.GetString(user, "sAMAccountName"));
            writer.WriteNumber("spn_count", spns.Count);
            writer.WriteEndObject();
        }

        private void WriteGroup(Utf8JsonWriter writer, SearchResultEntry group)
        {
            var members = _ldap.GetStringValues(group, "member");
            var memberOf = _ldap.GetStringValues(group, "memberOf");
            var groupType = LdapValues.GetInt64(group, "groupType");

            writer.WriteStartObject();
            Json.WriteNullableString(writer, "group_scope", GetGroupScope(groupType));
            writer.WriteNumber("member_count", members.Count);
            Json.WriteNullableString(writer, "group_category", GetGroupCategory(groupType));
            Json.WriteNullableString(writer, "sid", LdapValues.GetObjectSid(group));
            Json.WriteNullableString(writer, "description", LdapValues.GetString(group, "description"));
            Json.WriteNullableString(writer, "distinguished_name", group.DistinguishedName);
            Json.WriteNullableString(writer, "sam_account_name", LdapValues.GetString(group, "sAMAccountName"));
            writer.WriteNumber("member_of_count", memberOf.Count);
            writer.WriteEndObject();
        }

        private void WriteComputer(Utf8JsonWriter writer, SearchResultEntry computer)
        {
            var spns = _ldap.GetStringValues(computer, "servicePrincipalName");

            writer.WriteStartObject();
            writer.WriteBoolean("trusted_for_delegation", HasUacFlag(computer, UacTrustedForDelegation));
            Json.WriteNullableString(writer, "sid", LdapValues.GetObjectSid(computer));
            writer.WriteBoolean("constrained_delegation", HasUacFlag(computer, UacTrustedToAuthForDelegation));
            Json.WriteNullableString(writer, "operating_system", LdapValues.GetString(computer, "operatingSystem"));
            Json.WriteNullableString(writer, "distinguished_name", computer.DistinguishedName);
            writer.WriteBoolean("enabled", IsEnabled(computer));
            Json.WriteNullableString(writer, "sam_account_name", LdapValues.GetString(computer, "sAMAccountName"));
            writer.WriteNumber("spn_count", spns.Count);
            writer.WriteEndObject();
        }

        private void EmitNestedGroupMembers(
            Utf8JsonWriter writer,
            string currentGroupDn,
            string? rootGroupSam,
            string rootGroupDn,
            bool direct,
            HashSet<string> visited,
            ref long count)
        {
            if (!visited.Add(currentGroupDn))
            {
                return;
            }

            foreach (var memberDn in _ldap.GetStringValues(currentGroupDn, "member"))
            {
                var member = _dnResolver.Resolve(memberDn);
                if (member is null)
                {
                    continue;
                }

                writer.WriteStartObject();
                Json.WriteNullableString(writer, "group_dn", rootGroupDn);
                Json.WriteNullableString(writer, "member_sam", member.SamAccountName);
                Json.WriteNullableString(writer, "member_dn", member.DistinguishedName);
                Json.WriteNullableString(writer, "member_type", member.ObjectClass);
                Json.WriteNullableString(writer, "group_sam", rootGroupSam);
                writer.WriteBoolean("direct_membership", direct);
                writer.WriteEndObject();
                count++;

                if (member.ObjectClass.Equals("group", StringComparison.OrdinalIgnoreCase))
                {
                    EmitNestedGroupMembers(writer, member.DistinguishedName, rootGroupSam, rootGroupDn, false, visited, ref count);
                }
            }
        }

        private bool TryWriteDelegation(Utf8JsonWriter writer, SearchResultEntry entry, string identityType)
        {
            var trustedForDelegation = HasUacFlag(entry, UacTrustedForDelegation);
            var trustedToAuth = HasUacFlag(entry, UacTrustedToAuthForDelegation);
            var allowedTargets = _ldap.GetStringValues(entry, "msDS-AllowedToDelegateTo");
            if (!trustedForDelegation && !trustedToAuth && allowedTargets.Count == 0)
            {
                return false;
            }

            var delegationType = trustedForDelegation
                ? "unconstrained"
                : trustedToAuth
                    ? "constrained_with_protocol_transition"
                    : "constrained";

            Json.WriteDelegation(
                writer,
                LdapValues.GetString(entry, "sAMAccountName"),
                identityType,
                entry.DistinguishedName,
                delegationType,
                allowedTargets,
                IsEnabled(entry));
            return true;
        }

        private IEnumerable<SearchResultEntry> SearchUsers(string[] attributes)
        {
            return _ldap.SearchPaged(_config.BaseDn!, UserFilter, SearchScope.Subtree, attributes);
        }

        private IEnumerable<SearchResultEntry> SearchGroups(string[] attributes)
        {
            return _ldap.SearchPaged(_config.BaseDn!, GroupFilter, SearchScope.Subtree, attributes);
        }

        private IEnumerable<SearchResultEntry> SearchComputers(string[] attributes)
        {
            return _ldap.SearchPaged(_config.BaseDn!, ComputerFilter, SearchScope.Subtree, attributes);
        }

        private string GroupFilter
        {
            get
            {
                if (_config.IncludeBuiltIn)
                {
                    return "(objectClass=group)";
                }

                return "(&(objectClass=group)(!(distinguishedName=*CN=Builtin,*))(!(distinguishedName=*CN=Users,*)))";
            }
        }

        private static string UserFilter => "(&(objectCategory=person)(objectClass=user))";
        private static string UserAclFilter => UserFilter;
        private static string ComputerFilter => "(objectClass=computer)";

        private static readonly string[] UserAttributes =
        {
            "sAMAccountName",
            "distinguishedName",
            "objectSid",
            "memberOf",
            "servicePrincipalName",
            "userAccountControl",
            "description",
            "msDS-AllowedToDelegateTo"
        };

        private static readonly string[] GroupAttributes =
        {
            "sAMAccountName",
            "distinguishedName",
            "objectSid",
            "member",
            "memberOf",
            "description",
            "groupType"
        };

        private static readonly string[] ComputerAttributes =
        {
            "sAMAccountName",
            "distinguishedName",
            "objectSid",
            "servicePrincipalName",
            "operatingSystem",
            "userAccountControl",
            "msDS-AllowedToDelegateTo"
        };

        private static readonly string[] DelegationAttributes =
        {
            "sAMAccountName",
            "distinguishedName",
            "userAccountControl",
            "msDS-AllowedToDelegateTo"
        };

        private static IReadOnlyList<DirectoryControl> CreateSecurityDescriptorControls()
        {
            return new[]
            {
                new DirectoryControl(
                    "1.2.840.113556.1.4.801",
                    new byte[] { 0x30, 0x03, 0x02, 0x01, 0x07 },
                    true,
                    true)
            };
        }

        private static bool IsEnabled(SearchResultEntry entry)
        {
            return !HasUacFlag(entry, UacAccountDisable);
        }

        private static bool HasUacFlag(SearchResultEntry entry, long flag)
        {
            var uac = LdapValues.GetInt64(entry, "userAccountControl");
            return (uac & flag) == flag;
        }

        private static string GetGroupCategory(long groupType)
        {
            return (groupType & GroupTypeSecurityEnabled) != 0 ? "Security" : "Distribution";
        }

        private static string GetGroupScope(long groupType)
        {
            if ((groupType & GroupTypeDomainLocal) != 0)
            {
                return "DomainLocal";
            }

            if ((groupType & GroupTypeUniversal) != 0)
            {
                return "Universal";
            }

            if ((groupType & GroupTypeGlobal) != 0)
            {
                return "Global";
            }

            return string.Empty;
        }

        private static bool IsDefaultComputerSpn(string spn)
        {
            return spn.StartsWith("HOST/", StringComparison.OrdinalIgnoreCase) ||
                   spn.StartsWith("TERMSRV/", StringComparison.OrdinalIgnoreCase) ||
                   spn.StartsWith("RestrictedKrbHost/", StringComparison.OrdinalIgnoreCase);
        }

        private void ProgressEvery(string label, long count, long interval)
        {
            if (count > 0 && count % interval == 0)
            {
                _log.Progress("    " + label + ": " + count);
            }
        }
    }

    #endregion

    #region ACLs

    private sealed class AclParser
    {
        private readonly SchemaResolver _schema;
        private readonly SidResolver _sidResolver;
        private readonly bool _includeInherited;

        public AclParser(SchemaResolver schema, SidResolver sidResolver, bool includeInherited)
        {
            _schema = schema;
            _sidResolver = sidResolver;
            _includeInherited = includeInherited;
        }

        public long WriteInterestingAces(Utf8JsonWriter writer, byte[] securityDescriptor, string? targetSam, string targetType, string targetDn)
        {
            var descriptor = new RawSecurityDescriptor(securityDescriptor, 0);
            var count = 0L;
            if (descriptor.DiscretionaryAcl is null)
            {
                return count;
            }

            foreach (GenericAce ace in descriptor.DiscretionaryAcl)
            {
                if (ace is not QualifiedAce qualified)
                {
                    continue;
                }

                if (!_includeInherited && ace.IsInherited)
                {
                    continue;
                }

                if (qualified.AceQualifier is not AceQualifier.AccessAllowed and not AceQualifier.AccessDenied)
                {
                    continue;
                }

                var permission = ActiveDirectoryRightsFormatter.Format(qualified.AccessMask);
                if (!IsInteresting(permission))
                {
                    continue;
                }

                Guid? objectType = null;
                if (qualified is ObjectAce objectAce &&
                    objectAce.ObjectAceFlags.HasFlag(ObjectAceFlags.ObjectAceTypePresent) &&
                    objectAce.ObjectAceType != Guid.Empty)
                {
                    objectType = objectAce.ObjectAceType;
                }

                string? extendedRightName = null;
                if (permission.Contains("ExtendedRight", StringComparison.Ordinal) && objectType.HasValue)
                {
                    extendedRightName = _schema.ResolveExtendedRight(objectType.Value);
                }

                var trusteeSid = ResolveTrusteeReference(qualified.SecurityIdentifier);
                var trusteeIdentity = _sidResolver.ResolvePowerShellIdentity(trusteeSid);

                writer.WriteStartObject();
                Json.WriteNullableString(writer, "target_type", targetType);
                Json.WriteNullableString(writer, "permission", permission);
                Json.WriteNullableString(writer, "target_dn", targetDn);
                Json.WriteNullableString(writer, "trustee_identity", trusteeIdentity);
                Json.WriteNullableString(writer, "object_type_guid", objectType?.ToString());
                Json.WriteNullableString(writer, "inheritance_flags", ace.InheritanceFlags.ToString());
                Json.WriteNullableString(writer, "access_control_type", qualified.AceQualifier == AceQualifier.AccessAllowed ? "Allow" : "Deny");
                Json.WriteNullableString(writer, "target_sam", targetSam);
                Json.WriteNullableString(writer, "trustee_sid", trusteeSid);
                writer.WriteBoolean("is_inherited", ace.IsInherited);
                Json.WriteNullableString(writer, "extended_right_name", extendedRightName);
                writer.WriteEndObject();
                count++;
            }

            return count;
        }

        private static bool IsInteresting(string permission)
        {
            return permission.Contains("GenericAll", StringComparison.Ordinal) ||
                   permission.Contains("GenericWrite", StringComparison.Ordinal) ||
                   permission.Contains("WriteProperty", StringComparison.Ordinal) ||
                   permission.Contains("WriteDacl", StringComparison.Ordinal) ||
                   permission.Contains("WriteOwner", StringComparison.Ordinal) ||
                   permission.Contains("ResetPassword", StringComparison.Ordinal) ||
                   permission.Contains("ExtendedRight", StringComparison.Ordinal);
        }

        private static string ResolveTrusteeReference(SecurityIdentifier sid)
        {
            try
            {
                return sid.Translate(typeof(NTAccount)).Value;
            }
            catch
            {
                return sid.Value;
            }
        }
    }

    private static class ActiveDirectoryRightsFormatter
    {
        private const uint GenericReadBit = 0x80000000;
        private const uint GenericWriteBit = 0x40000000;
        private const uint GenericExecuteBit = 0x20000000;
        private const uint GenericAllBit = 0x10000000;

        private const uint GenericRead = 0x00020094;
        private const uint GenericWrite = 0x00020028;
        private const uint GenericExecute = 0x00020004;
        private const uint GenericAll = 0x000F01FF;

        private static readonly RightName[] Rights =
        {
            new(0x00000001, "CreateChild"),
            new(0x00000002, "DeleteChild"),
            new(0x00000004, "ListChildren"),
            new(0x00000008, "Self"),
            new(0x00000010, "ReadProperty"),
            new(0x00000020, "WriteProperty"),
            new(0x00000040, "DeleteTree"),
            new(0x00000080, "ListObject"),
            new(0x00000100, "ExtendedRight"),
            new(0x00010000, "Delete"),
            new(0x00020000, "ReadControl"),
            new(GenericExecute, "GenericExecute"),
            new(GenericWrite, "GenericWrite"),
            new(GenericRead, "GenericRead"),
            new(0x00040000, "WriteDacl"),
            new(0x00080000, "WriteOwner"),
            new(GenericAll, "GenericAll"),
            new(0x00100000, "Synchronize"),
            new(0x01000000, "AccessSystemSecurity")
        };

        public static string Format(int accessMask)
        {
            var remaining = NormalizeGenericBits(unchecked((uint)accessMask));
            if (remaining == 0)
            {
                return "0";
            }

            var names = new List<string>();
            for (var i = Rights.Length - 1; i >= 0; i--)
            {
                var value = Rights[i].Value;
                if (value != 0 && (remaining & value) == value)
                {
                    names.Add(Rights[i].Name);
                    remaining &= ~value;
                }
            }

            if (remaining != 0)
            {
                names.Add("0x" + remaining.ToString("X", CultureInfo.InvariantCulture));
            }

            names.Reverse();
            return string.Join(", ", names);
        }

        private static uint NormalizeGenericBits(uint mask)
        {
            if ((mask & GenericAllBit) != 0)
            {
                mask = (mask & ~GenericAllBit) | GenericAll;
            }

            if ((mask & GenericWriteBit) != 0)
            {
                mask = (mask & ~GenericWriteBit) | GenericWrite;
            }

            if ((mask & GenericExecuteBit) != 0)
            {
                mask = (mask & ~GenericExecuteBit) | GenericExecute;
            }

            if ((mask & GenericReadBit) != 0)
            {
                mask = (mask & ~GenericReadBit) | GenericRead;
            }

            return mask;
        }

        private readonly struct RightName
        {
            public RightName(uint value, string name)
            {
                Value = value;
                Name = name;
            }

            public uint Value { get; }
            public string Name { get; }
        }
    }

    #endregion

    #region JSON Writer

    private sealed class SectionSpool
    {
        private readonly CollectorConfig _config;
        private readonly Logger _log;
        private readonly string _workDir;
        private readonly bool _deleteOnDispose;

        public SectionSpool(CollectorConfig config, Logger log)
        {
            _config = config;
            _log = log;

            if (config.CheckpointEnabled)
            {
                _workDir = config.CheckpointDir;
                Directory.CreateDirectory(_workDir);
                _deleteOnDispose = false;
            }
            else
            {
                _workDir = Path.Combine(Path.GetTempPath(), "adauth-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(_workDir);
                _deleteOnDispose = true;
            }
        }

        public long WriteSection(string sectionName, Func<Utf8JsonWriter, long> producer)
        {
            if (_config.Resume && TryReadCheckpoint(sectionName, out var resumedCount))
            {
                _log.Info("    [=] Resuming completed section " + sectionName + " (" + resumedCount + " records)");
                return resumedCount;
            }

            var path = FragmentPath(sectionName);
            var tempPath = path + ".tmp";
            if (File.Exists(tempPath))
            {
                File.Delete(tempPath);
            }

            long count;
            using (var stream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 1024 * 128))
            using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
            {
                writer.WriteStartArray();
                count = producer(writer);
                writer.WriteEndArray();
                writer.Flush();
            }

            if (File.Exists(path))
            {
                File.Delete(path);
            }

            File.Move(tempPath, path);
            WriteCheckpoint(sectionName, count, path);
            return count;
        }

        public void WriteMetadataCheckpoint(MetadataRecord metadata)
        {
            if (!_config.CheckpointEnabled)
            {
                return;
            }

            var path = Path.Combine(_workDir, "metadata.checkpoint.json");
            using var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read);
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });
            writer.WriteStartObject();
            writer.WriteString("collector_version", metadata.CollectorVersion);
            writer.WriteString("domain", metadata.Domain);
            writer.WriteString("description", metadata.Description);
            writer.WriteString("collection_date", metadata.CollectionDate);
            writer.WriteEndObject();
        }

        public void ComposeFinalOutput(CollectionStats stats, MetadataRecord metadata)
        {
            var outputDir = Path.GetDirectoryName(_config.OutputPath);
            if (!string.IsNullOrWhiteSpace(outputDir))
            {
                Directory.CreateDirectory(outputDir);
            }

            var tempOutput = _config.OutputPath + ".tmp";
            using (var stream = new FileStream(tempOutput, FileMode.Create, FileAccess.Write, FileShare.Read, 1024 * 256))
            {
                WriteAscii(stream, "{\n");
                WritePropertyPrefix(stream, "statistics", first: true);
                Json.WriteStatisticsObject(stream, stats);

                WritePropertyPrefix(stream, "acl_permissions", first: false);
                CopyFragment(stream, "acl_permissions");

                WritePropertyPrefix(stream, "groups", first: false);
                CopyFragment(stream, "groups");

                WritePropertyPrefix(stream, "metadata", first: false);
                Json.WriteMetadataObject(stream, metadata);

                WritePropertyPrefix(stream, "group_memberships", first: false);
                CopyFragment(stream, "group_memberships");

                WritePropertyPrefix(stream, "users", first: false);
                CopyFragment(stream, "users");

                WritePropertyPrefix(stream, "delegation", first: false);
                CopyFragment(stream, "delegation");

                WritePropertyPrefix(stream, "spns", first: false);
                CopyFragment(stream, "spns");

                WritePropertyPrefix(stream, "computers", first: false);
                CopyFragment(stream, "computers");

                WriteAscii(stream, "\n}\n");
            }

            if (File.Exists(_config.OutputPath))
            {
                File.Delete(_config.OutputPath);
            }

            File.Move(tempOutput, _config.OutputPath);

            if (_deleteOnDispose)
            {
                try
                {
                    Directory.Delete(_workDir, recursive: true);
                }
                catch (Exception ex)
                {
                    _log.Debug("temporary spool cleanup failed: " + ex.Message);
                }
            }
        }

        private bool TryReadCheckpoint(string sectionName, out long count)
        {
            count = 0;
            var checkpointPath = CheckpointPath(sectionName);
            var fragmentPath = FragmentPath(sectionName);
            if (!File.Exists(checkpointPath) || !File.Exists(fragmentPath))
            {
                return false;
            }

            try
            {
                using var document = JsonDocument.Parse(File.ReadAllBytes(checkpointPath));
                if (!document.RootElement.TryGetProperty("section", out var section) ||
                    !section.ValueEquals(sectionName) ||
                    !document.RootElement.TryGetProperty("count", out var countElement))
                {
                    return false;
                }

                count = countElement.GetInt64();
                return true;
            }
            catch
            {
                return false;
            }
        }

        private void WriteCheckpoint(string sectionName, long count, string fragmentPath)
        {
            if (!_config.CheckpointEnabled)
            {
                return;
            }

            using var stream = new FileStream(CheckpointPath(sectionName), FileMode.Create, FileAccess.Write, FileShare.Read);
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });
            writer.WriteStartObject();
            writer.WriteString("section", sectionName);
            writer.WriteNumber("count", count);
            writer.WriteString("fragment", fragmentPath);
            writer.WriteString("completed_utc", DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            writer.WriteEndObject();
        }

        private void CopyFragment(Stream destination, string sectionName)
        {
            var path = FragmentPath(sectionName);
            if (!File.Exists(path))
            {
                throw new FileNotFoundException("Missing JSON fragment for section " + sectionName, path);
            }

            using var source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 256);
            source.CopyTo(destination);
        }

        private string FragmentPath(string sectionName)
        {
            return Path.Combine(_workDir, sectionName + ".array.json");
        }

        private string CheckpointPath(string sectionName)
        {
            return Path.Combine(_workDir, sectionName + ".checkpoint.json");
        }

        private static void WritePropertyPrefix(Stream stream, string propertyName, bool first)
        {
            if (!first)
            {
                WriteAscii(stream, ",\n");
            }

            WriteAscii(stream, "  \"" + propertyName + "\": ");
        }

        private static void WriteAscii(Stream stream, string text)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            stream.Write(bytes, 0, bytes.Length);
        }
    }

    private static class Json
    {
        public static void WriteNullableString(Utf8JsonWriter writer, string propertyName, string? value)
        {
            if (value is null)
            {
                writer.WriteNull(propertyName);
            }
            else
            {
                writer.WriteString(propertyName, value);
            }
        }

        public static void WriteSpn(Utf8JsonWriter writer, string? sam, string type, string dn, string spn, bool enabled)
        {
            writer.WriteStartObject();
            WriteNullableString(writer, "identity_sam", sam);
            writer.WriteBoolean("enabled", enabled);
            writer.WriteString("identity_type", type);
            writer.WriteString("spn", spn);
            writer.WriteString("identity_dn", dn);
            writer.WriteEndObject();
        }

        public static void WriteDelegation(
            Utf8JsonWriter writer,
            string? sam,
            string identityType,
            string dn,
            string delegationType,
            IReadOnlyList<string> allowedTargets,
            bool enabled)
        {
            writer.WriteStartObject();
            writer.WritePropertyName("allowed_targets");
            writer.WriteStartArray();
            foreach (var target in allowedTargets)
            {
                writer.WriteStringValue(target);
            }

            writer.WriteEndArray();
            writer.WriteString("delegation_type", delegationType);
            writer.WriteString("identity_type", identityType);
            writer.WriteString("identity_dn", dn);
            writer.WriteBoolean("enabled", enabled);
            WriteNullableString(writer, "identity_sam", sam);
            writer.WriteEndObject();
        }

        public static void WriteStatisticsObject(Stream stream, CollectionStats stats)
        {
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true, SkipValidation = true });
            writer.WriteStartObject();
            writer.WriteNumber("computer_count", stats.ComputerCount);
            writer.WriteNumber("membership_count", stats.MembershipCount);
            writer.WriteNumber("user_count", stats.UserCount);
            writer.WriteNumber("group_count", stats.GroupCount);
            writer.WriteNumber("spn_count", stats.SpnCount);
            writer.WriteNumber("acl_count", stats.AclCount);
            writer.WriteNumber("delegation_count", stats.DelegationCount);
            writer.WriteEndObject();
            writer.Flush();
        }

        public static void WriteMetadataObject(Stream stream, MetadataRecord metadata)
        {
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true, SkipValidation = true });
            writer.WriteStartObject();
            writer.WriteString("collector_version", metadata.CollectorVersion);
            writer.WriteString("domain", metadata.Domain);
            writer.WriteString("description", metadata.Description);
            writer.WriteString("collection_date", metadata.CollectionDate);
            writer.WriteEndObject();
            writer.Flush();
        }
    }

    #endregion

    #region Models

    private sealed class MetadataRecord
    {
        public string CollectorVersion { get; init; } = "1.1";
        public string Domain { get; init; } = "UNKNOWN";
        public string Description { get; init; } = "Active Directory authorization state snapshot";
        public string CollectionDate { get; init; } = string.Empty;
    }

    private sealed class CollectionStats
    {
        public long UserCount { get; set; }
        public long GroupCount { get; set; }
        public long ComputerCount { get; set; }
        public long MembershipCount { get; set; }
        public long SpnCount { get; set; }
        public long DelegationCount { get; set; }
        public long AclCount { get; set; }
    }

    #endregion
}
