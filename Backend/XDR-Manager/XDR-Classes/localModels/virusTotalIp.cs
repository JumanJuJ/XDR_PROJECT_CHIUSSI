

namespace XDR_Classes.localModels
{
    public class virusTotalIp
    {
        // Root myDeserializedClass = JsonConvert.DeserializeObject<Root>(myJsonResponse);

        public class Root
        {
            public Data? data { get; set; }
        }

        public class Data
        {
            public string? id { get; set; }
            public string? type { get; set; }
            public Attributes? attributes { get; set; }
            public Links? links { get; set; }
        }

        public class Attributes
        {
            public string? as_owner { get; set; }
            public int? asn { get; set; }
            public string? continent { get; set; }
            public string? country { get; set; }
            public string? jarm { get; set; }

            public int? last_analysis_date { get; set; }
            public LastAnalysisResults? last_analysis_results { get; set; }
            public LastAnalysisStats? last_analysis_stats { get; set; }

            public int? last_modification_date { get; set; }
            public string? network { get; set; }
            public string? regional_internet_registry { get; set; }
            public int? reputation { get; set; }

            public TotalVotes? total_votes { get; set; }
            public List<string>? tags { get; set; }

            public string? whois { get; set; }
            public int? whois_date { get; set; }
        }

        public class LastAnalysisResults
        {
            public Kaspersky? Kaspersky { get; set; }
            public BitDefender? BitDefender { get; set; }
        }

        public class Kaspersky
        {
            public string? category { get; set; }
            public string? engine_name { get; set; }
            public string? method { get; set; }
            public string? result { get; set; }
        }

        public class BitDefender
        {
            public string? category { get; set; }
            public string? engine_name { get; set; }
            public string? method { get; set; }
            public string? result { get; set; }
        }

        public class LastAnalysisStats
        {
            public int? harmless { get; set; }
            public int? malicious { get; set; }
            public int? suspicious { get; set; }
            public int? timeout { get; set; }
            public int? undetected { get; set; }
        }

        public class TotalVotes
        {
            public int? harmless { get; set; }
            public int? malicious { get; set; }
        }

        public class Links
        {
            public string? self { get; set; }
        }



    }
}
