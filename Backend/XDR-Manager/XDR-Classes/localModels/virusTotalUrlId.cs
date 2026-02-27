using System.Text;

public static class VirusTotalUrlId
{
    public static string ToUrlId(string url)
    {
        var bytes = Encoding.UTF8.GetBytes(url);

        // Base64 standard
        var b64 = Convert.ToBase64String(bytes);

        return b64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
