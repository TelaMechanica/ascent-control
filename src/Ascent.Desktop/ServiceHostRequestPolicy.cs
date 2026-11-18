namespace Ascent.Desktop;

// Native request eligibility only. No token, credential or widget API is exposed.
internal static class ServiceHostRequestPolicy
{
    internal static bool ShouldAttach(Uri? backend, object? trustedView, object? sender,
        string? pageUrl, string? requestUrl, string method, bool scriptRequest)
    {
        if (backend is null || trustedView is null || !ReferenceEquals(trustedView, sender) ||
            !scriptRequest || backend.Scheme != Uri.UriSchemeHttp || !backend.IsLoopback ||
            !Uri.TryCreate(pageUrl, UriKind.Absolute, out var page) ||
            !Uri.TryCreate(requestUrl, UriKind.Absolute, out var request)) return false;
        var origin = backend.GetLeftPart(UriPartial.Authority);
        if (backend.UserInfo.Length != 0 || page.UserInfo.Length != 0 || request.UserInfo.Length != 0 ||
            !string.Equals(page.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(request.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase) ||
            page.AbsolutePath is not ("/" or "/index.html")) return false;
        return (method, request.AbsolutePath) switch
        {
            ("GET", "/api/widgets/local/catalog") => true,
            ("POST", "/api/widgets/local/rescan") => true,
            ("POST", "/api/widgets/local/open-folder") => true,
            ("GET", "/api/service-mode/local/status") => true,
            ("POST", "/api/service-mode/local/prepare") => true,
            ("POST", "/api/service-mode/local/credential") => true,
            ("POST", "/api/service-mode/local/receiver/inspect") => true,
            ("POST", "/api/service-mode/local/receiver/verify") => true,
            _ => false
        };
    }
}
