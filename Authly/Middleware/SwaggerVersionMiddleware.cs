namespace Authly.Middleware
{
    public class SwaggerVersionMiddleware
    {
        private readonly RequestDelegate _next;

        public SwaggerVersionMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (context.Request.Path.StartsWithSegments("/swagger") &&
                context.Request.Path.Value.EndsWith("/swagger.json"))
            {
                var originalBodyStream = context.Response.Body;
                using var responseBody = new MemoryStream();
                context.Response.Body = responseBody;

                await _next(context);

                context.Response.Body.Seek(0, SeekOrigin.Begin);
                var responseBodyText = await new StreamReader(context.Response.Body).ReadToEndAsync();

                // Nahradit neplatnou verzi
                responseBodyText = responseBodyText.Replace("\"openapi\": \"3.0.4\",", "\"openapi\": \"3.0.3\",");

                context.Response.Body = originalBodyStream;
                await context.Response.WriteAsync(responseBodyText);
            }
            else
            {
                await _next(context);
            }
        }
    }
}