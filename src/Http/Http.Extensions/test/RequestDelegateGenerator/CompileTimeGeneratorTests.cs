// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
using Microsoft.CodeAnalysis;
namespace Microsoft.AspNetCore.Http.Generators.Tests;

public class CompileTimeGeneratorTests : RequestDelegateGeneratorTests
{
    protected override bool IsGeneratorEnabled { get; } = true;

    [Fact]
    public async Task MapAction_UnknownParameter_EmitsDiagnostic_NoSource()
    {
        // This will eventually be handled by the EndpointParameterSource.JsonBodyOrService.
        // All parameters should theoretically be handleable with enough "Or"s in the future
        // we'll remove this test and diagnostic.
        var source = """
app.MapGet("/", (IServiceProvider provider) => "Hello world!");
""";
        var expectedBody = "Hello world!";
        var (generatorRunResult, compilation) = await RunGeneratorAsync(source);

        // Emits diagnostic but generates no source
        var result = Assert.IsType<GeneratorRunResult>(generatorRunResult);
        var diagnostic = Assert.Single(result.Diagnostics);
        Assert.Equal(DiagnosticDescriptors.GetUnableToResolveParameterDescriptor("provider").Id, diagnostic.Id);
        Assert.Empty(result.GeneratedSources);

        // Falls back to runtime-generated endpoint
        var endpoint = GetEndpointFromCompilation(compilation, false);

        var httpContext = CreateHttpContext();
        await endpoint.RequestDelegate(httpContext);
        await VerifyResponseBodyAsync(httpContext, expectedBody);
    }

    [Fact]
    public async Task MapGet_WithRequestDelegate_DoesNotGenerateSources()
    {
        var (generatorRunResult, compilation) = await RunGeneratorAsync("""
app.MapGet("/hello", (HttpContext context) => Task.CompletedTask);
""");
        var results = Assert.IsType<GeneratorRunResult>(generatorRunResult);
        Assert.Empty(GetStaticEndpoints(results, GeneratorSteps.EndpointModelStep));

        var endpoint = GetEndpointFromCompilation(compilation, false);

        var httpContext = CreateHttpContext();
        await endpoint.RequestDelegate(httpContext);
        await VerifyResponseBodyAsync(httpContext, "");
    }

    // Todo: Move this to a shared test that checks metadata once that is supported
    // in the source generator.
    [Theory]
    [InlineData(@"app.MapGet(""/"", () => Console.WriteLine(""Returns void""));", null)]
    [InlineData(@"app.MapGet(""/"", () => TypedResults.Ok(""Alright!""));", null)]
    [InlineData(@"app.MapGet(""/"", () => Results.NotFound(""Oops!""));", null)]
    [InlineData(@"app.MapGet(""/"", () => Task.FromResult(new Todo() { Name = ""Test Item""}));", "application/json")]
    [InlineData(@"app.MapGet(""/"", () => ""Hello world!"");", "text/plain")]
    public async Task MapAction_ProducesCorrectContentType(string source, string expectedContentType)
    {
        var (result, compilation) = await RunGeneratorAsync(source);

        VerifyStaticEndpointModel(result, endpointModel =>
        {
            Assert.Equal("/", endpointModel.RoutePattern);
            Assert.Equal("MapGet", endpointModel.HttpMethod);
            Assert.Equal(expectedContentType, endpointModel.Response.ContentType);
        });
    }
}
